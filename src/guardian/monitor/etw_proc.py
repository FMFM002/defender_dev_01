"""进程监控（P1 真实实现：WMI Win32_ProcessStartTrace）。

为什么选 WMI 而不是 ETW：
- pyetwkit 等 ETW 原生绑定编译复杂（需要 VC++ toolchain），会显著拖慢用户首次安装
- WMI 自带 Python 绑定（wmi/pywin32），无新增二进制依赖
- WMI Win32_ProcessStartTrace 是 Windows 提供的进程创建通知通道，延迟秒级够用
- P2 阶段如有性能瓶颈可切换 ETW（pyetwkit）

检测规则（命中任一即上报告警）：
1. 父进程是 Office / 脚本宿主（winword / excel / wscript / mshta / rundll32 等）
2. 父进程是浏览器、但派生了非浏览器进程
3. 命令行含编码执行 / 远程下载特征（-EncodedCommand / certutil / IEX 等）
4. 可执行文件落地在 %TEMP% / Downloads

已刻意排除（误报率高）：
- cmd.exe / powershell.exe 单独作为父进程（终端里跑任何东西都是它们）
- conhost.exe 等系统控制台宿主进程（一律不报）
"""

from __future__ import annotations

import os
import threading
import time
from datetime import datetime

from src.guardian.core.logger import logger

try:
    import win32com.client  # type: ignore
    _HAVE_WMI = True
except ImportError:
    _HAVE_WMI = False

# ─────────────────────────────────────────────────────────────────────
# 进程告警规则（P1，v2 —— 收紧误报）
#
# 设计原则：宁可漏报、不可误报（误报会让用户直接关掉防护）。
#
# v1 的两个大坑（已在用户真机复现）：
#   1) 把 cmd.exe / powershell.exe 当"高风险父进程" → 终端里跑任何东西
#      父进程都是它们，导致连本服务自己（由 start.bat 经 cmd 启动）都告警。
#   2) 把 %APPDATA% / %LOCALAPPDATA% / \ProgramData\ 当"投放目录" → VSCode、
#      Teams、Edge 更新等正规软件全从这些目录运行，持续刷屏。
#
# v2 策略：用「谁派生谁」的**语义**判断，而不是无差别匹配父进程名。
# ─────────────────────────────────────────────────────────────────────

# 已知良性子进程：命中即直接放行（系统控制台宿主等，绝不告警）
BENIGN_CHILDREN = {
    "conhost.exe", "dllhost.exe", "runtimebroker.exe", "sihost.exe",
    "ctfmon.exe", "textinputhost.exe", "searchhost.exe", "wmiprvse.exe",
    "fontdrvhost.exe", "csrss.exe", "wininit.exe", "smss.exe",
    "lsass.exe", "services.exe", "winlogon.exe", "taskhostw.exe",
}

# 高风险父进程：Office / 脚本宿主 —— 这些宿主「正常不应」派生任意可执行文件
# （典型：Word 宏起 powershell、mshta 起木马、wscript 起 exe）
# 注意：故意不包含 cmd.exe / powershell.exe（见文件头说明）。
HIGH_RISK_PARENTS = {
    # Office（宏 / 文档漏洞攻击的主战场）
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "visio.exe", "msaccess.exe", "mspub.exe", "onenote.exe",
    # 脚本宿主 / 代理执行器
    "wscript.exe", "cscript.exe", "mshta.exe",
    "rundll32.exe", "regsvr32.exe",
}

# 浏览器：正常只派生「自己」（helper 进程）；派生「其它」进程才可疑
BROWSER_PARENTS = {"chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe"}

# 浏览器自带的辅助进程（子进程名白名单）。
# 覆盖 Edge / Chrome 常见的官方 helper —— identity_helper.exe 曾造成误报。
BROWSER_HELPERS = {
    "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe",
    "crashpad_handler.exe", "msedge_proxy.exe", "chrome_proxy.exe",
    "microsoftedgeupdate.exe", "msedgeupdate.exe", "microsoftedgecp.exe",
    "identity_helper.exe", "notification_helper.exe", "elevation_service.exe",
    "msedgewebview2.exe", "pwahelper.exe", "widgets.exe", "widgetservice.exe",
    "googleupdate.exe", "setup.exe",
}

# 浏览器官方安装目录：只要子进程的可执行文件落在这些目录里，就视为"浏览器自己人"。
# 比单纯比对进程名更稳（Edge 版本目录里不断新增 helper）。
BROWSER_INSTALL_DIRS = (
    "\\microsoft\\edge\\application\\",
    "\\google\\chrome\\application\\",
    "\\mozilla firefox\\",
    "\\microsoft\\edgewebview\\application\\",
)

# 高风险命令行模式（Suspicious）
# 说明：这些是"落地执行型"特征，正规软件极少出现在命令行里。
HIGH_RISK_CMDLINE_PATTERNS = [
    "-encodedcommand", "-windowstyle hidden",
    "certutil -decode", "certutil -urlcache",
    "bitsadmin /transfer",
    "installutil",
    "regsvr32 /s /n /i:",
    "mshta http",
    "iex (new-object",
    "invoke-expression",
    "frombase64string",
    "net.webclient).download",
    "downloadstring(",
]

# 高风险投放路径：只保留「用户临时 / 下载」这类真正的落地目录。
# 已移除 %APPDATA% / %LOCALAPPDATA% / \ProgramData\（正规软件也住这里）。
HIGH_RISK_PATH_TEMPLATES = [
    "%TEMP%",
    "\\Downloads\\",
]


class ETWProcessMonitor:
    """WMI Win32_ProcessStartTrace 订阅。

    用法：
        mon = ETWProcessMonitor(on_alert=callback)
        mon.start()
        ...
        mon.stop()

    告警通过 on_alert(dict) 推给上层；dict 结构：
        {
            "ts": ISO8601,
            "pid": int,
            "name": "...",
            "path": "C:\\...",
            "cmdline": "...",
            "ppid": int,
            "parent_name": "...",
            "rules": ["high_risk_parent", "high_risk_cmdline", ...],
            "evidence": ["...", ...],
        }
    """

    def __init__(self, on_alert=None) -> None:
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._running = False
        self.on_alert = on_alert
        self._alert_count = 0
        # 告警去重：同一 (进程名, 父进程名, 命中规则) 在窗口内只报一次
        self._recent: dict[tuple, float] = {}
        self._dedup_window = 300.0  # 5 分钟

    def start(self) -> None:
        if self._running:
            return
        if not _HAVE_WMI:
            logger.warning("ETWProcessMonitor: pywin32 未安装，跳过实时监控。"
                           "pip install pywin32 后重启服务。")
            return
        self._running = True
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="etw-proc-mon")
        self._thread.start()
        logger.info("ETWProcessMonitor: 已启动 WMI Win32_ProcessStartTrace 订阅。")

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3.0)
        self._running = False
        logger.info(f"ETWProcessMonitor: 已停止。本次会话告警 {self._alert_count} 次。")

    def _run(self) -> None:
        """WMI 阻塞订阅循环。"""
        # win32com 在子线程中必须先初始化 COM（STA）。
        try:
            import pythoncom  # type: ignore
            pythoncom.CoInitialize()
        except ImportError:
            pythoncom = None

        wmi = None
        try:
            wmi = win32com.client.Dispatch("WbemScripting.SWbemLocator")
            svc = wmi.ConnectServer(".", "root\\cimv2")
            watcher = svc.ExecNotificationQuery(
                "SELECT * FROM Win32_ProcessStartTrace"
            )
            logger.debug("ETWProcessMonitor: WMI 订阅已就绪，等待事件…")
        except Exception as e:
            err_str = str(e)
            # 0x80041005 = 访问被拒，通常因为非管理员
            if "0x80041005" in err_str or "-2147217405" in err_str or "拒绝访问" in err_str:
                logger.warning("ETWProcessMonitor: WMI 订阅失败 — 当前进程非管理员。"
                               "本服务仍可正常工作，仅进程告警不可用。"
                               "如需启用，请以管理员身份运行本服务。")
            else:
                logger.error(f"ETWProcessMonitor: WMI 初始化失败: {e}")
            self._running = False
            if pythoncom:
                pythoncom.CoUninitialize()
            return

        while not self._stop.is_set():
            try:
                # NextEvent(timeout_ms) 无事件时抛超时异常；这是正常现象，
                # 静默 continue（如果打日志会每秒刷一条）。
                ev = watcher.NextEvent(1000)  # 1 秒超时便于响应 stop
                if ev is None:
                    continue
                self._handle_event(ev)
            except Exception as e:
                if _is_wmi_timeout(e):
                    continue  # 无事件，正常
                logger.warning(f"ETWProcessMonitor: WMI 事件循环错误: {e}")
                # 出现非超时错误，短暂退避后继续
                self._stop.wait(2.0)
        # 释放 COM 引用（局部变量，逐个删除以尽快回收）
        try:
            del watcher
        except Exception:
            pass
        try:
            del svc
        except Exception:
            pass
        try:
            del wmi
        except Exception:
            pass
        if pythoncom:
            pythoncom.CoUninitialize()

    def _handle_event(self, ev) -> None:
        try:
            pid = int(ev.ProcessId)
            name = ev.ProcessName or ""
            path = _resolve_path(pid)  # 通过 PID 反查路径（避免依赖 WMI 内字段）
            cmdline = _get_cmdline(pid)
            ppid, parent_name = _get_parent(pid)
        except Exception as e:
            logger.debug(f"ETWProcessMonitor: 事件字段解析失败: {e}")
            return

        rules, evidence = _evaluate(name, path, cmdline, parent_name)
        if not rules:
            return

        # 5 分钟去重：同一 (进程名, 父进程名, 命中规则) 只上报一次
        key = ((name or "").lower(), (parent_name or "").lower(), tuple(rules))
        now = time.time()
        last = self._recent.get(key)
        if last is not None and (now - last) < self._dedup_window:
            return
        self._recent[key] = now
        # 轻量清理，避免字典无限增长
        if len(self._recent) > 500:
            cutoff = now - self._dedup_window
            self._recent = {k: t for k, t in self._recent.items() if t >= cutoff}

        alert = {
            "ts": datetime.now().isoformat(timespec="seconds"),
            "pid": pid,
            "name": name,
            "path": path,
            "cmdline": cmdline[:500],
            "ppid": ppid,
            "parent_name": parent_name,
            "rules": rules,
            "evidence": evidence,
        }
        self._alert_count += 1
        logger.warning(f"[进程告警] {path} | 父进程={parent_name} | "
                       f"命中规则={','.join(rules)}")
        if self.on_alert:
            try:
                self.on_alert(alert)
            except Exception as e:
                logger.warning(f"ETWProcessMonitor: on_alert 回调异常: {e}")


def _is_wmi_timeout(e: Exception) -> bool:
    """判断异常是否为 WMI 事件源超时（无事件）。

    NextEvent(timeout) 在无事件时抛超时异常，这是正常控制流，
    不应记录为告警。需要兼容中英文与 HRESULT。
    """
    s = str(e)
    low = s.lower()
    if "已超时" in s or "timed out" in low or "timeout" in low:
        return True
    # WMI 事件源超时的 HRESULT（用户日志中观察到 -2147209215）
    if "-2147209215" in s:
        return True
    hr = getattr(e, "hresult", None)
    if hr == -2147209215:
        return True
    return False


def _evaluate(name: str, path: str, cmdline: str, parent_name: str) -> tuple[list[str], list[str]]:
    rules: list[str] = []
    evidence: list[str] = []

    n = (name or "").lower()
    p = (parent_name or "").lower()

    # 0) 已知良性子进程（conhost 等系统进程）直接放行
    if n in BENIGN_CHILDREN:
        return [], []

    # 1) 父进程是 Office / 脚本宿主
    if p and p in HIGH_RISK_PARENTS:
        rules.append("high_risk_parent")
        evidence.append(f"父进程 {parent_name} 属于 Office/脚本宿主")

    # 2) 浏览器派生了「非浏览器」进程
    if p in BROWSER_PARENTS and n not in BROWSER_HELPERS and not _in_browser_install_dir(path):
        rules.append("browser_spawn_process")
        evidence.append(f"浏览器 {parent_name} 派生了 {name}")

    # 3) 命令行命中编码执行 / 远程下载特征
    if cmdline:
        c_lower = cmdline.lower()
        for pat in HIGH_RISK_CMDLINE_PATTERNS:
            if pat in c_lower:
                rules.append("high_risk_cmdline")
                evidence.append(f"命令行命中模式 {pat!r}")
                break

    # 4) 可执行文件落地在 %TEMP% / Downloads
    if path:
        p_lower = path.lower()
        for tmpl in HIGH_RISK_PATH_TEMPLATES:
            expanded = os.path.expandvars(tmpl).lower()
            if expanded and p_lower.startswith(expanded):
                rules.append("env_drop_path")
                evidence.append(f"路径 {path} 命中高风险目录 {tmpl!r}")
                break

    return rules, evidence


def _in_browser_install_dir(path: str) -> bool:
    """判断可执行文件是否位于浏览器官方安装目录（视为浏览器自带组件）。"""
    if not path:
        return False
    p = path.lower().replace("/", "\\")
    return any(d in p for d in BROWSER_INSTALL_DIRS)


def _resolve_path(pid: int) -> str:
    """通过 PID 查询进程路径。优先用 WMI，失败回退 None。"""
    try:
        wmi = win32com.client.Dispatch("WbemScripting.SWbemLocator")
        svc = wmi.ConnectServer(".", "root\\cimv2")
        for p in svc.ExecQuery(f"SELECT ExecutablePath FROM Win32_Process WHERE ProcessId={pid}"):
            return (p.ExecutablePath or "").replace("\\\\", "\\")
    except Exception:
        pass
    return ""


def _get_cmdline(pid: int) -> str:
    try:
        wmi = win32com.client.Dispatch("WbemScripting.SWbemLocator")
        svc = wmi.ConnectServer(".", "root\\cimv2")
        for p in svc.ExecQuery(f"SELECT CommandLine FROM Win32_Process WHERE ProcessId={pid}"):
            return p.CommandLine or ""
    except Exception:
        pass
    return ""


def _get_parent(pid: int) -> tuple[int, str]:
    """通过 WMI 取得父进程 PID + 名。"""
    try:
        wmi = win32com.client.Dispatch("WbemScripting.SWbemLocator")
        svc = wmi.ConnectServer(".", "root\\cimv2")
        for p in svc.ExecQuery(f"SELECT ParentProcessId, Name FROM Win32_Process WHERE ProcessId={pid}"):
            ppid = int(p.ParentProcessId)
            parent_name = ""
            if ppid:
                for q in svc.ExecQuery(f"SELECT Name FROM Win32_Process WHERE ProcessId={ppid}"):
                    parent_name = q.Name or ""
                    break
            return ppid, parent_name
    except Exception:
        pass
    return 0, ""


etw_monitor = ETWProcessMonitor()