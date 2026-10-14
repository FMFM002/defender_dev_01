"""进程监控（P1 真实实现：WMI Win32_ProcessStartTrace）。

为什么选 WMI 而不是 ETW：
- pyetwkit 等 ETW 原生绑定编译复杂（需要 VC++ toolchain），会显著拖慢用户首次安装
- WMI 自带 Python 绑定（wmi/pywin32），无新增二进制依赖
- WMI Win32_ProcessStartTrace 是 Windows 提供的进程创建通知通道，延迟秒级够用
- P2 阶段如有性能瓶颈可切换 ETW（pyetwkit）

检测规则（命中任一即上报告警）：
1. 路径在 %TEMP% / %APPDATA% / Downloads（典型恶意软件投放位）
2. 父进程是浏览器 / Office / 脚本宿主（PowerShell / WScript / cscript / mshta）
3. 命令行含 -enc / -EncodedCommand / certutil -decode / bitsadmin / InstallUtil / regsvr32
4. 无签名 PE（P1 暂不做数字签名校验，P2 加）
"""

from __future__ import annotations

import os
import threading
from datetime import datetime

from src.guardian.core.logger import logger

try:
    import win32com.client  # type: ignore
    _HAVE_WMI = True
except ImportError:
    _HAVE_WMI = False

# 高风险父进程：浏览器/Office/脚本宿主
HIGH_RISK_PARENTS = {
    "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe",
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
    "powershell.exe", "pwsh.exe", "cmd.exe",
}

# 高风险命令行模式（Suspicious）
HIGH_RISK_CMDLINE_PATTERNS = [
    "-enc", "-EncodedCommand", "-WindowStyle Hidden",
    "certutil -decode", "certutil -urlcache",
    "bitsadmin /transfer",
    "InstallUtil",
    "regsvr32 /s /n /i:",
    "mshta http",
    "IEX (New-Object",
    "Invoke-Expression",
    "FromBase64String",
    "Net.WebClient).Download",
]

# 高风险投放路径模板
HIGH_RISK_PATH_TEMPLATES = [
    "%TEMP%",
    "%APPDATA%",
    "%LOCALAPPDATA%",
    "\\Downloads\\",
    "\\ProgramData\\",
    "\\AppData\\",
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
                # Next() 默认阻��等待，timeout=-1 表示无限
                ev = watcher.NextEvent(1000)  # 1 秒超时便于响应 stop
                if ev is None:
                    continue
                self._handle_event(ev)
            except Exception as e:
                # WMI 超时时抛特定异常
                err_str = str(e)
                if "timed out" in err_str.lower() or "0x80041004" in err_str:
                    continue
                logger.warning(f"ETWProcessMonitor: WMI 事件循环错误: {e}")
                # 出现非超时错误，短暂退避后继续
                self._stop.wait(2.0)
        try:
            del watcher
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


def _evaluate(name: str, path: str, cmdline: str, parent_name: str) -> tuple[list[str], list[str]]:
    rules: list[str] = []
    evidence: list[str] = []

    if parent_name and parent_name.lower() in HIGH_RISK_PARENTS:
        rules.append("high_risk_parent")
        evidence.append(f"父进程 {parent_name} 属于浏览器/Office/脚本宿主")

    if cmdline:
        c_lower = cmdline.lower()
        for pat in HIGH_RISK_CMDLINE_PATTERNS:
            if pat.lower() in c_lower:
                rules.append("high_risk_cmdline")
                evidence.append(f"命令行命中模式 {pat!r}")
                break

    if path:
        p_lower = path.lower()
        for tmpl in HIGH_RISK_PATH_TEMPLATES:
            expanded = os.path.expandvars(tmpl).lower()
            if expanded and p_lower.startswith(expanded):
                rules.append("env_drop_path")
                evidence.append(f"路径 {path} 命中高风险模板 {tmpl!r}")
                break

    return rules, evidence


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