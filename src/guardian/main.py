"""FastAPI 启动入口。

启动顺序：
1. ensure_dirs() 创建所有数据目录
2. 配置 logger
3. 启动 MemGuard（监控 RSS）
4. 启动 ETW 进程监控占位
5. 启动 FastAPI

启动方式：
  D:\\AppData\\WorkBuddy\\binaries\\python\\envs\\pc-guardian\\Scripts\\python.exe -m src.guardian.main
"""

from __future__ import annotations

import socket
import sys
import threading

import uvicorn

from src.guardian.api.routes import router
from src.guardian.core.config import HOST, PORT, ensure_dirs
from src.guardian.core.logger import logger
from src.guardian.core.memguard import MemoryGuard
from src.guardian.monitor.etw_proc import etw_monitor

from fastapi import FastAPI

app = FastAPI(title="PC Guardian", version="0.1.0")
app.include_router(router)


def _start_blocklist_refresh() -> None:
    """后台刷新本地域名黑名单（不阻塞启动）。"""
    def _run():
        try:
            from src.guardian.intel import blocklist
            blocklist.refresh()
        except Exception as e:
            logger.warning(f"blocklist 后台刷新失败（不影响其它功能）: {e}")

    t = threading.Thread(target=_run, name="blocklist-refresh", daemon=True)
    t.start()


def _port_in_use(host: str, port: int) -> bool:
    """检测端口是否已被占用。"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
            return False
        except OSError:
            return True


def _find_pid_on_port(port: int) -> int | None:
    """尝试找出占用端口的 PID（仅 Windows）。"""
    if sys.platform != "win32":
        return None
    try:
        import subprocess
        out = subprocess.run(
            ["netstat", "-ano", "-p", "TCP"],
            capture_output=True, text=True, timeout=5,
        ).stdout
        for line in out.splitlines():
            if f":{port} " in line and "LISTENING" in line.upper():
                parts = line.split()
                if parts and parts[-1].isdigit():
                    return int(parts[-1])
    except Exception:
        pass
    return None


def main() -> int:
    ensure_dirs()

    # 单实例保护：端口已占用 = 已有一个实例在跑，避免 uvicorn 报原始错误。
    if _port_in_use(HOST, PORT):
        pid = _find_pid_on_port(PORT)
        logger.error(
            f"端口 {PORT} 已被占用 —— 可能已有一个 PC Guardian 实例在运行。"
            + (f" 占用进程 PID={pid}。" if pid else "")
            + f" 请先结束该进程（taskkill /PID <pid> /F），或改用其它端口。"
        )
        print(
            f"\n[PC Guardian] 启动失败：端口 {HOST}:{PORT} 已被占用。\n"
            + (f"  占用进程 PID = {pid}\n" if pid else "")
            + f"  处理方式：在 PowerShell 执行  Stop-Process -Id {pid or '<pid>'} -Force\n"
            + f"  然后重新运行。\n",
            file=sys.stderr,
        )
        return 2

    logger.info(f"PC Guardian starting on {HOST}:{PORT}")

    # 内存守护
    mem_guard = MemoryGuard()
    mem_guard.start()

    # ETW 进程监控（设置告警回调，统一走 logger + 内存队列）
    etw_monitor.on_alert = _on_proc_alert
    etw_monitor.start()

    # 本地域名黑名单：后台下载/刷新（首次约 3.4 MB，不阻塞启动）
    _start_blocklist_refresh()

    try:
        uvicorn.run(
            app,
            host=HOST,
            port=PORT,
            log_config=None,  # 禁用 uvicorn 自带 log，由 loguru 统一
            access_log=False,
        )
    finally:
        etw_monitor.stop()
        mem_guard.stop()
        logger.info("PC Guardian stopped")
    return 0


def _on_proc_alert(alert: dict) -> None:
    """进程告警统一处理：日志 + 内存队列（供 /proc_alerts 接口读取）。"""
    try:
        from src.guardian.core.db import db
        db.push_proc_alert(alert)
    except Exception:
        pass


if __name__ == "__main__":
    sys.exit(main())
