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

import sys

import uvicorn

from src.guardian.api.routes import router
from src.guardian.core.config import HOST, PORT, ensure_dirs
from src.guardian.core.logger import logger
from src.guardian.core.memguard import MemoryGuard
from src.guardian.monitor.etw_proc import etw_monitor

from fastapi import FastAPI

app = FastAPI(title="PC Guardian", version="0.1.0")
app.include_router(router)


def main() -> int:
    ensure_dirs()
    logger.info(f"PC Guardian starting on {HOST}:{PORT}")

    # 内存守护
    mem_guard = MemoryGuard()
    mem_guard.start()

    # ETW 进程监控（设置告警回调，统一走 logger + 内存队列）
    etw_monitor.on_alert = _on_proc_alert
    etw_monitor.start()

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
