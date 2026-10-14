"""按天切的 logger。

- 输出：data/logs/guardian-YYYY-MM-DD.log
- 保留：30 天
- 拦截页不显示 DEBUG 级日志（仅显示用户层告警）
- 控制台 DEBUG 级别（开发期可见）
"""

from __future__ import annotations

import sys
from pathlib import Path

from loguru import logger as _logger

from src.guardian.core.config import LOGS_DIR

_LOG_FORMAT = (
    "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
    "<level>{level:<7}</level> | "
    "<cyan>{name}:{function}:{line}</cyan> | "
    "<level>{message}</level>"
)


def setup_logger() -> "logger":
    """配置并返回 logger 实例。"""
    _logger.remove()

    # 控制台：DEBUG 起，开发期全量
    _logger.add(
        sys.stderr,
        format=_LOG_FORMAT,
        level="DEBUG",
        enqueue=False,
        backtrace=True,
        diagnose=False,
    )

    # 文件：按天切，30 天
    _logger.add(
        str(LOGS_DIR / "guardian-{time:YYYY-MM-DD}.log"),
        rotation="00:00",
        retention="30 days",
        format=_LOG_FORMAT,
        level="DEBUG",
        encoding="utf-8",
        enqueue=True,
        compression=None,
    )

    return _logger


logger = setup_logger()
