"""全局配置。所有路径/端口/阈值的单一来源。

低内存指标：
- 缓存大小上限 10 MB（SQLite 配额）
- 日志压缩 30 天后归档
- 单进程 RSS 上限 150 MB（高峰期）
"""

from __future__ import annotations

import os
from pathlib import Path

# 项目根目录：D:/Dtopdesk/普瑞赛斯在哪/workbuddy/电脑防毒/
PROJECT_ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = PROJECT_ROOT / "data"
CONFIG_DIR = PROJECT_ROOT / "config"
LOGS_DIR = DATA_DIR / "logs"
QUARANTINE_DIR = DATA_DIR / "quarantine"
DB_DIR = DATA_DIR / "db"

# HTTP 服务
HOST = "127.0.0.1"
PORT = 7890  # 不与 SakuraCat-VPN 7897 冲突

# 威胁情报
URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/"
SEC_MCP_API = ""  # sec-mcp 公开接口待确认，先留空
INTEL_CACHE_TTL_HOURS = 24

# VPN 代理（SakuraCat-VPN）
VPN_PROXY_HOST = "127.0.0.1"
VPN_PROXY_PORT = 7897
VPN_PROXY_TIMEOUT = 1.0  # 秒，连接探测超时

# 资源占用阈值（硬性指标）
RSS_IDLE_MAX_MB = 80
RSS_PEAK_MAX_MB = 150
RSS_CHECK_INTERVAL_S = 30

# ASR 规则（Microsoft Defender Attack Surface Reduction）
ASR_REG_PATH = r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
ASR_ENABLED_VALUE = 1
ASR_DISABLED_VALUE = 0
ASR_AUDIT_VALUE = 2

# 白名单
DEFAULT_WHITELIST_PATH = CONFIG_DIR / "default_whitelist.json"
USER_WHITELIST_DB_TABLE = "user_whitelist"

# 隔离区
QUARANTINE_AUTO_CLEAN_DAYS = 30


def ensure_dirs() -> None:
    """启动时确保所有目录存在。"""
    for p in (DATA_DIR, LOGS_DIR, QUARANTINE_DIR, DB_DIR, CONFIG_DIR):
        p.mkdir(parents=True, exist_ok=True)


def get_env(name: str, default: str) -> str:
    return os.environ.get(name, default)
