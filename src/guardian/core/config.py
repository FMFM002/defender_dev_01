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


def _load_dotenv(path: Path) -> None:
    """加载项目根目录下的 .env（本地密钥，不入版本库）。

    格式：每行 KEY=VALUE，# 开头为注释。已存在的系统环境变量优先（不被覆盖），
    这样"临时 set 环境变量"仍然可以压过 .env。
    """
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError:
        return
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = val


# 在读取任何 os.environ 之前先加载 .env
_load_dotenv(PROJECT_ROOT / ".env")

# HTTP 服务
HOST = "127.0.0.1"
PORT = 7890  # 不与 SakuraCat-VPN 7897 冲突

# 威胁情报
URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/"
SEC_MCP_API = ""  # sec-mcp 公开接口待确认，先留空
INTEL_CACHE_TTL_HOURS = 24

# URLhaus Auth-Key（abuse.ch 自 2025-06-30 起强制鉴权；留空则自动跳过 URLhaus）
# 申请地址（免费）：https://auth.abuse.ch/  →  个人资料 → 创建 Auth-Key
# 配置方式（任选其一，推荐 .env）：
#   1) 项目根目录 .env 写入一行： URLHAUS_AUTH_KEY=你的Key
#   2) 设置系统环境变量 URLHAUS_AUTH_KEY
URLHAUS_AUTH_KEY = os.environ.get("URLHAUS_AUTH_KEY", "").strip()

# 本地域名黑名单（Phishing Army，免 Key 免费，约 16 万条钓鱼域名）
# 首次启动后台自动下载，之后每 24h 刷新一次；命中走本地 SQLite，毫秒级
BLOCKLIST_DIR = DATA_DIR / "blocklist"
PHISHING_ARMY_URL = "https://phishing.army/download/phishing_army_blocklist_extended.txt"
BLOCKLIST_REFRESH_HOURS = 24
BLOCKLIST_ENABLED = True

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
    for p in (DATA_DIR, LOGS_DIR, QUARANTINE_DIR, DB_DIR, CONFIG_DIR, BLOCKLIST_DIR):
        p.mkdir(parents=True, exist_ok=True)


def get_env(name: str, default: str) -> str:
    return os.environ.get(name, default)
