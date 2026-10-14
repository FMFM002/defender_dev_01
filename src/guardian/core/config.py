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

# URLhaus / MalwareBazaar Auth-Key（abuse.ch 自 2025-06-30 起强制鉴权；留空则自动跳过）
# 申请地址（免费）：https://auth.abuse.ch/  ->  个人资料 -> 创建 Auth-Key
# 同一个 Key 通用于 URLhaus / MalwareBazaar / ThreatFox 三大服务
URLHAUS_AUTH_KEY = os.environ.get("URLHAUS_AUTH_KEY", "").strip()

# 本地域名黑名单（Phishing Army，免 Key 免费，约 16 万条钓鱼域名）
BLOCKLIST_DIR = DATA_DIR / "blocklist"
PHISHING_ARMY_URL = "https://phishing.army/download/phishing_army_blocklist_extended.txt"
BLOCKLIST_REFRESH_HOURS = 24
BLOCKLIST_ENABLED = True

# MalwareBazaar 文件哈希云查（同 abuse.ch Key）
MALBAZAAR_API = "https://mb-api.abuse.ch/api/v1/"

# VPN 代理（SakuraCat-VPN）
VPN_PROXY_HOST = "127.0.0.1"
VPN_PROXY_PORT = 7897
VPN_PROXY_TIMEOUT = 1.0

# 资源占用阈值（硬性指标）
RSS_IDLE_MAX_MB = 80
RSS_PEAK_MAX_MB = 150
RSS_CHECK_INTERVAL_S = 30

# ASR 规则
ASR_REG_PATH = r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
ASR_ENABLED_VALUE = 1
ASR_DISABLED_VALUE = 0
ASR_AUDIT_VALUE = 2

# 白名单
DEFAULT_WHITELIST_PATH = CONFIG_DIR / "default_whitelist.json"
USER_WHITELIST_DB_TABLE = "user_whitelist"

# 隔离区
QUARANTINE_AUTO_CLEAN_DAYS = 30
QUARANTINE_SCORE_THRESHOLD = 70      # >= 此分数触发自动隔离
QUARANTINE_KEEPORIGINAL = True       # 开发期保留原文件副本（False 则真移走）

# ----------------------------------------------------------------------
# 文件监控（P2-1）
# ----------------------------------------------------------------------

USERPROFILE = os.environ.get("USERPROFILE", str(Path.home()))
APPDATA = os.environ.get("APPDATA", "")
LOCALAPPDATA = os.environ.get("LOCALAPPDATA", "")
TEMP_DIR = os.environ.get("TEMP", "")
STARTUP_DIR = (APPDATA + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup") if APPDATA else ""

# 监控白名单：用户可写入、感染主要落地点
# 注意：USN 全卷监控成功时这些目录都已被覆盖；这里是 USN 失败（权限不足）的降级路径
FSMON_WATCH_DIRS = [
    USERPROFILE + "\\Downloads",
    USERPROFILE + "\\Desktop",
    TEMP_DIR,
    STARTUP_DIR,
    LOCALAPPDATA,
    # 用户明确要求的 D:\Download（QQ/迅雷/IDM 默认落地）
    # 应用场景白名单 (\\Download\\pic\\) 会过滤掉 QQ 预览图
    "D:\\Download",
]

# 不订阅系统路径前缀（避免 Windows 自动展开目录）
FSMON_EXCLUDE_DIR_PARTS = [
    "\\Windows\\",
    "\\Program Files\\",
    "\\Program Files (x86)\\",
    "\\ProgramData\\",
    "\\$Recycle.Bin\\",
    "\\System Volume Information\\",
    "\\node_modules\\",
    "\\.git\\",
    "\\WindowsApps\\",
]

# 应用场景白名单（已知安全/低价值，落地点 = "不该扫"）——
# 这些路径下的新增文件直接豁免，不进评分队列。命中理由记 debug 日志。
# 用户场景：QQ 系统预览图、聊天记录库、企业微信、iCloud 等同步盘目录。
FSMON_APP_EXCLUDE_PATTERNS = [
    "\\Download\\pic\\",            # QQ 默认收图/系统预览缓存
    "\\Download\\Thumb\\",          # QQ 缩略图
    "\\Tencent Files\\",            # 微信/QQ 文件收发目录
    "\\Documents\\WeChat Files\\",  # 微信聊天记录（主进程 db 库）
    "\\Documents\\WXWork\\",        # 企业微信
    "\\DingTalk\\",                 # 钉钉（英文）
    "\\钉钉\\",                     # 钉钉（中文安装路径）
    "\\Lark\\",                     # 飞书（英文）
    "\\飞书\\",                     # 飞书（中文安装路径）
    "\\Documents\\Tencent Files\\", # 微信文档
    "\\OneDrive\\",
    "\\Dropbox\\",
    "\\Google Drive\\",
    "\\iCloudDrive\\",
    "\\AppData\\Local\\Packages\\", # UWP app 沙箱
    "\\AppData\\Local\\Microsoft\\WindowsApps\\",
]

# USN Journal 全卷监听（P2-1 增强）
FSMON_USN_ENABLED = True               # 全卷监控总开关
FSMON_USN_PATH_CACHE_MAX = 100_000     # file_ref → path LRU 上限（≈30 MB）
FSMON_USN_POLL_INTERVAL_S = 0.5        # 无事件时循环间隔
FSMON_USN_BUFFER_KB = 64               # DeviceIoControl 输出缓冲

# USN 用 reason mask（位或组合）：FILE_CREATE + RENAME_OLD_NAME_NEW
USN_REASON_MASK = 0x00000100 | 0x00002000

# 已知厂商子目录（避免合法安装噪声）
NOISY_VENDOR_DIRS = [
    "\\Microsoft\\",
    "\\Google\\",
    "\\Chrome\\",
    "\\Programs\\",
    "\\Microsoft VS Code\\",
    "\\Discord\\",
    "\\Spotify\\",
    "\\Steam\\",
    "\\NVIDIA\\",
    "\\JetBrains\\",
    "\\Docker\\",
    "\\Python\\",
    "\\nodejs\\",
]

# 大文件只算头尾哈希（性能保护）
FSMON_MAX_HASH_SIZE_MB = 50
FSMONHASH_HEAD_TAIL_KB = 64

# 安装行为豁免（频次合并）
INSTALLER_NOISE_WINDOW_S = 5
INSTALLER_NOISE_MIN_FILES = 3

# 后台 worker 并发
FSMON_WORKER_THREADS = 2
FSMON_QUEUED_EVENTS_MAX = 500

# 文件启发式评分（威胁分维度）
EXEC_EXT_HIT = 30                    # 可执行后缀加分
FILENAME_KEYWORD_HIT = 20            # 可疑关键词加分
NO_SIGNATURE_HIT = 20                 # 无数字签名加分
SOURCE_DIR_STARTUP = 30               # 来源目录加分
SOURCE_DIR_TEMP = 15
SOURCE_DIR_DESKTOP = 10
SOURCE_DIR_DOWNLOADS = 5
SOURCE_DIR_APPDATA = 5
SIZETOOLARGE_HIT = -5                # >100MB 减分

# 可疑文件后缀（大小写不敏感）
SUSPICIOUSEXEC_EXTS = {
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse",
    ".wsf", ".wsh", ".lnk", ".scr", ".msi", ".jar",
    ".hta", ".cpl", ".com", ".pif", ".gadget", ".inf",
    ".reg", ".docm", ".xlsm", ".pptm",
}

# 可疑文件名关键词
SUSPICIOUS_FILENAME_KEYWORDS = (
    "crack", "keygen", "patch", "installer", "setup",
    "activator", "loader", "hack", "cheat", "serial",
    "kms",
)

# EICAR 标准测试字符串（业内公认）—— 文件一旦包含这个模式直接判黑
EICAR_STD_BYTES = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_CONTENT_HIT = 50     # 文件内容含 EICAR 字符串的加分


def ensure_dirs() -> None:
    """启动时确保所有目录存在。"""
    for p in (DATA_DIR, LOGS_DIR, QUARANTINE_DIR, DB_DIR, CONFIG_DIR, BLOCKLIST_DIR):
        p.mkdir(parents=True, exist_ok=True)


def get_env(name: str, default: str) -> str:
    return os.environ.get(name, default)
