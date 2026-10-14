"""本地域名黑名单（Phishing Army，免 Key 免费源）。

背景：abuse.ch（URLhaus）自 2025-06-30 起对所有 API 强制要求 Auth-Key，
"免 Key 逐条查询"路线已不可行。改用【整表下载 + 本地匹配】的方案：

  - 数据源：Phishing Army 社区钓鱼域名黑名单（约 16 万条，无需任何 Key）
  - 存储：SQLite `domain_blocklist` 表（走主键索引，查询毫秒级、几乎不吃内存）
  - 刷新：首次启动后台自动下载，之后每 24h 一次（BLOCKLIST_REFRESH_HOURS）
  - 匹配：完整域名逐级回退到注册域，最多 6 级

对外接口：
  refresh(force=False) -> dict    下载并重建本地库
  check_url(url) -> dict          标准 source 结构（与 urlhaus 对齐）
  status() -> dict                当前库状态
"""

from __future__ import annotations

import threading
import time
from urllib.parse import urlparse

import httpx

from src.guardian.core.config import (
    BLOCKLIST_DIR,
    BLOCKLIST_ENABLED,
    BLOCKLIST_REFRESH_HOURS,
    PHISHING_ARMY_URL,
)
from src.guardian.core.db import db
from src.guardian.core.logger import logger
from src.guardian.core.proxy import proxy

META_LAST_REFRESH = "blocklist_last_refresh"
META_COUNT = "blocklist_count"

_RAW_FILE = BLOCKLIST_DIR / "phishing_army.txt"
_TIMEOUT = 60.0
_refresh_lock = threading.Lock()
_refreshing = False


def should_refresh() -> bool:
    last = db.meta_get(META_LAST_REFRESH)
    if not last:
        return True
    try:
        return (time.time() - int(last)) > BLOCKLIST_REFRESH_HOURS * 3600
    except Exception:
        return True


def refresh(force: bool = False) -> dict:
    """下载 Phishing Army 黑名单并重建本地库。

    返回 {ok, count, bytes, source, message}
    """
    global _refreshing
    if not BLOCKLIST_ENABLED:
        return {"ok": False, "message": "blocklist disabled"}

    if not force and not should_refresh():
        return {"ok": True, "count": db.domain_blocklist_count(), "message": "up-to-date (skip)"}

    if not _refresh_lock.acquire(blocking=False):
        return {"ok": False, "message": "already refreshing"}
    _refreshing = True
    try:
        proxy_url = proxy.get_proxy_url()
        logger.info(f"blocklist: 开始下载 {PHISHING_ARMY_URL} (proxy={proxy_url or 'direct'})")
        BLOCKLIST_DIR.mkdir(parents=True, exist_ok=True)
        with httpx.Client(timeout=_TIMEOUT, proxy=proxy_url, follow_redirects=True) as client:
            with client.stream("GET", PHISHING_ARMY_URL) as r:
                if r.status_code != 200:
                    logger.warning(f"blocklist: HTTP {r.status_code}，保留旧库")
                    return {"ok": False, "message": f"http_{r.status_code}"}
                total = 0
                with open(_RAW_FILE, "wb") as f:
                    for chunk in r.iter_bytes(65536):
                        f.write(chunk)
                        total += len(chunk)

        domains = _parse_file(_RAW_FILE)
        if not domains:
            logger.warning("blocklist: 下载成功但解析为空，保留旧库")
            return {"ok": False, "message": "parsed empty"}

        n = db.replace_domain_blocklist(domains)
        db.meta_set(META_LAST_REFRESH, str(int(time.time())))
        db.meta_set(META_COUNT, str(n))
        logger.info(f"blocklist: 已更新 {n} 条域名（{total // 1024} KB）")
        return {"ok": True, "count": n, "bytes": total, "source": "phishing.army"}
    except Exception as e:
        logger.warning(f"blocklist: 下载/解析失败，保留旧库: {e}")
        return {"ok": False, "message": str(e)}
    finally:
        _refreshing = False
        _refresh_lock.release()


def _parse_file(path) -> list[str]:
    """解析纯域名清单。兼容 `||domain^` / 带 scheme 的写法。"""
    out: set[str] = set()
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#") or line.startswith("!"):
                    continue
                line = line.strip("|^").strip()
                if not line:
                    continue
                # 兼容 hostfile / hosts 格式 "0.0.0.0 evil.com"
                parts = line.split()
                if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
                    line = parts[1]
                # 兼容带 scheme
                if "://" in line:
                    try:
                        line = urlparse(line).hostname or ""
                    except Exception:
                        line = ""
                line = line.strip().lower().strip(".")
                if line and "." in line and not line.startswith("."):
                    out.add(line)
    except FileNotFoundError:
        return []
    return sorted(out)


def check_url(url: str) -> dict:
    """查询 URL 是否命中本地域名黑名单。返回标准 source 结构。"""
    if not BLOCKLIST_ENABLED:
        return {"source": "blocklist", "status": "disabled", "malicious": False,
                "threat": None, "tags": [], "url_status": None}

    try:
        host = urlparse(url).hostname or ""
    except Exception:
        host = ""
    if not host:
        return {"source": "blocklist", "status": "invalid", "malicious": False,
                "threat": None, "tags": [], "url_status": None}

    matched = db.is_blocked_domain(host)
    if matched:
        return {
            "source": "blocklist",
            "status": "ok",
            "malicious": True,
            "threat": "phishing_domain",
            "tags": ["phishing", "blocklist"],
            "url_status": None,
            "matched_domain": matched,
        }
    return {"source": "blocklist", "status": "no_results", "malicious": False,
            "threat": None, "tags": [], "url_status": None}


def status() -> dict:
    last = db.meta_get(META_LAST_REFRESH)
    return {
        "enabled": BLOCKLIST_ENABLED,
        "count": db.domain_blocklist_count(),
        "last_refresh": int(last) if last else None,
        "refreshing": _refreshing,
        "source": "phishing.army",
        "next_refresh_hours": BLOCKLIST_REFRESH_HOURS,
    }
