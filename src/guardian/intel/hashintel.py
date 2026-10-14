"""MalwareBazaar 哈希云查客户端。

API 文档：https://bazaar.abuse.ch/api/
端点：POST https://mbapi.abuse.ch/api/v1/
参数：query=get_info, hash=<sha256>
响应 query_status：
  - 'ok'           -> 样本在库（含 threat / signature / tags / intel / delivery_method）
  - 'hash_not_found' -> 未知哈希
  - 'invalid' / 'empty' -> 参数无效

Auth-Key 与 URLhaus 通用（同一个 abuse.ch 账户），代码自动复用 URLHAUS_AUTH_KEY。
"""

from __future__ import annotations

import httpx

from src.guardian.core.config import MALBAZAAR_API, URLHAUS_AUTH_KEY
from src.guardian.core.logger import logger
from src.guardian.core.proxy import proxy

TIMEOUT = 8.0

# 最近一次云查状态
_warned_no_key = False
_state = "unknown"     # disabled / valid / invalid / unreachable / unknown
_last = ""             # 详情

_DISABLED = object()


def _set_state(s: str, msg: str) -> None:
    global _state, _last
    _state, _last = s, msg


def status() -> dict:
    return {
        "source": "malwarebazaar",
        "configured": bool(URLHAUS_AUTH_KEY),
        "key_len": len(URLHAUS_AUTH_KEY),
        "state": _state,
        "detail": _last,
    }


def _no_key_skip(sha256: str) -> dict | None:
    """未配置 Key 时返回禁用占位（None）；否则返回 None。"""
    global _warned_no_key
    if URLHAUS_AUTH_KEY:
        return None
    if not _warned_no_key:
        logger.info(
            "MalwareBazaar 未配置 Auth-Key，已跳过（abuse.ch 2025-06-30 起强制鉴权）。"
        )
        _warned_no_key = True
    return {
        "source": "malwarebazaar",
        "status": "disabled",
        "malicious": False,
        "threat": None,
        "tags": [],
        "sha256": sha256,
        "_threat_score": 0,
        "note": "未配置 Auth-Key",
    }


def query_hash(sha256: str) -> dict:
    """查询一个 SHA-256。返回统一结构。

    返回字段：
      - source, status, malicious, threat, tags, sha256, _threat_score
    """
    placeholder = _no_key_skip(sha256)
    if placeholder is not None:
        _set_state("disabled", "Auth-Key 未配置")
        return placeholder

    if not sha256 or len(sha256) != 64:
        _set_state("invalid", "hash 长度非 64")
        return {
            "source": "malwarebazaar",
            "status": "invalid",
            "malicious": False,
            "threat": None,
            "tags": [],
            "sha256": sha256,
            "_threat_score": 0,
            "error": "sha256 长度必须为 64",
        }

    proxy_url = proxy.get_proxy_url()
    try:
        with httpx.Client(timeout=TIMEOUT, proxy=proxy_url) as client:
            r = client.post(
                MALBAZAAR_API,
                data={"query": "get_info", "hash": sha256},
                headers={"Auth-Key": URLHAUS_AUTH_KEY},
            )
    except Exception as e:
        _set_state("unreachable", str(e)[:120])
        logger.warning(f"MalwareBazaar http failed for {sha256[:16]}: {e}")
        return {
            "source": "malwarebazaar",
            "status": "error",
            "malicious": False,
            "threat": None,
            "tags": [],
            "sha256": sha256,
            "_threat_score": 0,
            "error": str(e),
        }

    if r.status_code != 200:
        body = (r.text or "")[:200]
        if "unknown_auth_key" in body or r.status_code in (401, 403):
            _set_state("invalid", f"Auth-Key 被拒 (HTTP {r.status_code})")
            logger.warning(
                f"MalwareBazaar Auth-Key 被拒绝：{body[:120]}；"
                "请到 auth.abuse.ch 重新生成 Key 并更新 .env"
            )
        else:
            _set_state("unreachable", f"HTTP {r.status_code}")
            logger.warning(f"MalwareBazaar HTTP {r.status_code} for {sha256[:16]}")
        return {
            "source": "malwarebazaar",
            "status": "error",
            "malicious": False,
            "threat": None,
            "tags": [],
            "sha256": sha256,
            "_threat_score": 0,
            "error": f"http_{r.status_code}",
        }

    try:
        data = r.json()
    except Exception as e:
        _set_state("unreachable", "json parse failed")
        logger.warning(f"MalwareBazaar json parse failed: {e}")
        return {
            "source": "malwarebazaar",
            "status": "error",
            "malicious": False,
            "threat": None,
            "tags": [],
            "sha256": sha256,
            "_threat_score": 0,
            "error": "json parse",
        }

    status = data.get("query_status", "error")
    if status == "ok":
        _set_state("valid", "Auth-Key 有效，云查已启用")
        threat = (
            data.get("threat")
            or data.get("malware")
            or data.get("signature")
            or "malware_sample"
        )
        tags = data.get("tags") or []
        # 评分：明确命中 +80
        return {
            "source": "malwarebazaar",
            "status": "ok",
            "malicious": True,
            "threat": threat,
            "tags": tags,
            "sha256": sha256,
            "_threat_score": 80,
            "delivery_method": data.get("delivery_method"),
            "file_type": data.get("file_type"),
            "first_seen": data.get("first_seen"),
            "signature": data.get("signature"),
        }
    elif status in ("hash_not_found", "no_results"):
        _set_state("valid", "Key 有效（哈希未知）")
        return {
            "source": "malwarebazaar",
            "status": status,
            "malicious": False,
            "threat": None,
            "tags": [],
            "sha256": sha256,
            "_threat_score": 0,
        }
    elif status in ("invalid", "empty"):
        _set_state("valid", f"参数问题: {status}")
        return {
            "source": "malwarebazaar",
            "status": "invalid",
            "malicious": False,
            "threat": None,
            "tags": [],
            "sha256": sha256,
            "_threat_score": 0,
        }
    else:
        _set_state("unreachable", f"未知 status: {status}")
        logger.warning(f"MalwareBazaar 未识别 status={status} for {sha256[:16]}")
        return {
            "source": "malwarebazaar",
            "status": "error",
            "malicious": False,
            "threat": None,
            "tags": [],
            "sha256": sha256,
            "_threat_score": 0,
            "error": f"unknown_status:{status}",
        }
