"""URLhaus 客户端（abuse.ch，免 API Key）。

参考: https://urlhaus-api.abuse.ch/

URL 查询:
  POST https://urlhaus-api.abuse.ch/v1/url/
  body: url=<url>

响应关键字段:
  - query_status: 'ok' | 'no_results' | 'invalid'
  - threat: 'malware_download'
  - url_status: 'online' | 'offline' | 'unknown'
  - tags: [...]
  - date_added
"""

from __future__ import annotations

import httpx

from src.guardian.core.config import URLHAUS_AUTH_KEY
from src.guardian.core.logger import logger
from src.guardian.core.proxy import proxy

API_URL = "https://urlhaus-api.abuse.ch/v1/url/"
TIMEOUT = 8.0

# 未配置 Auth-Key 时只提示一次，避免每次导航都刷日志
_warned_no_key = False
_key_logged = False
_warned_bad_key = False


def query_url(url: str) -> dict:
    """查询 URL，返回标准化结果。

    注意：abuse.ch 自 2025-06-30 起强制要求 Auth-Key（HTTP 头 `Auth-Key`）。
    未配置 URLHAUS_AUTH_KEY 时直接返回 status='disabled'，不算异常、不刷日志。

    返回格式:
      {
        'source': 'urlhaus',
        'status': 'ok' | 'no_results' | 'invalid' | 'disabled' | 'error',
        'malicious': bool,
        'threat': str | None,
        'tags': list[str],
        'url_status': str | None,
        'date_added': str | None,
        'raw': dict,
      }
    """
    global _warned_no_key, _key_logged
    if not URLHAUS_AUTH_KEY:
        if not _warned_no_key:
            logger.info(
                "URLhaus 未配置 Auth-Key，已跳过（abuse.ch 2025-06-30 起强制鉴权）。"
                "启用方式：在项目根目录 .env 写入一行 URLHAUS_AUTH_KEY=你的Key（或设同名环境变量）；"
                "Key 免费申请：https://auth.abuse.ch/"
            )
            _warned_no_key = True
        return {
            "source": "urlhaus",
            "status": "disabled",
            "malicious": False,
            "threat": None,
            "tags": [],
            "url_status": None,
            "date_added": None,
            "raw": {},
        }

    if not _key_logged:
        logger.info(f"URLhaus 已启用（Auth-Key 长度 {len(URLHAUS_AUTH_KEY)}）。")
        _key_logged = True

    proxy_url = proxy.get_proxy_url()
    try:
        with httpx.Client(timeout=TIMEOUT, proxy=proxy_url) as client:
            r = client.post(API_URL, data={"url": url}, headers={"Auth-Key": URLHAUS_AUTH_KEY})
        if r.status_code in (401, 403):
            qs = ""
            try:
                qs = (r.json() or {}).get("query_status") or ""
            except Exception:
                pass
            if qs == "unknown_auth_key" or r.status_code == 401:
                _warn_bad_key()
            else:
                logger.warning(f"URLhaus HTTP {r.status_code} for {url[:80]}")
            return _error(url, f"http_{r.status_code}" + (f":{qs}" if qs else ""))
        if r.status_code != 200:
            logger.warning(f"URLhaus HTTP {r.status_code} for {url[:80]}")
            return _error(url, f"http_{r.status_code}")
        data = r.json()
    except Exception as e:
        logger.warning(f"URLhaus query failed for {url[:80]}: {e}")
        return _error(url, str(e))

    status = data.get("query_status", "error")
    if status == "ok":
        return {
            "source": "urlhaus",
            "status": "ok",
            "malicious": True,
            "threat": data.get("threat"),
            "tags": data.get("tags") or [],
            "url_status": data.get("url_status"),
            "date_added": data.get("date_added"),
            "raw": data,
        }
    elif status == "no_results":
        return {
            "source": "urlhaus",
            "status": "no_results",
            "malicious": False,
            "threat": None,
            "tags": [],
            "url_status": None,
            "date_added": None,
            "raw": data,
        }
    else:
        return {
            "source": "urlhaus",
            "status": status,
            "malicious": False,
            "threat": None,
            "tags": [],
            "url_status": None,
            "date_added": None,
            "raw": data,
        }


def _warn_bad_key() -> None:
    """Auth-Key 被 abuse.ch 拒绝时只提示一次。"""
    global _warned_bad_key
    if _warned_bad_key:
        return
    _warned_bad_key = True
    logger.warning(
        "URLhaus 拒绝了当前 Auth-Key（unknown_auth_key）—— Key 无效、写错或尚未激活。"
        "请到 https://auth.abuse.ch/ 登录 → 个人资料(Profile) 的 Optional 区域点 'Generate Key' "
        "重新生成，复制完整 Key 后更新项目根目录 .env 里的 URLHAUS_AUTH_KEY，再重启服务。"
        "（Key 未生效期间不影响本地黑名单/启发式拦截，只是云端 URLhaus 结果暂缺。）"
    )


def _error(url: str, msg: str) -> dict:
    return {
        "source": "urlhaus",
        "status": "error",
        "malicious": False,
        "threat": None,
        "tags": [],
        "url_status": None,
        "date_added": None,
        "error": msg,
        "raw": {},
    }
