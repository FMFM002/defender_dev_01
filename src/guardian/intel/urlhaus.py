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

from src.guardian.core.logger import logger
from src.guardian.core.proxy import proxy

API_URL = "https://urlhaus-api.abuse.ch/v1/url/"
TIMEOUT = 8.0


def query_url(url: str) -> dict:
    """查询 URL，返回标准化结果。

    返回格式:
      {
        'source': 'urlhaus',
        'status': 'ok' | 'no_results' | 'invalid' | 'error',
        'malicious': bool,
        'threat': str | None,
        'tags': list[str],
        'url_status': str | None,
        'date_added': str | None,
        'raw': dict,
      }
    """
    proxy_url = proxy.get_proxy_url()
    try:
        with httpx.Client(timeout=TIMEOUT, proxy=proxy_url) as client:
            r = client.post(API_URL, data={"url": url})
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
