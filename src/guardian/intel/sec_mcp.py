"""sec-mcp 占位（公开接口待确认）。

GitHub: https://github.com/0x4m4/sec-mcp（待核实）
聚合源: OpenPhish / PhishTank / PhishStats / URLhaus / BlocklistDE / CINSSCORE

如果未来确认有 HTTP 入口，在这里补 httpx.Client.post(...)

目前占位返回：空结果 + 状态 unavailable，聚合层正常跳过此源。
"""

from __future__ import annotations

from src.guardian.core.logger import logger

_AVAILABLE = False


def query_url(url: str) -> dict:
    """占位实现：始终返回 unavailable。"""
    return {
        "source": "sec_mcp",
        "status": "unavailable",
        "malicious": False,
        "threat": None,
        "tags": [],
        "url_status": None,
        "date_added": None,
        "raw": {},
        "note": "sec-mcp 公开接口未确认，目前跳过此源",
    }


def is_available() -> bool:
    return _AVAILABLE
