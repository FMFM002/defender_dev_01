"""多源威胁情报合并去重。

优先级:
- URLhaus 明确命中（query_status=ok）权重最高
- 其他源命中累积加分
- 任一源不可用不影响其他源

输出威胁评分:
- 0: 无记录
- 1~39: 低（单源命中无具体威胁）
- 40~79: 中
- 80~100: 高
"""

from __future__ import annotations

import threading
import time

from src.guardian.core.db import db
from src.guardian.core.logger import logger
from src.guardian.intel import blocklist, sec_mcp, urlhaus


def check_url(url: str, use_cache: bool = True) -> dict:
    """URL 查询：先缓存，再多源并行。"""
    if use_cache:
        cached = db.get_url(url)
        if cached is not None:
            logger.debug(f"cache HIT url={url[:80]} score={cached['threat_score']}")
            return {**cached["result"], "_cache": "hit", "_threat_score": cached["threat_score"]}

    results = _query_all(url)
    merged = _merge(results)
    threat_score = _score(merged)

    if use_cache:
        db.put_url(url, merged, threat_score)

    return {**merged, "_cache": "miss", "_threat_score": threat_score}


def _query_all(url: str) -> list[dict]:
    """多源查询：本地黑名单同步（快），远端源并行。"""
    results: list[dict] = []

    # 1) 本地域名黑名单 —— 走 SQLite 索引，毫秒级，同步执行
    try:
        results.append(blocklist.check_url(url))
    except Exception as e:
        logger.warning(f"intel source blocklist crashed: {e}")

    # 2) 远端源并行（URLhaus / sec-mcp）
    threads: list[tuple[threading.Thread, callable]] = []

    def _wrap(fn, name):
        def run():
            try:
                r = fn(url)
                results.append(r)
            except Exception as e:
                logger.warning(f"intel source {name} crashed: {e}")
        return run

    t1 = threading.Thread(target=_wrap(urlhaus.query_url, "urlhaus"), daemon=True)
    t2 = threading.Thread(target=_wrap(sec_mcp.query_url, "sec_mcp"), daemon=True)
    t1.start()
    t2.start()
    t1.join(timeout=10)
    t2.join(timeout=10)
    return results


def _merge(results: list[dict]) -> dict:
    """合并多源结果。"""
    merged = {
        "sources": [],
        "malicious": False,
        "threats": [],
        "tags": [],
        "url_status": None,
        "errors": [],
    }
    seen_tags: set[str] = set()
    for r in results:
        merged["sources"].append({
            "source": r["source"],
            "status": r["status"],
            "malicious": r["malicious"],
            "threat": r.get("threat"),
        })
        if r.get("malicious"):
            merged["malicious"] = True
            if r.get("threat"):
                merged["threats"].append(r["threat"])
        for t in r.get("tags") or []:
            if t not in seen_tags:
                seen_tags.add(t)
                merged["tags"].append(t)
        if r.get("url_status"):
            merged["url_status"] = r["url_status"]
        if r["status"] == "error":
            merged["errors"].append({"source": r["source"], "error": r.get("error")})
    return merged


def check_hash(sha256: str, use_cache: bool = True) -> dict:
    """文件哈希查询：先缓存。P1 阶段无在线哈希源，直接返回未知（让上层决定是否放行）。

    返回: {malicious, sources, threat_score, _cache, raw}
    """
    if use_cache:
        cached = db.get_hash(sha256)
        if cached is not None:
            return {**cached["result"], "_cache": "hit"}

    # P1 阶段：没有免 Key 的在线哈希源（P2 接 VirusTotal）
    # 暂用本地启发式：空结果，threat_score=0
    merged = {
        "sources": [],
        "malicious": False,
        "threats": [],
        "tags": [],
        "sha256": sha256,
        "errors": [],
        "note": "P1 阶段未启用在线哈希源",
    }
    score = 0
    if use_cache:
        db.put_hash(sha256, merged, score)
    return {**merged, "_cache": "miss", "_threat_score": score}


def _score(merged: dict) -> int:
    """综合评分。"""
    if not merged["malicious"]:
        return 0
    score = 50  # 基础分（任一源命中）
    for src in merged["sources"]:
        if src["source"] == "urlhaus" and src["malicious"]:
            score += 30  # URLhaus 明确命中权重最高
        if src["source"] == "blocklist" and src["malicious"]:
            score += 20  # 本地钓鱼域名黑名单
    # 多源印证 +10
    malicious_sources = sum(1 for s in merged["sources"] if s["malicious"])
    if malicious_sources >= 2:
        score += 10
    return min(score, 100)
