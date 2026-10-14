"""多源威胁情报合并去重 + 文件启发式评分。

URL 聚合：
- URLhaus 明确命中权重最高
- 其他源命中累积加分
- 任一源不可用不影响其他源

文件哈希聚合：
- MalwareBazaar 云查（abuse.ch Key，key 通用 URLhaus）
- 本地启发式：可执行后缀 / 文件名关键词 / 来源目录 / 无签名 / EICAR 标准串

输出威胁评分:
- 0: 无记录
- 1~39: 低（单源命中无具体威胁）
- 40~69: 中
- 70~100: 高（>=阈值触发隔离）
"""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path

from src.guardian.core.config import (
    EICAR_CONTENT_HIT,
    EICAR_STD_BYTES,
    EXEC_EXT_HIT,
    FILENAME_KEYWORD_HIT,
    NOISY_VENDOR_DIRS,
    NO_SIGNATURE_HIT,
    SOURCE_DIR_APPDATA,
    SOURCE_DIR_DESKTOP,
    SOURCE_DIR_DOWNLOADS,
    SOURCE_DIR_STARTUP,
    SOURCE_DIR_TEMP,
    SIZETOOLARGE_HIT,
    SUSPICIOUSEXEC_EXTS,
    SUSPICIOUS_FILENAME_KEYWORDS,
)
from src.guardian.core.db import db
from src.guardian.core.logger import logger
from src.guardian.intel import blocklist, hashintel, sec_mcp, urlhaus
from src.guardian.quarantine.signature import has_signature


def check_url(url: str, use_cache: bool = True) -> dict:
    """URL 查询：先缓存，再多源并行。"""
    if use_cache:
        cached = db.get_url(url)
        if cached is not None:
            logger.debug(f"cache HIT url={url[:80]} score={cached['threat_score']}")
            return {**cached["result"], "_cache": "hit", "_threat_score": cached["threat_score"]}

    results = _query_url_sources(url)
    merged = _merge_url_results(results)
    threat_score = _score_url(merged)

    if use_cache:
        db.put_url(url, merged, threat_score)

    return {**merged, "_cache": "miss", "_threat_score": threat_score}


def _query_url_sources(url: str) -> list[dict]:
    results: list[dict] = []
    try:
        results.append(blocklist.check_url(url))
    except Exception as e:
        logger.warning(f"intel source blocklist crashed: {e}")

    threads = []

    def _wrap(fn, name):
        def run():
            try:
                r = fn(url)
                results.append(r)
            except Exception as e:
                logger.warning(f"intel source {name} crashed: {e}")
        return run

    t1 = threading.Thread(target=_wrap(urlhaus.query_url, "urlhaus"), daemon=True)
    t2 = threading.Thread(target=_wrap(lambda u: sec_mcp.query_url(u), "sec_mcp"), daemon=True)
    t1.start()
    t2.start()
    t1.join(timeout=10)
    t2.join(timeout=10)
    return results


def _merge_url_results(results: list[dict]) -> dict:
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


def _score_url(merged: dict) -> int:
    if not merged["malicious"]:
        return 0
    score = 50
    for src in merged["sources"]:
        if src["source"] == "urlhaus" and src["malicious"]:
            score += 30
        if src["source"] == "blocklist" and src["malicious"]:
            score += 20
    malicious_sources = sum(1 for s in merged["sources"] if s["malicious"])
    if malicious_sources >= 2:
        score += 10
    return min(score, 100)


# ============================================================
# 文件哈希聚合（P2-1：下载钩子）
# ============================================================

def check_hash(
    sha256: str,
    *,
    file_path: str | None = None,
    source_dir: str | None = None,
    use_cache: bool = True,
) -> dict:
    """文件哈希查询 + 启发式评分。

    返回: {malicious, sources, threat_score, evidence, sha256, ...}
    """
    if use_cache:
        cached = db.get_hash(sha256)
        if cached is not None and not file_path:
            return {**cached["result"], "_cache": "hit"}

    results: list[dict] = []

    # 1) MalwareBazaar 云查（线程化以避免延迟）
    t = threading.Thread(target=_run_hashintel(sha256, results), daemon=True)
    t.start()
    t.join(timeout=10)

    # 2) 本地启发式（仅在提供了 file_path 时计算）
    heuristic_evidence: list[dict] = []
    if file_path:
        heur = evaluate_file_heuristic(file_path, source_dir)
        heuristic_evidence = heur.get("evidence", [])

    merged = _merge_hash_results(results, heuristic_evidence, file_path)
    threat_score = _score_hash(merged)

    if use_cache:
        db.put_hash(sha256, merged, threat_score)

    return {**merged, "_cache": "miss", "_threat_score": threat_score}


def _run_hashintel(sha256, results):
    def run():
        try:
            results.append(hashintel.query_hash(sha256))
        except Exception as e:
            logger.warning(f"intel source hashintel crashed: {e}")
    return run


def _merge_hash_results(
    results: list[dict],
    heuristic_evidence: list[dict],
    file_path: str | None,
) -> dict:
    merged = {
        "sources": results[:],
        "malicious": False,
        "threats": [],
        "tags": [],
        "errors": [],
        "evidence": [],
        "sha256": None,
        "path": file_path,
    }
    seen_tags: set[str] = set()
    for r in results:
        if r.get("malicious"):
            merged["malicious"] = True
            if r.get("threat"):
                merged["threats"].append(r["threat"])
        for t in r.get("tags") or []:
            if t not in seen_tags:
                seen_tags.add(t)
                merged["tags"].append(t)
        if r.get("sha256"):
            merged["sha256"] = r["sha256"]
        if r["status"] == "error":
            merged["errors"].append({"source": r["source"], "error": r.get("error")})

    # 启发式证据带上
    if heuristic_evidence:
        merged["evidence"].extend(heuristic_evidence)
        # 启发式单项评分 >= 30 视为可疑
        if any(ev.get("score", 0) >= 30 for ev in heuristic_evidence):
            # 不直接置 malicious（避免误伤合法安装），但 evidence 已经在
            pass

    return merged


def _score_hash(merged: dict) -> int:
    """综合评分：云查命中 + 启发式。"""
    if not merged["malicious"] and not merged.get("evidence"):
        return 0

    score = 0
    # 云查命中（MB / URLhaus）
    for s in merged["sources"]:
        if s.get("malicious"):
            if s["source"] == "malwarebazaar":
                score += 80
            else:
                score += 50

    # 启发式累加（带 evidence dict 中的 score 字段）
    for ev in merged.get("evidence", []):
        score += int(ev.get("score", 0))

    # 多源印证
    malicious_sources = sum(1 for s in merged["sources"] if s.get("malicious"))
    if malicious_sources >= 2:
        score += 10

    return max(0, min(score, 100))


# ============================================================
# 文件启发式评分（本地）
# ============================================================

def evaluate_file_heuristic(file_path: str, source_dir: str | None = None) -> dict:
    """对单个文件做启发式评分，返回 evidence 列表（每项带 score）。

    evidence 项格式: {rule, detail, score}
    """
    p = Path(filePath if False else file_path)  # 兼容 Python 命名
    p = Path(file_path)
    evidence: list[dict] = []
    if not p.exists() or not p.is_file():
        return {"evidence": evidence, "score": 0}

    name_lower = p.name.lower()
    ext = p.suffix.lower()
    size_bytes = 0
    try:
        size_bytes = p.stat().st_size
    except OSError:
        pass

    # 1) 可执行后缀
    if ext in SUSPICIOUSEXEC_EXTS:
        evidence.append({"rule": "exec_ext", "detail": f"可疑后缀 {ext}", "score": EXEC_EXT_HIT})

    # 2) 文件名关键词
    for kw in SUSPICIOUS_FILENAME_KEYWORDS:
        if kw in name_lower:
            evidence.append({
                "rule": "filename_keyword",
                "detail": f"文件名含可疑关键词 '{kw}'",
                "score": FILENAME_KEYWORD_HIT,
            })
            break

    # 3) 来源目录
    src = (source_dir or "").lower()
    if src:
        if "startup" in src or "启动" in src:
            evidence.append({"rule": "source_startup", "detail": "落入启动项目录", "score": SOURCE_DIR_STARTUP})
        elif "temp" in src and "appdata" not in src:
            evidence.append({"rule": "source_temp", "detail": "落入临时目录", "score": SOURCE_DIR_TEMP})
        elif "desktop" in src:
            evidence.append({"rule": "source_desktop", "detail": "落入桌面", "score": SOURCE_DIR_DESKTOP})
        elif "downloads" in src or "下载" in src:
            evidence.append({"rule": "source_downloads", "detail": "落入 Downloads", "score": SOURCE_DIR_DOWNLOADS})
        elif LOCALAPPDATA_LOWER := (os.environ.get("LOCALAPPDATA", "").lower()):
            if LOCALAPPDATA_LOWER and LOCALAPPDATA_LOWER in src:
                # 只对 AppData\Local 落到已知厂商子目录外的加分；已知厂商略过
                in_vendor = any(v.replace("\\", os.sep).lower() in src for v in NOISY_VENDOR_DIRS)
                if not in_vendor:
                    evidence.append({"rule": "source_appdata", "detail": "落入 AppData\\Local", "score": SOURCE_DIR_APPDATA})

    # 4) 大文件减分（>100MB 多为合法安装包/镜像）
    if size_bytes > 100 * 1024 * 1024:
        evidence.append({"rule": "size_large", "detail": f"大文件 {size_bytes//1024//1024} MB", "score": SIZETOOLARGE_HIT})

    # 5) Authenticode 数字签名
    if ext in SUSPICIOUSEXEC_EXTS or ".scr" in ext or ".msi" in ext or ext == ".dll":
        sig = has_signature(str(p))
        if sig is False:
            evidence.append({"rule": "no_signature", "detail": "可执行但无数字签名", "score": NO_SIGNATURE_HIT})
        # sig is True → 不加分；sig is None → 验证失败，不加分也不扣分

    # 6) EICAR 标准测试串
    if size_bytes and size_bytes < 2 * 1024 * 1024:
        try:
            with open(p, "rb") as f:
                head = f.read(min(size_bytes, 4096))
            if EICAR_STD_BYTES in head:
                evidence.append({
                    "rule": "eicar_standard",
                    "detail": "文件含 EICAR 标准测试字符串",
                    "score": EICAR_CONTENT_HIT,
                })
        except OSError:
            pass

    return {"evidence": evidence}


# 旧 check_hash 兼容：仅传 sha256 时退化为旧"P1占位"实现
# 上面已扩展：保留 compat 入口即可。
