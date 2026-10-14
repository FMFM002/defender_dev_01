"""HTTP API（与 Edge 扩展通信）。

端点：
  GET  /health                      - 健康检查 + RSS + 队列大小
  POST /intel/url                   - 查询 URL（云查 + 缓存）
  POST /intel/hash                  - 查询文件哈希
  GET  /intel/status                - 威胁情报状态（本地黑名单 + URLhaus 云查）
  GET  /intel/blocklist/status      - 本地黑名单状态
  POST /intel/blocklist/refresh     - 强制刷新本地黑名单
  GET  /whitelist                   - 列出白名单
  POST /whitelist                   - 添加白名单
  DELETE /whitelist/{pattern}       - 移除白名单
  POST /whitelist/match             - 检查 URL 是否命中白名单
  GET  /quarantine                  - 列出隔离区
  POST /quarantine                  - 隔离文件 {path, reason}
  POST /quarantine/{id}/restore     - 恢复
  DELETE /quarantine/{id}           - 彻底删除
  GET  /asr/rules                   - 列出 ASR 规则 + 当前状态
  GET  /proc_alerts                 - 最近进程告警
  POST /system/check_file           - 文件监控评分 + 自动隔离（fsmon.feed）
  GET  /system/fsmon/status         - 文件监控状态
  POST /system/fsmon/feed           - 手动注入文件路径（测试）
  POST /system/quarantine/check     - 同步评估单个文件
  POST /alerts/url_block            - 扩展上报 URL 拦截事件
  GET  /alerts/history              - 拉取告警历史（URL/进程/文件 三类合并）
  GET  /alerts/summary              - 拉取告警摘要（按规则 top + 分类统计）
"""

from __future__ import annotations

import time
from typing import Literal

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from src.guardian.core.db import db
from src.guardian.core.logger import logger
from src.guardian.intel.aggregator import check_hash, check_url
from src.guardian.quarantine import manager as quarantine

router = APIRouter()


# ---- Health ----

@router.get("/health")
def health() -> dict:
    import psutil
    p = psutil.Process()
    rss_mb = p.memory_info().rss / 1024 / 1024
    return {
        "ok": True,
        "rss_mb": round(rss_mb, 1),
        "queue_size": db.queue_size(),
    }


# ---- Intel ----

class UrlQuery(BaseModel):
    url: str = Field(..., min_length=4, max_length=2048)


class HashQuery(BaseModel):
    sha256: str = Field(..., min_length=64, max_length=64)


@router.post("/intel/url")
def intel_url(q: UrlQuery) -> dict:
    return check_url(q.url)


@router.post("/intel/hash")
def intel_hash(q: HashQuery) -> dict:
    return check_hash(q.sha256)


# ---- 本地域名黑名单（Phishing Army）----

@router.get("/intel/blocklist/status")
def blocklist_status() -> dict:
    from src.guardian.intel import blocklist
    return blocklist.status()


@router.post("/intel/blocklist/refresh")
def blocklist_refresh(force: bool = True) -> dict:
    from src.guardian.intel import blocklist
    return blocklist.refresh(force=force)


@router.get("/intel/status")
def intel_status() -> dict:
    """威胁情报整体状态（供扩展自检面板展示）：本地黑名单 + URLhaus 云查。"""
    from src.guardian.intel import blocklist, urlhaus
    return {
        "blocklist": blocklist.status(),
        "urlhaus": urlhaus.status(),
    }


# ---- Whitelist ----

class WhitelistAdd(BaseModel):
    pattern: str = Field(..., min_length=1)


class UrlMatch(BaseModel):
    url: str


@router.get("/whitelist")
def whitelist_list() -> dict:
    return {"items": db.whitelist_list()}


@router.post("/whitelist")
def whitelist_add(req: WhitelistAdd) -> dict:
    ok = db.whitelist_add(req.pattern)
    return {"ok": ok}


@router.delete("/whitelist/{pattern}")
def whitelist_remove(pattern: str) -> dict:
    ok = db.whitelist_remove(pattern)
    return {"ok": ok}


@router.post("/whitelist/match")
def whitelist_match(req: UrlMatch) -> dict:
    pat = db.whitelist_match(req.url)
    return {"matched": pat is not None, "pattern": pat}


# ---- Quarantine ----

class QuarantineAdd(BaseModel):
    path: str
    reason: str


@router.get("/quarantine")
def quarantine_list() -> dict:
    return {"items": quarantine.list_all()}


@router.post("/quarantine")
def quarantine_add(req: QuarantineAdd) -> dict:
    qid = quarantine.quarantine(req.path, req.reason)
    if qid is None:
        raise HTTPException(400, "隔离失败，文件不存在或读取失败")
    return {"ok": True, "id": qid}


@router.post("/quarantine/{qid}/restore")
def quarantine_restore(qid: int) -> dict:
    ok, msg = quarantine.restore(qid)
    return {"ok": ok, "message": msg}


@router.delete("/quarantine/{qid}")
def quarantine_delete(qid: int) -> dict:
    ok, msg = quarantine.delete_forever(qid)
    return {"ok": ok, "message": msg}


# ---- ASR ----

@router.get("/asr/rules")
def asr_rules() -> dict:
    from src.guardian.asr import rules as asr_rules
    return {"rules": asr_rules.list_rules()}


# ---- Proc Alerts (WMI/ETW 进程告警) ----

@router.get("/proc_alerts")
def proc_alerts(limit: int = 50) -> dict:
    """最近进程告警（高风险父进程 / 命令行 / 投放路径）。"""
    return {"items": db.list_proc_alerts(limit=min(max(limit, 1), 200))}


# ---- 文件监控（P2-1）----

class CheckFile(BaseModel):
    path: str = Field(..., min_length=1)
    source_dir: str = ""


@router.post("/system/check_file")
@router.post("/system/quarantine/check")  # alias
def system_check_file(req: CheckFile) -> dict:
    """对单个文件做完整评分 + 自动隔离（fsmon 检查同款接口）。"""
    from src.guardian.quarantine.manager import check_and_quarantine
    return check_and_quarantine(req.path, source_dir=req.source_dir)


@router.get("/system/fsmon/status")
def system_fsmon_status() -> dict:
    from src.guardian.quarantine import fsmon
    info = fsmon.status()
    info["config"] = {
        "watch_dirs_count": len(getattr(fsmon, "FSMON_WATCH_DIRS", [])),
        "watch_dirs": [d for d in getattr(fsmon, "FSMON_WATCH_DIRS", []) if d],
        "workers": getattr(fsmon, "FSMON_WORKER_THREADS", None),
        "threshold": __import__("src.guardian.core.config", fromlist=["QUARANTINE_SCORE_THRESHOLD"]).QUARANTINE_SCORE_THRESHOLD,
        "keep_original": __import__("src.guardian.core.config", fromlist=["QUARANTINE_KEEPORIGINAL"]).QUARANTINE_KEEPORIGINAL,
    }
    return info


@router.post("/system/fsmon/feed")
def system_fsmon_feed(req: CheckFile) -> dict:
    """手动喂一个文件路径给 fsmon 处理（测试 / 扩展使用）。"""
    from src.guardian.quarantine import fsmon
    return fsmon.feed(req.path)


# ---- 告警历史（P2-2：可视化页）----

class UrlBlockReport(BaseModel):
    url: str = Field(..., min_length=1, max_length=4096)
    rule: str = Field("", max_length=64)
    threat_score: int = 0
    layers: str = Field("", max_length=64)
    evidence: list = Field(default_factory=list)
    tab_id: int = 0


@router.post("/alerts/url_block")
def alerts_url_block(req: UrlBlockReport) -> dict:
    """Edge 扩展上报 URL 拦截事件（P2-2）。"""
    try:
        aid = db.push_url_block(req.model_dump())
    except Exception as e:
        logger.error(f"push_url_block failed: {e}")
        raise HTTPException(500, f"db error: {e}")
    return {"ok": True, "id": aid}


# 时间桶映射：since 参数 -> 距今秒数
_SINCE_SECONDS = {
    "1h": 3600,
    "24h": 24 * 3600,
    "7d": 7 * 24 * 3600,
    "30d": 30 * 24 * 3600,
    "all": 0,
}


def _since_ts(since: str) -> int:
    if since not in _SINCE_SECONDS:
        raise HTTPException(400, f"invalid since={since}; use one of {list(_SINCE_SECONDS)}")
    sec = _SINCE_SECONDS[since]
    return int(time.time()) - sec if sec > 0 else 0


def _normalize_proc(p: dict) -> dict:
    return {
        "type": "proc",
        "ts": p["ts"],
        "rule": ",".join(p.get("rules") or []) or "wmi",
        "name": p.get("name") or "",
        "path": p.get("path") or "",
        "pid": p.get("pid") or 0,
        "parent_name": p.get("parent_name") or "",
        "evidence": p.get("evidence") or [],
    }


def _normalize_quar(q: dict) -> dict:
    return {
        "type": "quarantine",
        "ts": q["quarantined_at"],
        "rule": q.get("reason") or "",
        "path": q.get("original_path") or "",
        "sha256": q.get("sha256") or "",
        "threat_score": q.get("threat_score") or 0,
        "source_dir": q.get("source_dir") or "",
        "signature_status": q.get("signature_status") or "unknown",
    }


def _normalize_url(u: dict) -> dict:
    return {
        "type": "url",
        "ts": u["blocked_at"],
        "rule": u.get("rule") or "",
        "url": u.get("url") or "",
        "threat_score": u.get("threat_score") or 0,
        "layers": u.get("layers") or "",
        "evidence": u.get("evidence") or [],
    }


@router.get("/alerts/history")
def alerts_history(
    type: Literal["all", "url", "proc", "quarantine"] = "all",
    since: str = "24h",
    limit: int = Query(100, ge=1, le=500),
) -> dict:
    """拉取告警历史（合并 URL / 进程 / 文件 三类，按时间倒序）。"""
    since_ts = _since_ts(since)
    items: list[dict] = []

    if type in ("all", "url"):
        items.extend(_normalize_url(u) for u in db.list_url_blocks(since_ts, limit))
    if type in ("all", "proc"):
        items.extend(_normalize_proc(p) for p in db.list_proc_alerts(limit))
    if type in ("all", "quarantine"):
        # quarantine_list 已经按时间倒序
        for q in db.quarantine_list():
            if q["quarantined_at"] >= since_ts:
                items.append(_normalize_quar(q))

    # 按时间倒序；同时间稳定
    items.sort(key=lambda x: x["ts"], reverse=True)
    return {"count": len(items), "items": items[:limit]}


@router.get("/alerts/summary")
def alerts_summary(since: str = "24h") -> dict:
    """告警摘要：按类型计数 + 按规则 top N。"""
    since_ts = _since_ts(since)
    now = int(time.time())

    # 各类型计数
    url_count = db.url_blocks_count(since_ts)
    proc_total = len(db.list_proc_alerts(limit=1000))
    proc_count = sum(1 for _ in _iter_proc_since(since_ts))
    quar_total = db.quarantine_list()  # 时间倒序
    quar_count = sum(1 for q in quar_total if q["quarantined_at"] >= since_ts)

    # URL top rules
    url_top = db.url_blocks_top_rules(since_ts, limit=5)

    # proc top rules
    proc_top = _top_rules_by_proc(since_ts, limit=5)

    # quarantine top reasons
    quar_top = _top_reasons_by_quar(since_ts, limit=5)

    return {
        "since": since,
        "since_ts": since_ts,
        "now": now,
        "total": url_count + proc_count + quar_count,
        "by_type": {
            "url": url_count,
            "proc": proc_count,
            "quarantine": quar_count,
        },
        "top_rules": {
            "url": [{"rule": r, "count": c} for r, c in url_top],
            "proc": proc_top,
            "quarantine": quar_top,
        },
    }


def _iter_proc_since(since_ts: int):
    """yield 进程告警（过滤 since）。proc_alerts 表按 id DESC 顺序遍历。"""
    for p in db.list_proc_alerts(limit=1000):
        if p["ts"] >= since_ts:
            yield p


def _top_rules_by_proc(since_ts: int, limit: int = 5) -> list[dict]:
    """按 rules 聚合进程告警。"""
    counts: dict[str, int] = {}
    for p in _iter_proc_since(since_ts):
        rules = p.get("rules") or []
        if not rules:
            counts["wmi"] = counts.get("wmi", 0) + 1
            continue
        for r in rules:
            counts[r] = counts.get(r, 0) + 1
    items = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:limit]
    return [{"rule": r, "count": c} for r, c in items]


def _top_reasons_by_quar(since_ts: int, limit: int = 5) -> list[dict]:
    counts: dict[str, int] = {}
    for q in db.quarantine_list():
        if q["quarantined_at"] < since_ts:
            continue
        # reason 可能是 "rule1; rule2; rule3" 拼接，取第一个作为归类
        reason = (q.get("reason") or "unknown").split(";")[0].strip()
        counts[reason] = counts.get(reason, 0) + 1
    items = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:limit]
    return [{"rule": r, "count": c} for r, c in items]
