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
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
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
