"""隔离区管理（P2-1：文件监控自动隔离）。

原 P1：手动 quarantine()/restore()/list()/delete_forever()
P2-1 新增：
- check_and_quarantine(path, source_dir)  —— 评分 + 阈值 + 移动到隔离区
- _sha256_of(path)        —— 大文件只读头尾
- _move_to_quarantine()    —— 按 KEEP_ORIGINAL 决定复制还是移走
"""

from __future__ import annotations

import hashlib
import shutil
import time
from pathlib import Path

from src.guardian.core.config import (
    FSMONHASH_HEAD_TAIL_KB,
    FSMON_MAX_HASH_SIZE_MB,
    QUARANTINE_AUTO_CLEAN_DAYS,
    QUARANTINE_DIR,
    QUARANTINE_KEEPORIGINAL,
    QUARANTINE_SCORE_THRESHOLD,
)
from src.guardian.core.db import db
from src.guardian.core.logger import logger
from src.guardian.intel.aggregator import check_hash, evaluate_file_heuristic
from src.guardian.quarantine.signature import has_signature


def _sha256(path: Path) -> str:
    """计算文件的 SHA-256。

    对小文件读全文；>FSMON_MAX_HASH_SIZE_MB 时只读头尾各 FSMONHASH_HEAD_TAIL_KB KB，
    保证恶意软件特征被覆盖的同时节省 IO（绝大多数 Windows PE 特征在文件头/尾部）。
    """
    try:
        size = path.stat().st_size
    except OSError:
        return ""
    head_tail = FSMONHASH_HEAD_TAIL_KB * 1024
    if size <= FSMON_MAX_HASH_SIZE_MB * 1024 * 1024:
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError as e:
            logger.error(f"sha256 read failed for {path}: {e}")
            return ""
        return hashlib.sha256(data).hexdigest()

    # 大文件：只算 head+tail（够 AV 签名匹配用，恶意软件特征聚集在 PE 头/尾部）
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            head = f.read(head_tail)
            h.update(head)
            f.seek(max(0, size - head_tail))
            tail = f.read(head_tail)
            h.update(tail)
    except OSError as e:
        logger.error(f"sha256 (head/tail) failed for {path}: {e}")
        return ""
    return h.hexdigest()


def quarantine(src_path: str, reason: str) -> int | None:
    """把文件移到隔离区（P1 接口保留）。"""
    p = Path(src_path)
    if not p.exists():
        logger.error(f"quarantine source not found: {src_path}")
        return None

    sha = _sha256(p)
    if not sha:
        return None
    size = _safe_size(p)
    return _do_move(p, sha, reason, size, source_dir="", threat_score=0, signature_status="unknown")


def _safe_size(p: Path) -> int:
    try:
        return p.stat().st_size
    except OSError:
        return 0


def _do_move(
    p: Path,
    sha: str,
    reason: str,
    size: int,
    source_dir: str,
    threat_score: int,
    signature_status: str,
) -> int | None:
    timestamp = int(time.time())
    target_name = f"{timestamp}_{sha[:16]}_{p.name}"
    target_path = QUARANTINE_DIR / target_name

    if QUARANTINE_KEEPORIGINAL:
        try:
            shutil.copy2(p, target_path)
        except OSError as e:
            logger.error(f"quarantine copy failed: {e}")
            return None
    else:
        try:
            shutil.move(str(p), target_path)
        except OSError as e:
            logger.error(f"quarantine move failed: {e}")
            return None

    quar_id = db.quarantine_add(
        str(p.resolve()),
        sha,
        reason,
        size,
        source_dir=source_dir,
        threat_score=threat_score,
        signature_status=signature_status,
    )
    logger.warning(
        f"QUARANTINED: {p} -> {target_path} score={threat_score} reason={reason}"
    )
    return quar_id


def check_and_quarantine(
    src_path: str,
    source_dir: str = "",
    *,
    force: bool = False,
) -> dict:
    """对单个文件做完整评分，达到阈值则自动隔离，返回完整决策结果。

    返回结构：
      - action: 'quarantined' | 'skipped' | 'failed'
      - quar_id: int | None
      - threat_score, sha256, evidence, malicious
    """
    p = Path(src_path)
    result = {
        "action": "skipped",
        "quar_id": None,
        "threat_score": 0,
        "sha256": None,
        "evidence": [],
        "malicious": False,
        "path": str(p),
    }

    if not p.exists() or not p.is_file():
        result["action"] = "failed"
        result["reason"] = "file not found"
        return result

    sha = _sha256(p)
    if not sha:
        result["action"] = "failed"
        result["reason"] = "sha256 read failed"
        return result

    result["sha256"] = sha

    # 启发式评分（cheap, sync）
    heur = evaluate_file_heuristic(str(p), source_dir)
    result["evidence"] = heur.get("evidence", [])

    # 签名状态（辅助 evidence，不计分）
    sig = has_signature(str(p))
    sig_status = (
        "signed" if sig is True else ("unsigned" if sig is False else "unknown")
    )
    if sig is False:
        result["evidence"].append({
            "rule": "no_signature",
            "detail": "可执行但无数字签名",
            "score": 0,  # evaluate_file_heuristic 已加，这里仅记录
        })

    # 评分聚合（含云查，已并行）
    intel = check_hash(sha, file_path=str(p), source_dir=source_dir, use_cache=True)
    result["threat_score"] = intel.get("_threat_score", 0)
    result["malicious"] = intel.get("malicious", False)
    # 合并 evidence: intel 可能带 cloud 项；heur 已展开在 result.evidence
    for ev in intel.get("evidence", []):
        if ev not in result["evidence"]:
            result["evidence"].append(ev)

    if force or result["threat_score"] >= QUARANTINE_SCORE_THRESHOLD:
        size = _safe_size(p)
        # 构造 reason 摘要
        rules = sorted({ev["rule"] for ev in result["evidence"]})
        reason = "; ".join(rules) if rules else f"score={result['threat_score']}"
        quar_id = _do_move(
            p,
            sha,
            reason,
            size,
            source_dir=source_dir,
            threat_score=result["threat_score"],
            signature_status=sig_status,
        )
        result["action"] = "quarantined" if quar_id else "failed"
        result["quar_id"] = quar_id
        return result

    result["action"] = "skipped"
    return result


# -------------------- 兼容旧 API --------------------

def list_all() -> list[dict]:
    return db.quarantine_list()


def restore(quar_id: int) -> tuple[bool, str]:
    rec = db.quarantine_remove(quar_id)
    if rec is None:
        return (False, "记录不存在")
    original_path, sha = rec
    target = Path(original_path)
    if not target.parent.exists():
        return (False, f"原目录不存在: {target.parent}")
    matches = list(QUARANTINE_DIR.glob(f"*_{sha[:16]}_*"))
    if not matches:
        return (False, f"隔离区副本不存在: sha={sha[:16]}")
    try:
        # 开发期安全：把隔离区副本复制回去，不删隔离区
        # 前缀 restored- 避免覆盖现有文件
        restore_target = target.parent / f"restored-{target.name}"
        shutil.copy2(matches[0], restore_target)
        return (True, f"已恢复到 {restore_target}")
    except OSError as e:
        return (False, f"恢复失败: {e}")


def delete_forever(quar_id: int) -> tuple[bool, str]:
    rec = db.quarantine_remove(quar_id)
    if rec is None:
        return (False, "记录不存在")
    _, sha = rec
    matches = list(QUARANTINE_DIR.glob(f"*_{sha[:16]}_*"))
    for m in matches:
        try:
            m.unlink()
        except OSError as e:
            logger.warning(f"quarantine delete failed: {m}: {e}")
    return (True, "已彻底删除")


def auto_clean(days: int = QUARANTINE_AUTO_CLEAN_DAYS) -> int:
    cutoff = int(time.time()) - days * 86400
    items = db.quarantine_list()
    cleaned = 0
    for it in items:
        if it["quarantined_at"] < cutoff:
            delete_forever(it["id"])
            cleaned += 1
    if cleaned:
        logger.info(f"auto_clean: removed {cleaned} quarantine entries older than {days} days")
    return cleaned
