"""隔离区管理。

开发期：移到 data/quarantine/，原文件保留（避免误删），记录原始路径/SHA256/时间/原因。
30 天后自动清理隔离区文件。

提供接口：
- quarantine(path, reason) -> int (quar_id)
- list() -> list[dict]
- restore(quar_id) -> bool
- delete(quar_id) -> bool
- auto_clean(days=30) -> int (清理数量)
"""

from __future__ import annotations

import hashlib
import shutil
import time
from pathlib import Path

from src.guardian.core.config import QUARANTINE_AUTO_CLEAN_DAYS, QUARANTINE_DIR
from src.guardian.core.db import db
from src.guardian.core.logger import logger


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError as e:
        logger.error(f"sha256 read failed for {path}: {e}")
        return ""


def quarantine(src_path: str, reason: str) -> int | None:
    """把文件移到隔离区。开发期不删原文件，只复制。

    返回 quar_id；失败返回 None。
    """
    p = Path(src_path)
    if not p.exists():
        logger.error(f"quarantine source not found: {src_path}")
        return None

    sha = _sha256(p)
    if not sha:
        return None
    size = p.stat().st_size

    timestamp = int(time.time())
    target_name = f"{timestamp}_{sha[:16]}_{p.name}"
    target_path = QUARANTINE_DIR / target_name

    try:
        shutil.copy2(p, target_path)
    except OSError as e:
        logger.error(f"quarantine copy failed: {e}")
        return None

    quar_id = db.quarantine_add(str(p.resolve()), sha, reason, size)
    logger.warning(f"QUARANTINED: {p} -> {target_path} reason={reason}")
    return quar_id


def list_all() -> list[dict]:
    return db.quarantine_list()


def restore(quar_id: int) -> tuple[bool, str]:
    """恢复文件到原路径。

    开发期行为：把隔离区文件复制回原路径，不删隔离区副本（避免丢失）。
    返回 (success, message)。
    """
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
        shutil.copy2(matches[0], target)
        return (True, f"已恢复到 {target}")
    except OSError as e:
        return (False, f"恢复失败: {e}")


def delete_forever(quar_id: int) -> tuple[bool, str]:
    """彻底删除隔离区条目（含副本）。"""
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
    """清理 days 天前的隔离区条目。返回清理数量。"""
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
