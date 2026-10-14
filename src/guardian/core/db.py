"""SQLite 缓存层（WAL 模式）。

- 文件哈希查询：永久缓存
- URL 查询：缓存 24 小时
- 队列 + 去重：相同哈希或 URL 自动合并
"""

from __future__ import annotations

import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from src.guardian.core.config import DB_DIR, INTEL_CACHE_TTL_HOURS
from src.guardian.core.logger import logger

DB_PATH = DB_DIR / "guardian.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS url_cache (
    url TEXT PRIMARY KEY,
    result_json TEXT NOT NULL,
    threat_score INTEGER NOT NULL DEFAULT 0,
    cached_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_url_expires ON url_cache(expires_at);

CREATE TABLE IF NOT EXISTS hash_cache (
    sha256 TEXT PRIMARY KEY,
    result_json TEXT NOT NULL,
    threat_score INTEGER NOT NULL DEFAULT 0,
    cached_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS user_whitelist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern TEXT NOT NULL UNIQUE,
    added_at INTEGER NOT NULL,
    hit_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS quarantine (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    quarantined_at INTEGER NOT NULL,
    reason TEXT NOT NULL,
    file_size INTEGER NOT NULL DEFAULT 0,
    source_dir TEXT NOT NULL DEFAULT '',
    threat_score INTEGER NOT NULL DEFAULT 0,
    signature_status TEXT NOT NULL DEFAULT 'unknown'
);
CREATE INDEX IF NOT EXISTS idx_quar_sha ON quarantine(sha256);

CREATE TABLE IF NOT EXISTS request_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,    -- 'url' or 'hash'
    target TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 5,
    enqueued_at INTEGER NOT NULL,
    UNIQUE(kind, target)
);

CREATE TABLE IF NOT EXISTS proc_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    pid INTEGER NOT NULL,
    name TEXT NOT NULL,
    path TEXT NOT NULL DEFAULT '',
    cmdline TEXT NOT NULL DEFAULT '',
    ppid INTEGER NOT NULL DEFAULT 0,
    parent_name TEXT NOT NULL DEFAULT '',
    rules TEXT NOT NULL DEFAULT '',
    evidence TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_proc_ts ON proc_alerts(ts DESC);

CREATE TABLE IF NOT EXISTS domain_blocklist (
    domain TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class CacheDB:
    """线程安全的 SQLite 包装。WAL 模式允许多读单写。"""

    def __init__(self, path: Path = DB_PATH) -> None:
        self._path = path
        self._lock = threading.RLock()
        self._init_schema()

    @contextmanager
    def _conn(self):
        c = sqlite3.connect(str(self._path), timeout=5.0, isolation_level=None)
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        c.execute("PRAGMA temp_store=MEMORY")
        c.execute("PRAGMA cache_size=-4096")  # 4 MB 缓存上限（保护内存指标）
        try:
            yield c
        finally:
            c.close()

    def _init_schema(self) -> None:
        with self._lock, self._conn() as c:
            c.executescript(_SCHEMA)
            # 兼容老库：补齐 quarantine 表的可选列（无则 ALTER TABLE）
            cur = c.execute("PRAGMA table_info(quarantine)")
            cols = {r[1] for r in cur.fetchall()}
            if "source_dir" not in cols:
                c.execute("ALTER TABLE quarantine ADD COLUMN source_dir TEXT NOT NULL DEFAULT ''")
            if "threat_score" not in cols:
                c.execute("ALTER TABLE quarantine ADD COLUMN threat_score INTEGER NOT NULL DEFAULT 0")
            if "signature_status" not in cols:
                c.execute("ALTER TABLE quarantine ADD COLUMN signature_status TEXT NOT NULL DEFAULT 'unknown'")
            logger.debug(f"CacheDB schema initialized at {self._path}")

    # ---- URL cache ----

    def get_url(self, url: str) -> dict | None:
        now = int(time.time())
        with self._lock, self._conn() as c:
            row = c.execute(
                "SELECT result_json, threat_score FROM url_cache WHERE url=? AND expires_at>?",
                (url, now),
            ).fetchone()
            if row:
                import json
                return {"result": json.loads(row[0]), "threat_score": row[1]}
        return None

    def put_url(self, url: str, result: dict, threat_score: int) -> None:
        import json
        now = int(time.time())
        expires = now + INTEL_CACHE_TTL_HOURS * 3600
        with self._lock, self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO url_cache(url, result_json, threat_score, cached_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (url, json.dumps(result, ensure_ascii=False), threat_score, now, expires),
            )
            logger.debug(f"url_cache PUT url={url[:80]} score={threat_score}")

    # ---- hash cache ----

    def get_hash(self, sha256: str) -> dict | None:
        with self._lock, self._conn() as c:
            row = c.execute(
                "SELECT result_json, threat_score FROM hash_cache WHERE sha256=?",
                (sha256,),
            ).fetchone()
            if row:
                import json
                return {"result": json.loads(row[0]), "threat_score": row[1]}
        return None

    def put_hash(self, sha256: str, result: dict, threat_score: int) -> None:
        import json
        now = int(time.time())
        with self._lock, self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO hash_cache(sha256, result_json, threat_score, cached_at) "
                "VALUES (?, ?, ?, ?)",
                (sha256, json.dumps(result, ensure_ascii=False), threat_score, now),
            )
            logger.debug(f"hash_cache PUT sha={sha256[:16]} score={threat_score}")

    # ---- queue ----

    def enqueue(self, kind: str, target: str, priority: int = 5) -> bool:
        """返回 True 表示新入队，False 表示已存在（去重）。"""
        now = int(time.time())
        with self._lock, self._conn() as c:
            cur = c.execute(
                "INSERT OR IGNORE INTO request_queue(kind, target, priority, enqueued_at) "
                "VALUES (?, ?, ?, ?)",
                (kind, target, priority, now),
            )
            return cur.rowcount > 0

    def dequeue(self) -> tuple[str, str, int] | None:
        """取出队首（高优先级优先）。"""
        with self._lock, self._conn() as c:
            row = c.execute(
                "SELECT id, kind, target FROM request_queue "
                "ORDER BY priority ASC, enqueued_at ASC LIMIT 1",
            ).fetchone()
            if row:
                c.execute("DELETE FROM request_queue WHERE id=?", (row[0],))
                return (row[1], row[2], row[0])
        return None

    def queue_size(self) -> int:
        with self._lock, self._conn() as c:
            return c.execute("SELECT COUNT(*) FROM request_queue").fetchone()[0]

    # ---- whitelist ----

    def whitelist_add(self, pattern: str) -> bool:
        now = int(time.time())
        with self._lock, self._conn() as c:
            cur = c.execute(
                "INSERT OR IGNORE INTO user_whitelist(pattern, added_at) VALUES (?, ?)",
                (pattern, now),
            )
            return cur.rowcount > 0

    def whitelist_match(self, url: str) -> str | None:
        with self._lock, self._conn() as c:
            rows = c.execute("SELECT pattern FROM user_whitelist").fetchall()
        url_l = url.lower()
        for (pat,) in rows:
            if url_l.startswith(pat.lower()):
                return pat
        return None

    def whitelist_list(self) -> list[dict]:
        with self._lock, self._conn() as c:
            rows = c.execute(
                "SELECT id, pattern, added_at, hit_count FROM user_whitelist ORDER BY added_at DESC"
            ).fetchall()
        return [{"id": r[0], "pattern": r[1], "added_at": r[2], "hit_count": r[3]} for r in rows]

    def whitelist_remove(self, pattern: str) -> bool:
        with self._lock, self._conn() as c:
            cur = c.execute("DELETE FROM user_whitelist WHERE pattern=?", (pattern,))
            return cur.rowcount > 0

    # ---- quarantine ----

    def quarantine_add(
        self,
        original_path: str,
        sha256: str,
        reason: str,
        file_size: int,
        source_dir: str = "",
        threat_score: int = 0,
        signature_status: str = "unknown",
    ) -> int:
        now = int(time.time())
        with self._lock, self._conn() as c:
            cur = c.execute(
                "INSERT INTO quarantine(original_path, sha256, quarantined_at, reason, file_size, "
                "source_dir, threat_score, signature_status) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (original_path, sha256, now, reason, file_size,
                 source_dir, threat_score, signature_status),
            )
            return cur.lastrowid

    def quarantine_list(self) -> list[dict]:
        with self._lock, self._conn() as c:
            rows = c.execute(
                "SELECT id, original_path, sha256, quarantined_at, reason, file_size, "
                "source_dir, threat_score, signature_status "
                "FROM quarantine ORDER BY quarantined_at DESC"
            ).fetchall()
        return [
            {"id": r[0], "original_path": r[1], "sha256": r[2],
             "quarantined_at": r[3], "reason": r[4], "file_size": r[5],
             "source_dir": r[6] or "", "threat_score": r[7] or 0,
             "signature_status": r[8] or "unknown"}
            for r in rows
        ]

    def quarantine_remove(self, quar_id: int) -> tuple[str, str] | None:
        """返回 (original_path, sha256) 用于恢复。"""
        with self._lock, self._conn() as c:
            row = c.execute(
                "SELECT original_path, sha256 FROM quarantine WHERE id=?", (quar_id,)
            ).fetchone()
            if row:
                c.execute("DELETE FROM quarantine WHERE id=?", (quar_id,))
                return (row[0], row[1])
        return None

    # ---- proc_alerts ----

    def push_proc_alert(self, alert: dict) -> int:
        import json
        ts = int(time.time())
        with self._lock, self._conn() as c:
            cur = c.execute(
                "INSERT INTO proc_alerts(ts, pid, name, path, cmdline, ppid, parent_name, rules, evidence) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    ts,
                    int(alert.get("pid") or 0),
                    alert.get("name") or "",
                    alert.get("path") or "",
                    alert.get("cmdline") or "",
                    int(alert.get("ppid") or 0),
                    alert.get("parent_name") or "",
                    json.dumps(alert.get("rules") or [], ensure_ascii=False),
                    json.dumps(alert.get("evidence") or [], ensure_ascii=False),
                ),
            )
            # 软上限：保留最近 1000 条，避免内存/磁盘无限制增长
            c.execute(
                "DELETE FROM proc_alerts WHERE id NOT IN "
                "(SELECT id FROM proc_alerts ORDER BY id DESC LIMIT 1000)"
            )
            return cur.lastrowid

    def list_proc_alerts(self, limit: int = 50) -> list[dict]:
        import json
        with self._lock, self._conn() as c:
            rows = c.execute(
                "SELECT id, ts, pid, name, path, cmdline, ppid, parent_name, rules, evidence "
                "FROM proc_alerts ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        out = []
        for r in rows:
            try:
                rules = json.loads(r[8]) if r[8] else []
            except Exception:
                rules = []
            try:
                evidence = json.loads(r[9]) if r[9] else []
            except Exception:
                evidence = []
            out.append({
                "id": r[0], "ts": r[1], "pid": r[2], "name": r[3],
                "path": r[4], "cmdline": r[5], "ppid": r[6], "parent_name": r[7],
                "rules": rules, "evidence": evidence,
            })
        return out

    # ---- 本地域名黑名单（Phishing Army）----

    def replace_domain_blocklist(self, domains: list[str]) -> int:
        """整表替换（单事务，快速）。返回写入条数。"""
        rows = [(d,) for d in domains]
        with self._lock, self._conn() as c:
            c.execute("BEGIN")
            c.execute("DELETE FROM domain_blocklist")
            c.executemany("INSERT OR IGNORE INTO domain_blocklist(domain) VALUES (?)", rows)
            c.execute("COMMIT")
        return len(rows)

    def is_blocked_domain(self, host: str) -> str | None:
        """命中返回被匹配的域名（含父域回溯），未命中返回 None。"""
        host = (host or "").lower().strip(".")
        if not host:
            return None
        labels = host.split(".")
        # 从完整域名逐级回退到注册域（最多 6 级，够用且快）
        candidates = []
        for i in range(len(labels)):
            if len(labels) - i < 2:
                break
            candidates.append(".".join(labels[i:]))
            if len(candidates) >= 6:
                break
        if not candidates:
            return None
        placeholders = ",".join("?" * len(candidates))
        with self._lock, self._conn() as c:
            rows = c.execute(
                f"SELECT domain FROM domain_blocklist WHERE domain IN ({placeholders}) LIMIT 1",
                candidates,
            ).fetchone()
        return rows[0] if rows else None

    def domain_blocklist_count(self) -> int:
        with self._lock, self._conn() as c:
            return c.execute("SELECT COUNT(*) FROM domain_blocklist").fetchone()[0]

    # ---- meta（键值存储）----

    def meta_get(self, key: str) -> str | None:
        with self._lock, self._conn() as c:
            row = c.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    def meta_set(self, key: str, value: str) -> None:
        with self._lock, self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", (key, str(value))
            )


class _LazyDB:
    """延迟初始化的全局 DB 实例，避免 import 时即触发 IO。"""

    def __init__(self) -> None:
        self._instance: CacheDB | None = None

    def _get(self) -> CacheDB:
        if self._instance is None:
            self._instance = CacheDB()
        return self._instance

    def __getattr__(self, name: str):
        return getattr(self._get(), name)


db = _LazyDB()
