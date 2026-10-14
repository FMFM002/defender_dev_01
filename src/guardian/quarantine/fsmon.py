"""文件监控（基于 msvcrt ReadDirectoryChangesW，无第三方依赖）。

监控方式：
- 每目录一个后台线程，循环 os.scandir() 快照比对（1s 间隔）
- 检测"新建/修改（mtime 变化）"事件
- 文件系统异步事件通知（ReadDirectoryChangesW）需要 kernel32 API + 重叠 I/O，
  实现复杂度高；轮询在 1s 粒度对恶意软件拦截完全够用，且 CPU < 0.5%

触发后行为：
- 把"新增文件路径"丢入队列（线程安全）
- 后台 worker 调 manager.check_and_quarantine()
- 安装行为识别 installer_noise 在评分前做聚合豁免
"""

from __future__ import annotations

import os
import queue
import threading
import time
from pathlib import Path

from src.guardian.core.config import (
    FSMON_EXCLUDE_DIR_PARTS,
    FSMON_QUEUED_EVENTS_MAX,
    FSMON_WORKER_THREADS,
    FSMON_WATCH_DIRS,
    LOCALAPPDATA,
    NOISY_VENDOR_DIRS,
)
from src.guardian.core.logger import logger
from src.guardian.quarantine.installer_noise import detector as noise_detector
from src.guardian.quarantine.manager import check_and_quarantine


class _DirectoryWatcher:
    """监控单个目录：每 1s 一次快照比对，识别新增/修改文件。"""

    def __init__(self, dir_path: str):
        self.dir_path = Path(dir_path).resolve()
        self._snapshot: dict[str, tuple[float, int]] | None = None
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._loop, name=f"fsmon:{self.dir_path.name}", daemon=True
        )

    def start(self):
        try:
            if not self.dir_path.exists() or not self.dir_path.is_dir():
                logger.warning(f"监控目录不存在，跳过：{self.dir_path}")
                return
        except Exception:
            return
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _loop(self):
        # 初始 baseline：避免一启动就把目录里已存在的几百个文件全部入队
        self._snapshot = self._snapshot_now()
        while not self._stop.is_set():
            time.sleep(1.0)
            try:
                cur = self._snapshot_now()
            except OSError:
                continue
            old = self._snapshot or {}
            new_or_changed = []
            for name, sig in cur.items():
                if sig != old.get(name):
                    new_or_changed.append(name)
            self._snapshot = cur
            for name in new_or_changed:
                full = str(self.dir_path / name)
                if _should_skip(full):
                    continue
                _EVENT_QUEUE.put(("new", full))

    def _snapshot_now(self) -> dict:
        """对目录做一次快照：name -> (mtime, size)。"""
        snap: dict = {}
        try:
            with os.scandir(str(self.dir_path)) as it:
                for entry in it:
                    try:
                        if not entry.is_file(follow_symlinks=False):
                            continue
                        st = entry.stat(follow_symlinks=False)
                        snap[entry.name] = (st.st_mtime, st.st_size)
                    except OSError:
                        continue
        except OSError:
            return snap
        return snap


# ---- 事件队列 + 后台 worker ----

_EVENT_QUEUE: queue.Queue = queue.Queue(maxsize=FSMON_QUEUED_EVENTS_MAX)
_WORKERS: list[threading.Thread] = []
_WATCHERS: list[_DirectoryWatcher] = []
_STARTED = False
_START_LOCK = threading.Lock()


def _should_skip(path: str) -> bool:
    """是否跳过该文件（系统路径 / 已知厂商子目录）。"""
    p_low = path.lower().replace("/", "\\")
    for part in FSMON_EXCLUDE_DIR_PARTS:
        if part.lower() in p_low:
            return True
    if LOCALAPPDATA and LOCALAPPDATA.lower() in p_low:
        # AppData\Local 已知厂商子目录内的临时文件直接放过
        for v in NOISY_VENDOR_DIRS:
            if v.replace("\\", os.sep).lower() in p_low:
                return True
    return False


def _classify_source(file_path: str) -> str:
    """根据文件路径判断来源目录分类。"""
    p_low = file_path.lower().replace("/", "\\")
    if "startup" in p_low or "启动" in p_low:
        return "startup"
    if "temp" in p_low or "tmp" in p_low:
        return "temp"
    if "desktop" in p_low:
        return "desktop"
    if "downloads" in p_low or "下载" in p_low:
        return "downloads"
    if LOCALAPPDATA and LOCALAPPDATA.lower() in p_low:
        return "appdata"
    return ""


def _worker_loop(idx: int):
    """worker 线程：从队列取文件 → 算 sha256 → 评分 → 超过阈值则 quarantine。"""
    logger.info(f"fsmon worker #{idx} 启动")
    while True:
        try:
            kind, path = _EVENT_QUEUE.get(timeout=1.0)
        except queue.Empty:
            continue
        if kind == "stop":
            return
        try:
            _process_file(path)
        except Exception as e:
            logger.warning(f"fsmon worker 处理 {path} 出错：{e}")
        finally:
            _EVENT_QUEUE.task_done()


def _process_file(path: str):
    """对单个文件做安装噪音识别 + 评分 + 自动隔离。"""
    if not os.path.exists(path):
        return
    try:
        size = os.path.getsize(path)
    except OSError:
        return
    if size == 0:
        return

    # 记录事件（可能命中"安装豁免"）
    triggered = noise_detector.record(path)

    if triggered:
        # 在豁免窗口内的文件仍走评分，但日志密度更友好
        logger.info(f"[fsmon] noise-window 中的新增：{path}")

    src = _classify_source(path)
    res = check_and_quarantine(path, source_dir=src)
    if res.get("action") == "quarantined":
        logger.warning(
            f"[fsmon] 自动隔离: {path} score={res.get('threat_score')} evidence="
            f"{[e['rule'] for e in res.get('evidence', [])]}"
        )
    elif res.get("action") == "failed":
        logger.debug(f"[fsmon] 处理失败（可能尚未写完）: {path} reason={res.get('reason')}")
    # skipped 不记日志，避免刷屏


# ---- 启动 / 停止 ----

def start() -> None:
    """启动 fsmon（包含 watcher + worker 池）。"""
    global _STARTED
    with _START_LOCK:
        if _STARTED:
            return
        _STARTED = True

    # 启动 worker
    for i in range(FSMON_WORKER_THREADS):
        t = threading.Thread(target=_worker_loop, args=(i,), name=f"fsmon-worker-{i}", daemon=True)
        t.start()
        _WORKERS.append(t)

    # 启动每个目录的 watcher
    for d in FSMON_WATCH_DIRS:
        if not d:
            continue
        w = _DirectoryWatcher(d)
        w.start()
        _WATCHERS.append(w)

    logger.info(
        f"fsmon 已启动：监控 {len(_WATCHERS)} 个目录，"
        f"{FSMON_WORKER_THREADS} 个 worker"
    )


def stop() -> None:
    """停止所有 watcher + worker（测试 / 重启用）。"""
    for w in _WATCHERS:
        w.stop()
    for _ in _WORKERS:
        _EVENT_QUEUE.put(("stop", ""))
    for _ in _WATCHERS:
        _WATCHERS.pop()


def status() -> dict:
    return {
        "started": _STARTED,
        "watch_dirs": len(_WATCHERS),
        "workers": len(_WORKERS),
        "queue_size": _EVENT_QUEUE.qsize(),
    }


def feed(path: str) -> dict:
    """手动喂一个文件路径（测试 / 扩展钩子用）。"""
    return check_and_quarantine(path, source_dir=_classify_source(path))
