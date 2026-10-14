"""USN Journal 全卷监控（P2-1 增强）。

为什么用 USN 而不是 ReadDirectoryChangesW 全卷？
- RDCW 需要为每个目录开句柄 + 重叠 I/O，C 盘几十万子目录会爆
- USN 单句柄监听整个 NTFS 卷（NTFS Change Journal 是 OS 内核自带的）
- 增量读 + 路径解析；事件流式、不扫主板

事件类型（reason）：
- USN_REASON_FILE_CREATE  (0x00000100) 文件/目录首次创建
- USN_REASON_RENAME_NEW_NAME (0x00002000) 重命名后的新名字

只关注"创建 + 重命名新名"，其它（写入、删除、关闭）忽略。

路径解析：
- USN 只给"文件名 + 父目录的 NTFS file reference"
- 维护 file_ref → 完整路径 的 LRU 缓存（启动时只有根已知）
- 父目录在缓存里 → 拼出路径；不在 → 跳过本次（后续增量补齐）

限制：
- 仅 NTFS 卷（FAT32/exFAT 不支持 USN）
- 单卷一个线程；卷根打开失败（如权限不足）降级为目录轮询
- USN Journal 不存在会先调 FSCTL_CREATE_USN_JOURNAL 创建
"""

from __future__ import annotations

import ctypes
import os
import threading
import time
from collections import OrderedDict
from ctypes import wintypes

from src.guardian.core.config import (
    FSMON_USN_BUFFER_KB,
    FSMON_USN_ENABLED,
    FSMON_USN_PATH_CACHE_MAX,
    FSMON_USN_POLL_INTERVAL_S,
    USN_REASON_MASK,
)
from src.guardian.core.logger import logger


# ---- Win32 常量 ----

GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

FSCTL_USN_TRACK_MODIFIED_RANGES = 0x00090000  # 暂未使用
FSCTL_QUERY_USN_JOURNAL = 0x00090094
FSCTL_READ_USN_JOURNAL = 0x000900E4
FSCTL_CREATE_USN_JOURNAL = 0x00090074

USN_REASON_FILE_CREATE = 0x00000100
USN_REASON_RENAME_NEW_NAME = 0x00002000

FILE_ATTRIBUTE_DIRECTORY = 0x00000010

ERROR_MORE_DATA = 234
ERROR_JOURNAL_ENTRY_DELETED = 1181
ERROR_HANDLE_EOF = 38


# ---- ctypes 结构 ----

class USN_RECORD_V2(ctypes.Structure):
    """USN record 头部（固定 64 字节），filename 在偏移 64 处变长。"""
    _fields_ = [
        ("RecordLength", ctypes.c_uint32),
        ("MajorVersion", ctypes.c_uint16),
        ("MinorVersion", ctypes.c_uint16),
        ("FileReferenceNumber", ctypes.c_uint64),
        ("ParentFileReferenceNumber", ctypes.c_uint64),
        ("Usn", ctypes.c_int64),
        ("TimeStamp", ctypes.c_int64),
        ("Reason", ctypes.c_uint32),
        ("SourceInfo", ctypes.c_uint32),
        ("SecurityId", ctypes.c_uint32),
        ("FileAttributes", ctypes.c_uint32),
        ("FileNameLength", ctypes.c_uint16),
        ("FileNameOffset", ctypes.c_uint16),
    ]


class READ_USN_JOURNAL_DATA(ctypes.Structure):
    _fields_ = [
        ("StartUsn", ctypes.c_int64),
        ("ReasonMask", ctypes.c_uint32),
        ("ReturnOnlyOnClose", ctypes.c_uint32),
        ("Timeout", ctypes.c_uint32),
        ("BytesToWaitFor", ctypes.c_uint64),
        ("UsnJournalID", ctypes.c_int64),
    ]


class USN_JOURNAL_DATA(ctypes.Structure):
    _fields_ = [
        ("UsnJournalID", ctypes.c_uint64),
        ("FirstUsn", ctypes.c_int64),
        ("NextUsn", ctypes.c_int64),
        ("LowestValidUsn", ctypes.c_int64),
        ("MaxUsn", ctypes.c_int64),
        ("MaximumSize", ctypes.c_uint64),
        ("AllocationDelta", ctypes.c_uint64),
    ]


# 头 8 字节是 next_usn（返回缓冲的前 8 字节）


# ---- 工具 ----

def _is_ntfs(drive_letter: str) -> bool:
    """检测卷是否为 NTFS（USN 只支持 NTFS）。"""
    root = f"{drive_letter}:\\"
    try:
        fs_name = ctypes.create_unicode_buffer(256)
        ret = ctypes.windll.kernel32.GetVolumeInformationW(
            root, None, 0, None, None, None, fs_name, 256
        )
        return bool(ret) and fs_name.value.upper().startswith("NTFS")
    except Exception:
        return False


def list_drives() -> list[str]:
    """返回系统所有固定盘符（A-Z）。"""
    try:
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    except Exception:
        return []
    out = []
    for i in range(26):
        if bitmask & (1 << i):
            out.append(chr(ord("A") + i))
    return out


def list_ntfs_volumes() -> list[str]:
    """返回所有 NTFS 卷的盘符。"""
    return [d for d in list_drives() if _is_ntfs(d)]


def _open_volume(drive_letter: str):
    """打开 NTFS 卷设备句柄。"""
    path = f"\\\\.\\{drive_letter}:"
    h = ctypes.windll.kernel32.CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None,
        OPEN_EXISTING,
        0,
        None,
    )
    if h == INVALID_HANDLE_VALUE or h == -1:
        err = ctypes.GetLastError()
        raise OSError(f"CreateFileW({path!r}) failed: err={err}")
    return h


def _query_usn_journal(h_volume):
    """查询卷的 USN Journal 元数据。"""
    journal = USN_JOURNAL_DATA()
    bytes_ret = wintypes.DWORD(0)
    ret = ctypes.windll.kernel32.DeviceIoControl(
        h_volume,
        FSCTL_QUERY_USN_JOURNAL,
        None, 0,
        ctypes.byref(journal), ctypes.sizeof(journal),
        ctypes.byref(bytes_ret),
        None,
    )
    if not ret:
        raise OSError(f"FSCTL_QUERY_USN_JOURNAL failed: err={ctypes.GetLastError()}")
    return journal


def _read_usn_records(h_volume, start_usn: int, reason_mask: int, journal_id: int,
                       buffer_size: int):
    """读一次增量记录。返回 (records, next_usn, has_more)。

    record: (file_ref:int, parent_ref:int, name:str, reason:int, is_dir:bool)
    """
    inp = READ_USN_JOURNAL_DATA()
    inp.StartUsn = start_usn
    inp.ReasonMask = reason_mask
    inp.ReturnOnlyOnClose = 0
    inp.Timeout = 0
    inp.BytesToWaitFor = 0
    inp.UsnJournalID = journal_id

    buf = ctypes.create_string_buffer(buffer_size)
    bytes_ret = wintypes.DWORD(0)
    ret = ctypes.windll.kernel32.DeviceIoControl(
        h_volume,
        FSCTL_READ_USN_JOURNAL,
        ctypes.byref(inp), ctypes.sizeof(inp),
        buf, buffer_size,
        ctypes.byref(bytes_ret),
        None,
    )

    if not ret:
        err = ctypes.GetLastError()
        if err == ERROR_HANDLE_EOF:
            return [], start_usn, False
        if err == ERROR_MORE_DATA:
            pass  # 部分数据可用，继续解析
        else:
            raise OSError(f"FSCTL_READ_USN_JOURNAL failed: err={err}")

    raw = bytes(buf[:bytes_ret.value])
    if len(raw) < 8:
        return [], start_usn, False

    next_usn = int.from_bytes(raw[:8], "little", signed=True)
    records = []
    offset = 8
    while offset + 64 <= len(raw):
        rec = USN_RECORD_V2.from_buffer_copy(raw, offset)
        rec_len = rec.RecordLength
        if rec_len < 64 or offset + rec_len > len(raw):
            break
        # 解析 filename（FileNameOffset 通常是 64）
        name_off = offset + rec.FileNameOffset
        name_end = name_off + rec.FileNameLength
        if name_end > len(raw):
            break
        try:
            name = raw[name_off:name_end].decode("utf-16-le", errors="replace")
        except Exception:
            name = ""
        is_dir = bool(rec.FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        records.append((
            rec.FileReferenceNumber,
            rec.ParentFileReferenceNumber,
            name,
            rec.Reason,
            is_dir,
        ))
        offset += rec_len

    has_more = bool(bytes_ret.value == buffer_size)  # 缓冲满 → 还有
    return records, next_usn, has_more


# ---- 单卷 watcher ----

class UsnWatcher:
    """单 NTFS 卷的 USN Journal 监听器。"""

    # NTFS 卷根目录的固定 file reference = 5
    NTFS_ROOT_FILE_REF = 5

    def __init__(self, drive_letter: str):
        self.drive = drive_letter.upper()
        self._h = None
        self._journal_id = 0
        self._next_usn = 0
        self._thread = None
        self._stop = threading.Event()
        self._cache: "OrderedDict[int, str]" = OrderedDict()
        self._cache_max = FSMON_USN_PATH_CACHE_MAX
        # stats
        self.stats = {
            "records_read": 0,
            "events_emitted": 0,
            "skipped_no_path": 0,
            "skipped_is_dir": 0,
            "skipped_exempt": 0,
            "errors": 0,
        }
        self.started = False

    def start(self) -> bool:
        """启动本卷的监听线程。失败返回 False。"""
        try:
            self._h = _open_volume(self.drive)
            journal = _query_usn_journal(self._h)
            self._journal_id = journal.UsnJournalID
            self._next_usn = journal.NextUsn
        except Exception as e:
            err = ctypes.GetLastError()
            hint = ""
            if err == 5:  # ERROR_ACCESS_DENIED
                hint = "（需要管理员权限或 SE_BACKUP_NAME）"
            logger.warning(f"USN[{self.drive}] 启动失败：{e}{hint}")
            return False

        # 根目录是 NTFS 固定 file_ref = 5
        self._cache[self.NTFS_ROOT_FILE_REF] = f"{self.drive}:\\"

        self._thread = threading.Thread(
            target=self._loop, name=f"usn:{self.drive}", daemon=True
        )
        self._thread.start()
        self.started = True
        logger.info(
            f"USN[{self.drive}] 启动：journal_id={self._journal_id} "
            f"next_usn={self._next_usn}"
        )
        return True

    def stop(self) -> None:
        self._stop.set()
        if self._h is not None:
            try:
                ctypes.windll.kernel32.CloseHandle(self._h)
            except Exception:
                pass
            self._h = None

    def _add_to_cache(self, file_ref: int, path: str) -> None:
        if len(self._cache) >= self._cache_max:
            self._cache.popitem(last=False)
        self._cache[file_ref] = path

    def _resolve_path(self, parent_ref: int, name: str) -> str | None:
        parent = self._cache.get(parent_ref)
        if parent is None:
            return None
        sep = "\\"
        return parent.rstrip("\\") + sep + name

    def _emit(self, file_path: str) -> None:
        """推送到 fsmon 事件队列。"""
        # 延迟 import 避免循环依赖
        try:
            from src.guardian.quarantine.fsmon import _EVENT_QUEUE
        except Exception as e:
            logger.error(f"USN[{self.drive}] 入队失败：{e}")
            return
        try:
            _EVENT_QUEUE.put_nowait(("new", file_path))
            self.stats["events_emitted"] += 1
        except Exception:
            # 队列满时丢弃，避免阻塞 USN 读取
            self.stats["skipped_no_path"] += 1

    def _handle_record(self, file_ref: int, parent_ref: int, name: str,
                        reason: int, is_dir: bool) -> None:
        self.stats["records_read"] += 1
        # 解析路径
        path = self._resolve_path(parent_ref, name)
        if path is None:
            self.stats["skipped_no_path"] += 1
            # 即便路径解析失败，仍把 parent/file_ref 占位记录，
            # 让后续兄弟能解析（虽然没拿到路径，但 cache 里 file_ref 还在）
            return

        # 缓存自身（无论是文件还是目录，都入缓存，方便后续子项解析）
        self._add_to_cache(file_ref, path)

        if is_dir:
            self.stats["skipped_is_dir"] += 1
            return

        # 是文件：发往评分队列
        # 白名单豁免（应用场景级）由 fsmon._process_file 统一处理
        self._emit(path)

    def _loop(self) -> None:
        logger.info(f"USN[{self.drive}] worker 启动")
        last_status_log = time.time()
        buffer_size = FSMON_USN_BUFFER_KB * 1024

        while not self._stop.is_set():
            try:
                records, next_usn, _has_more = _read_usn_records(
                    self._h, self._next_usn, USN_REASON_MASK, self._journal_id,
                    buffer_size,
                )
            except OSError as e:
                self.stats["errors"] += 1
                logger.warning(f"USN[{self.drive}] 读取错误：{e}")
                if self._stop.wait(2.0):
                    break
                continue
            except Exception as e:
                self.stats["errors"] += 1
                logger.error(f"USN[{self.drive}] 异常：{e}")
                if self._stop.wait(2.0):
                    break
                continue

            # 更新水位线
            if next_usn > self._next_usn:
                self._next_usn = next_usn

            if records:
                for rec in records:
                    self._handle_record(*rec)
            else:
                # 没有事件：按间隔睡眠
                if self._stop.wait(FSMON_USN_POLL_INTERVAL_S):
                    break

            # 定期输出状态
            now = time.time()
            if now - last_status_log > 60:
                last_status_log = now
                logger.debug(
                    f"USN[{self.drive}] status: read={self.stats['records_read']} "
                    f"emitted={self.stats['events_emitted']} "
                    f"no_path={self.stats['skipped_no_path']} "
                    f"cache={len(self._cache)}"
                )

    def status(self) -> dict:
        return {
            "drive": self.drive,
            "started": self.started,
            "alive": self._thread.is_alive() if self._thread else False,
            "next_usn": self._next_usn,
            "cache_size": len(self._cache),
            **self.stats,
        }


# ---- 启动 / 状态 ----

_WATCHERS: list[UsnWatcher] = []
_STARTED = False
_START_LOCK = threading.Lock()


def start_all() -> dict:
    """启动所有 NTFS 卷的 USN 监听。返回 {drive: ok|reason}。

    失败时返回失败原因，调用方自行降级为目录轮询。
    """
    if not FSMON_USN_ENABLED:
        return {"enabled": False}
    global _STARTED
    with _START_LOCK:
        if _STARTED:
            return {w.drive: True for w in _WATCHERS}
        _STARTED = True

    results: dict[str, object] = {"enabled": True, "drives": {}}
    for d in list_ntfs_volumes():
        w = UsnWatcher(d)
        ok = w.start()
        _WATCHERS.append(w)
        results["drives"][d] = "ok" if ok else "failed"
    return results


def stop_all() -> None:
    for w in _WATCHERS:
        w.stop()


def status() -> dict:
    if not FSMON_USN_ENABLED:
        return {"enabled": False}
    return {
        "enabled": True,
        "watchers": [w.status() for w in _WATCHERS],
        "ntfs_volumes": list_ntfs_volumes(),
    }