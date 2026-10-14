"""安装行为识别 —— 5 秒内同目录出现 >=3 个可执行后缀文件视为"安装噪声"。

聚合豁免窗口：
- 同一父目录
- 滑动窗口长度 = INSTALLER_NOISE_WINDOW_S (5s)
- 文件数 >= INSTALLER_NOISE_MIN_FILES (3)
- 仅"新增创建"事件计入（write_data = 0 但 FILE_ACTION_ADDED）

判断为安装行为后：
- 单文件仍走评分（不被豁免）
- 但日志记一条聚合摘要，不重复算散装 sha256（成本控制）
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

from src.guardian.core.config import INSTALLER_NOISE_MIN_FILES, INSTALLER_NOISE_WINDOW_S, SUSPICIOUSEXEC_EXTS
from src.guardian.core.logger import logger


class InstallerNoiseDetector:
    """每个监控目录一份实例，记录最近 N 秒内的"可疑后缀新增文件"事件。"""

    def __init__(self):
        self._lock = threading.Lock()
        self._events: dict[str, list[float]] = {}  # parent_dir -> [ts, ts, ...]

    def _maybe_noise(self, parent_dir: str) -> bool:
        """加入一次事件，返回 True 表示刚触发"安装豁免"。"""
        now = time.time()
        with self._lock:
            lst = self._events.setdefault(parent_dir.lower(), [])
            lst.append(now)
            cutoff = now - INSTALLER_NOISE_WINDOW_S
            while lst and lst[0] < cutoff:
                lst.pop(0)
            if len(lst) >= INSTALLER_NOISE_MIN_FILES:
                self._events[parent_dir.lower()] = lst[INSTALLER_NOISE_MIN_FILES:]
                return True
            return False

    def record(self, file_path: str) -> bool:
        """通知本文件是"新增事件"，返回是否进入安装豁免窗口。"""
        p = Path(file_path)
        ext = p.suffix.lower()
        if ext not in SUSPICIOUSEXEC_EXTS:
            return False
        triggered = self._maybe_noise(str(p.parent))
        if triggered:
            logger.info(
                f"[installer-noise] {p.parent} in {INSTALLER_NOISE_WINDOW_S}s 内"
                f"出现 >= {INSTALLER_NOISE_MIN_FILES} 个可执行后缀文件"
                f"（最后文件：{p.name}）；后续 N s 同目录新文件按需评估"
            )
        return triggered

    def is_in_noise_window(self, file_path: str) -> bool:
        """用于聚合豁免时，是否仍处于"安装噪声窗口"内（5s 内已有 >=3 个）。"""
        now = time.time()
        parent = str(Path(file_path).parent).lower()
        with self._lock:
            lst = self._events.get(parent, [])
            cutoff = now - INSTALLER_NOISE_WINDOW_S
            return sum(1 for t in lst if t >= cutoff) >= INSTALLER_NOISE_MIN_FILES


# 模块级单例
detector = InstallerNoiseDetector()
