"""内存资源监控 + 超阈值自动降级。

指标：
- RSS_IDLE_MAX_MB = 80 MB
- RSS_PEAK_MAX_MB = 150 MB

策略：
- 启动时记录基础 RSS
- 每 30 秒采样
- 连续 3 次超阈值 → 进入降级模式（关闭非核心轮询）
- 进入降级后每 60 秒重试一次；恢复后回正常
"""

from __future__ import annotations

import threading
import time
from typing import Callable

import psutil

from src.guardian.core.config import RSS_CHECK_INTERVAL_S, RSS_IDLE_MAX_MB, RSS_PEAK_MAX_MB
from src.guardian.core.logger import logger


class MemoryGuard(threading.Thread):
    """后台守护线程，监控自身进程 RSS。"""

    def __init__(self, on_degrade: Callable[[], None] | None = None,
                 on_recover: Callable[[], None] | None = None) -> None:
        super().__init__(daemon=True, name="memory-guard")
        self._on_degrade = on_degrade
        self._on_recover = on_recover
        self._stop = threading.Event()
        self._is_degraded = False
        self._overshoot_streak = 0
        self._overshoot_threshold = 3  # 连续 3 次超阈值才降级（避免抖动）
        self._proc = psutil.Process()
        self._baseline_mb = self._sample_mb()
        logger.info(f"MemGuard start: baseline={self._baseline_mb:.1f} MB, "
                    f"idle_max={RSS_IDLE_MAX_MB} MB, peak_max={RSS_PEAK_MAX_MB} MB")

    def _sample_mb(self) -> float:
        return self._proc.memory_info().rss / 1024 / 1024

    def stop(self) -> None:
        self._stop.set()

    def is_degraded(self) -> bool:
        return self._is_degraded

    def run(self) -> None:
        while not self._stop.wait(RSS_CHECK_INTERVAL_S):
            current_mb = self._sample_mb()
            over_idle = current_mb > RSS_IDLE_MAX_MB
            over_peak = current_mb > RSS_PEAK_MAX_MB

            if over_peak:
                # 严重超阈值：立即降级
                logger.warning(f"RSS {current_mb:.1f} MB > peak {RSS_PEAK_MAX_MB} MB, force degrade")
                self._enter_degraded()
            elif over_idle:
                self._overshoot_streak += 1
                logger.debug(f"RSS {current_mb:.1f} MB > idle {RSS_IDLE_MAX_MB} MB "
                             f"({self._overshoot_streak}/{self._overshoot_threshold})")
                if self._overshoot_streak >= self._overshoot_threshold and not self._is_degraded:
                    self._enter_degraded()
            else:
                self._overshoot_streak = 0
                if self._is_degraded and current_mb < RSS_IDLE_MAX_MB * 0.9:
                    self._exit_degraded()

    def _enter_degraded(self) -> None:
        if self._is_degraded:
            return
        self._is_degraded = True
        logger.warning("Entering DEGRADED mode: suspending non-critical workers")
        if self._on_degrade:
            try:
                self._on_degrade()
            except Exception as e:
                logger.exception(f"on_degrade callback failed: {e}")

    def _exit_degraded(self) -> None:
        if not self._is_degraded:
            return
        self._is_degraded = False
        logger.info("Exiting DEGRADED mode: resuming normal operation")
        if self._on_recover:
            try:
                self._on_recover()
            except Exception as e:
                logger.exception(f"on_recover callback failed: {e}")
