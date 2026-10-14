"""SakuraCat-VPN 代理探测。

- 默认 127.0.0.1:7897 提供 SOCKS5 + HTTP 代理
- 启动时探测一次：有 → 缓存；没 → 不缓存，每次请求重新探测
- 所有云查请求走代理或直连，由探测结果自动决定
"""

from __future__ import annotations

import socket
import threading
import time

from src.guardian.core.config import VPN_PROXY_HOST, VPN_PROXY_PORT, VPN_PROXY_TIMEOUT
from src.guardian.core.logger import logger


class ProxyProbe:
    """单实例代理探测器。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cached_status: bool | None = None
        self._cached_at: float = 0.0
        self._reprobe_after_s = 60.0  # 缓存 60 秒

    def is_available(self) -> bool:
        """检查 VPN 代理端口是否可用。"""
        with self._lock:
            now = time.time()
            if self._cached_status is not None and (now - self._cached_at) < self._reprobe_after_s:
                return self._cached_status
            self._cached_status = self._probe()
            self._cached_at = now
            if self._cached_status:
                logger.info(f"VPN proxy detected at {VPN_PROXY_HOST}:{VPN_PROXY_PORT}")
            else:
                logger.debug(f"VPN proxy not available at {VPN_PROXY_HOST}:{VPN_PROXY_PORT}")
            return self._cached_status

    def _probe(self) -> bool:
        try:
            with socket.create_connection(
                (VPN_PROXY_HOST, VPN_PROXY_PORT),
                timeout=VPN_PROXY_TIMEOUT,
            ) as s:
                return True
        except (OSError, socket.timeout):
            return False

    def get_proxy_url(self) -> str | None:
        """返回 httpx 用的 proxy URL，None 表示直连。"""
        if self.is_available():
            return f"http://{VPN_PROXY_HOST}:{VPN_PROXY_PORT}"
        return None


proxy = ProxyProbe()
