"""路径/场景白名单 —— fsmon 在评分前先过这一关，过则直接放行。

设计目标：
- 全卷监控（USN）会带来大量"已知安全/低价值"文件事件（QQ 预览图、
  聊天记录库、OneDrive 同步缓存等），逐个评分浪费 CPU/IO
- 这些路径是产品层面"该忽略"的，按路径子串匹配即可
- 命中后只记 debug 日志，不进评分队列、不入白名单表
- 与 fsmon.FSMON_EXCLUDE_DIR_PARTS 互补：后者管"系统级噪声"，
  本模块管"应用场景级豁免"
"""

from __future__ import annotations

import os
from pathlib import PureWindowsPath

from src.guardian.core.config import FSMON_APP_EXCLUDE_PATTERNS
from src.guardian.core.logger import logger


def is_exempt(file_path: str) -> tuple[bool, str | None]:
    """判断文件路径是否在应用场景白名单豁免中。

    返回 (是否豁免, 命中原因)。豁免时 reason 非空，便于日志和调试。
    匹配规则：路径（统一 \\）的子串 + 大小写不敏感。
    """
    if not file_path:
        return False, None

    # PureWindowsPath 在 Windows 上原生 split；在 Git Bash 里也工作
    p_norm = str(PureWindowsPath(file_path)).lower()
    for pat in FSMON_APP_EXCLUDE_PATTERNS:
        if pat.lower() in p_norm:
            return True, pat
    return False, None


def should_log_skip(file_path: str) -> bool:
    """是否值得在 debug 日志里记一条"豁免命中"。"""
    exempt, _ = is_exempt(file_path)
    return exempt


def safe_str_path(p: str | bytes) -> str:
    """处理编码异常时回退（脱敏的路径子串可能含非 ASCII）。"""
    if isinstance(p, bytes):
        try:
            return p.decode("utf-8", errors="replace")
        except Exception:
            return repr(p)
    return str(p)


def explain(file_path: str) -> str:
    """调试用：返回豁免原因（含所有命中 patterns）。"""
    p_norm = str(PureWindowsPath(file_path)).lower()
    hits = [pat for pat in FSMON_APP_EXCLUDE_PATTERNS if pat.lower() in p_norm]
    return ",".join(hits) if hits else "no-exempt"