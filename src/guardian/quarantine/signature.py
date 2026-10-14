"""Authenticode 数字签名校验（WinVerifyTrust / SIGNATURE_CHECK）。

返回:
  - True  : 有合法签名
  - False : 文件无签名（或签名失效）
  - None  : 验证失败（系统缺接口等异常情况），调用方按"未知"处理

实现要点:
- 使用 ctypes 直接调 crypt32.dll 的 WinVerifyTrust（WTH_USER_OBJECT）
- 大文件不读（只走 Windows PE 文件头，API 自带 IO）
- 失败时不抛异常，纯日志记录一次，避免噪声
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes
from ctypes import wintypes
from pathlib import Path

from src.guardian.core.logger import logger

# ---- WinTrust / Wintrust 接口常量 ----
class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_ubyte * 8),
    ]

WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID(
    0x00AAC56B, 0xCD44, 0x11D0,
    (ctypes.c_ubyte * 8)(0x8C, 0x3C, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
)

WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
ERROR_SUCCESS = 0
WTD_SAFER_FLAG = 0x00000100

# 单次失败只报一次（避免进程监控每次都打）
_warned_failure = False


def _to_python_path(p: Path) -> str:
    s = str(p)
    # WinVerifyTrust 需要反斜杠路径；Python 路径在 Windows 上默认就是 \\
    return s if "\\" in s else s.replace("/", "\\")


def has_signature(file_path: str) -> bool | None:
    """返回 True/False/None。"""
    global _warned_failure

    if not file_path:
        return None
    p = Path(file_path)
    if not p.exists() or not p.is_file():
        return None

    path = _to_python_path(p)

    # 结构体对齐
    class WINTRUST_DATA(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pPolicyCallbackData", ctypes.c_void_p),
            ("pSIPClientData", ctypes.c_void_p),
            ("dwUIChoice", wintypes.DWORD),
            ("fdwRevocationChecks", wintypes.DWORD),
            ("dwUnionChoice", wintypes.DWORD),
            ("pFile", ctypes.c_void_p),
            ("dwStateAction", wintypes.DWORD),
            ("hWVTStateData", ctypes.c_void_p),
            ("pwszURLReference", wintypes.LPCWSTR),
            ("dwProvFlags", wintypes.DWORD),
            ("dwUIContext", wintypes.DWORD),
            ("pSignatureSettings", ctypes.c_void_p),
        ]

    class WINTRUST_FILE_INFO(ctypes.Structure):
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pcwszFilePath", wintypes.LPCWSTR),
            ("pgKnownSubject", ctypes.c_void_p),
            ("hFile", wintypes.HANDLE),
        ]

    try:
        wtinfo = WINTRUST_FILE_INFO()
        wtinfo.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
        wtinfo.pcwszFilePath = ctypes.c_wchar_p(path)
        wtinfo.hFile = None

        wtd = WINTRUST_DATA()
        wtd.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        wtd.dwUIChoice = WTD_UI_NONE
        wtd.fdwRevocationChecks = WTD_REVOKE_NONE
        wtd.dwUnionChoice = 1  # WTD_CHOICE_FILE
        wtd.pFile = ctypes.cast(
            ctypes.pointer(wtinfo), ctypes.c_void_p
        )
        wtd.dwProvFlags = WTD_SAFER_FLAG

        wintrust = ctypes.windll.wintrust
        hr = wintrust.WinVerifyTrust(
            None,
            ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2),
            ctypes.byref(wtd),
        )
        # ERROR_SUCCESS (0) 表示通过；其它 hr 都视为非合格签名
        return hr == ERROR_SUCCESS
    except Exception as e:
        if not _warned_failure:
            logger.warning(f"WinVerifyTrust 调用失败（后续不再提示）：{e}")
            _warned_failure = True
        return None
