"""ASR Rule 字典与注册表写入工具。

GUID 清单来源：https://github.com/0xsp-SRD/MDE_Enum (funcs.cs)
共 19 条规则（含 4 条 preview）。

写入路径：
  HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules
值类型：REG_DWORD
  0 = Disabled
  1 = Enabled (Block)
  2 = Audit

注意：写 HKLM 需要管理员权限。开发期不自动写，仅提供工具。
"""

from __future__ import annotations

import sys
from typing import Literal

# 完整 ASR Rule 字典
ASR_RULES: dict[str, str] = {
    "56A863A9-875E-4185-98A7-B882C64B5CE5": "Block Exploit of Vulnerable Signed Drivers",
    "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C": "Prevent Adobe Reader from creating child processes",
    "D4F940AB-401B-4EFC-AADC-AD5F3C50688A": "Prevent all Office applications from creating child processes",
    "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2": "Block stealing credentials from the Windows Local Security Authority (lsass.exe) Subsystem",
    "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550": "Block executable content from email client and webmail",
    "01443614-CD74-433A-B99E-2ECDC07BFC25": "Block executable files unless they meet a prevalence, age, or trusted list criterion",
    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC": "Block execution of potentially hidden scripts",
    "D3E037E1-3EB8-44C8-A917-57927947596D": "Block JavaScript or VBScript from launching downloaded executable content",
    "3B576869-A4EC-4529-8536-B80A7769E899": "Block Office applications from creating executable content",
    "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84": "Prevent Office applications from injecting code into other processes",
    "26190899-1602-49E8-8B27-EB1D0A1CE869": "Block Office Communication Application from Creating Child Processes",
    "E6DB77E5-3DF2-4CF1-B95A-636979351E5B": "Block persistence via WMI event subscription",
    "D1E49AAC-8F56-4280-B9BA-993A6D77406C": "Block Process Creations from PSExec and WMI Commands",
    "33ddedf1-c6e0-47cb-833e-de6133960387": "Block computer restarting in safe mode (preview)",
    "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4": "Block untrusted and unsigned processes running from USB",
    "C0033C00-D16D-4114-A5A0-DC9B3A7D2CEB": "Block the use of copied or imitated system utilities (preview)",
    "A8F5898E-1DC8-49A9-9878-85004B8A61E6": "Block the creation of web shells for servers",
    "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B": "Block Win32 API Calls from Office Macros",
    "C1DB55AB-C21A-4637-BB3F-A12568109D35": "How to use advanced ransomware protection",
}

# P1 默认启用的两条（最小可用链路，先解决"下载后自动运行"）
P1_DEFAULT_ENABLE = [
    "D3E037E1-3EB8-44C8-A917-57927947596D",  # 阻止 JS/VBScript 启动下载可执行内容
    "01443614-CD74-433A-B99E-2ECDC07BFC25",  # 阻止可执行文件运行除非满足流行度/年龄/可信列表
]


def list_rules() -> list[dict]:
    """返回所有规则 + 当前启用状态。"""
    current = read_current_values()
    return [
        {"guid": g, "description": d, "value": current.get(g, 0)}
        for g, d in ASR_RULES.items()
    ]


def read_current_values() -> dict[str, int]:
    """读取当前 ASR 规则值。需要在 Windows 上运行。"""
    if sys.platform != "win32":
        return {}
    try:
        import winreg
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules",
        ) as key:
            values: dict[str, int] = {}
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    values[name] = int(value)
                    i += 1
                except OSError:
                    break
            return values
    except FileNotFoundError:
        return {}
    except Exception:
        return {}


def write_rule(guid: str, value: Literal[0, 1, 2]) -> bool:
    """写入单条 ASR 规则。需要管理员权限。

    返回 True = 成功，False = 失败（无权限或非 Windows）。
    """
    if sys.platform != "win32":
        return False
    if guid not in ASR_RULES:
        return False
    try:
        import winreg
        with winreg.CreateKeyEx(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules",
            0,
            winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY,
        ) as key:
            winreg.SetValueEx(key, guid, 0, winreg.REG_DWORD, int(value))
        return True
    except Exception as e:
        from src.guardian.core.logger import logger
        logger.error(f"ASR write failed for {guid}: {e}")
        return False


def enable_p1_defaults() -> dict[str, bool]:
    """启用 P1 默认规则。返回每条成功与否。"""
    return {guid: write_rule(guid, 1) for guid in P1_DEFAULT_ENABLE}


def disable_rule(guid: str) -> bool:
    return write_rule(guid, 0)
