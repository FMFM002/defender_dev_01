"""ASR 规则启用工具（独立运行，需要管理员权限）。

用户双击运行（已在文件属性里勾选"以管理员身份运行"），
启用 P1 阶段的 2 条默认规则：

1. D3E037E1 - 阻止 JS/VBScript 启动下载的可执行内容
2. 01443614 - 阻止可执行文件运行（除非满足流行度/年龄/可信列表）

使用方法：
    python -m src.guardian.tools.apply_asr

也可指定规则 GUID 和值（0=Disable, 1=Enable, 2=Audit）：
    python -m src.guardian.tools.apply_asr --list         # 列出所有规则
    python -m src.guardian.tools.apply_asr --p1           # 启用 P1 默认
    python -m src.guardian.tools.apply_asr --guid D3E037E1... --value 1
    python -m src.guardian.tools.apply_asr --disable-all  # 关闭所有
"""

from __future__ import annotations

import argparse
import sys

from src.guardian.asr.rules import (
    ASR_RULES,
    P1_DEFAULT_ENABLE,
    disable_rule,
    list_rules,
    read_current_values,
    write_rule,
)


def _check_admin() -> bool:
    """检测当前进程是否有管理员权限。"""
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def cmd_list() -> int:
    current = read_current_values()
    print(f"{'GUID':<40} {'Value':<8} Description")
    print("-" * 100)
    for g, desc in ASR_RULES.items():
        v = current.get(g, 0)
        v_str = {0: "Disabled", 1: "Enabled", 2: "Audit"}.get(v, str(v))
        print(f"{g:<40} {v_str:<8} {desc}")
    print(f"\n当前已配置: {len(current)} 条")
    return 0


def cmd_p1() -> int:
    if not _check_admin():
        print("[错误] 需要管理员权限。请右键此脚本 → 以管理员身份运行。")
        return 2
    print("启用 P1 默认规则：")
    results: dict[str, bool] = {}
    for guid in P1_DEFAULT_ENABLE:
        ok = write_rule(guid, 1)
        results[guid] = ok
        mark = "✓" if ok else "✗"
        print(f"  {mark} {guid}  {ASR_RULES[guid]}")
    if all(results.values()):
        print("\n所有 P1 规则已启用。")
        return 0
    print("\n部分规则启用失败。请检查权限或 Windows Defender 是否启用。")
    return 1


def cmd_one(guid: str, value: int) -> int:
    if not _check_admin():
        print("[错误] 需要管理员权限。")
        return 2
    if guid not in ASR_RULES:
        print(f"[错误] 未知的 GUID: {guid}")
        return 1
    ok = write_rule(guid, value)
    v_str = {0: "Disabled", 1: "Enabled", 2: "Audit"}.get(value, str(value))
    print(f"{'✓' if ok else '✗'} {guid} -> {v_str}  {ASR_RULES[guid]}")
    return 0 if ok else 1


def cmd_disable_all() -> int:
    if not _check_admin():
        print("[错误] 需要管理员权限。")
        return 2
    print("关闭所有规则：")
    fail = 0
    for guid in ASR_RULES:
        ok = write_rule(guid, 0)
        if not ok:
            fail += 1
            print(f"  ✗ {guid}")
    print(f"\n{'所有规则已关闭。' if fail == 0 else f'有 {fail} 项失败。'}")
    return 0 if fail == 0 else 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="PC Guardian ASR 规则管理工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    g = parser.add_mutually_exclusive_group()
    g.add_argument("--list", action="store_true", help="列出所有规则当前状态")
    g.add_argument("--p1", action="store_true", help="启用 P1 默认规则")
    g.add_argument("--disable-all", action="store_true", help="关闭所有规则")
    g.add_argument("--guid", help="指定规则 GUID（与 --value 配合）")
    parser.add_argument("--value", type=int, default=1, help="值：0=禁用 1=启用 2=审计")
    args = parser.parse_args()

    if args.list:
        return cmd_list()
    if args.p1:
        return cmd_p1()
    if args.disable_all:
        return cmd_disable_all()
    if args.guid:
        return cmd_one(args.guid, args.value)
    # 默认：列出
    return cmd_list()


if __name__ == "__main__":
    sys.exit(main())