"""告警历史端到端测试（P2-2）。

覆盖：
- url_blocks db 表基本 CRUD
- /alerts/url_block POST 接收
- /alerts/history GET（合并 url/proc/quarantine）
- /alerts/summary GET（按类型计数 + top 规则）
- E2E：模拟扩展上报多条事件，验证聚合正确

运行：
  python tests/test_alerts.py
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import urllib.request

from src.guardian.core.db import db

PASS = 0
FAIL = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} {detail}")


def _post(url: str, body: dict | None = None) -> dict:
    data = json.dumps(body or {}).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())


def _get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=5) as r:
        return json.loads(r.read())


# ---- Test 1: db 直接 ----

def test_db_crud():
    print("\n--- db: url_blocks CRUD ---")
    # 清空旧数据
    with db._lock:
        with db._conn() as c:
            c.execute("DELETE FROM url_blocks")

    aid = db.push_url_block({
        "url": "http://test1.example/",
        "rule": "cloud",
        "threat_score": 80,
        "layers": "cloud",
        "evidence": [{"layer": "cloud", "hit": "phishing", "detail": "黑名单命中"}],
        "tab_id": 1,
    })
    check("push_url_block 返回 id > 0", aid > 0, f"id={aid}")

    items = db.list_url_blocks(0, 10)
    check("list_url_blocks 返回非空", len(items) >= 1, f"len={len(items)}")
    check("list_url_blocks 第一条 url 正确", items[0]["url"] == "http://test1.example/")
    check("evidence 是 list", isinstance(items[0]["evidence"], list))

    cnt = db.url_blocks_count(0)
    check("url_blocks_count 大于 0", cnt >= 1, f"cnt={cnt}")

    top = db.url_blocks_top_rules(0, 5)
    check("url_blocks_top_rules 返回 list[tuple]", isinstance(top, list) and len(top) >= 1)
    # 再插入一条 rule=cloud 应该是 top
    db.push_url_block({
        "url": "http://test2.example/",
        "rule": "cloud",
        "threat_score": 70,
        "layers": "cloud",
        "evidence": [],
        "tab_id": 2,
    })
    top2 = db.url_blocks_top_rules(0, 5)
    cloud_count = next((c for r, c in top2 if r == "cloud"), 0)
    check("rule=cloud 计数 >= 2", cloud_count >= 2, f"cloud={cloud_count}")


# ---- Test 2: API 端点 ----

def test_alerts_url_block_endpoint():
    print("\n--- API: POST /alerts/url_block ---")
    body = {
        "url": "http://1.2.3.4/malware.exe",
        "rule": "heuristic:raw_ip_host",
        "threat_score": 45,
        "layers": "heuristic",
        "evidence": [{"layer": "heuristic", "rule": "raw_ip_host", "detail": "裸 IP 主机 1.2.3.4"}],
        "tab_id": 5,
    }
    res = _post("http://127.0.0.1:7890/alerts/url_block", body)
    check("返回 ok=True", res.get("ok") is True, f"res={res}")
    check("返回 id > 0", isinstance(res.get("id"), int) and res["id"] > 0)


def test_alerts_history_endpoint():
    print("\n--- API: GET /alerts/history ---")
    # type=all
    res = _get("http://127.0.0.1:7890/alerts/history?type=all&since=24h&limit=50")
    check("type=all 返回 items", isinstance(res.get("items"), list))
    check("至少 3 条 url + 1 条 proc + 2 条 quar 事件",
          len(res["items"]) >= 3,  # 测试 1 已有 2 条 + Test 2 加 1 条
          f"got={len(res['items'])}")

    # 仅 url
    res_url = _get("http://127.0.0.1:7890/alerts/history?type=url&since=24h")
    check("type=url 仅返回 url 类型",
          all(it["type"] == "url" for it in res_url["items"]),
          f"types={set(it['type'] for it in res_url['items'])}")

    # since=1h（空集或很少）
    res_1h = _get("http://127.0.0.1:7890/alerts/history?type=all&since=1h")
    check("since=1h 返回 items list", isinstance(res_1h.get("items"), list))

    # 时间倒序
    res_all = _get("http://127.0.0.1:7890/alerts/history?type=all&since=24h&limit=200")
    ts_list = [it["ts"] for it in res_all["items"]]
    check("items 按时间倒序", ts_list == sorted(ts_list, reverse=True),
          f"first={ts_list[:3]}, last={ts_list[-3:]}")


def test_alerts_summary_endpoint():
    print("\n--- API: GET /alerts/summary ---")
    res = _get("http://127.0.0.1:7890/alerts/summary?since=24h")
    check("返回 total", isinstance(res.get("total"), int))
    check("返回 by_type", "by_type" in res)
    check("by_type 含 url/proc/quarantine",
          all(k in res["by_type"] for k in ("url", "proc", "quarantine")))
    check("返回 top_rules", "top_rules" in res)
    check("top_rules 含 cloud (前面 db 测试插了)",
          any(r["rule"] == "cloud" for r in res["top_rules"].get("url", [])),
          f"url_top={res['top_rules'].get('url', [])}")


# ---- Test 3: 模拟扩展上报 + 流程串联 ----

def test_simulate_extension_report():
    print("\n--- E2E: 模拟扩展上报 + 合并 ---")
    # 1) 模拟 5 条 URL 拦截
    for i, (url, rule, score, layer) in enumerate([
        ("http://malicious-site1.tk/",              "grayscale", 60, "grayscale"),
        ("http://phishing-page.tk/login",          "grayscale", 60, "grayscale"),
        ("http://bit.ly/abc123",                   "grayscale", 60, "grayscale"),
        ("http://1.2.3.4/malware.exe",             "heuristic:raw_ip_host", 45, "heuristic"),
        ("http://cdn.malicious-cdn.com/payload",   "cloud",     80, "cloud"),
    ]):
        _post("http://127.0.0.1:7890/alerts/url_block", {
            "url": url,
            "rule": rule,
            "threat_score": score,
            "layers": layer,
            "evidence": [{"layer": layer, "hit": rule, "detail": f"E2E 测试 #{i}"}],
            "tab_id": 100 + i,
        })

    # 2) 模拟 1 条进程告警
    db.push_proc_alert({
        "pid": 9999,
        "name": "evil.exe",
        "path": r"C:\Users\farma\AppData\Local\Temp\evil.exe",
        "cmdline": "evil.exe -hacker",
        "ppid": 1234,
        "parent_name": "cmd.exe",
        "rules": ["high_risk_parent", "suspicious_path"],
        "evidence": [{"rule": "high_risk_parent", "detail": "Office 派生的命令行进程"}],
    })

    # 3) 模拟 2 条 quarantine（已存在其他测试 + 我们再插 1 条）
    db.quarantine_add(
        r"D:\Download\another_malware.exe",
        "deadbeef" * 8,
        "exec_ext; filename_keyword",
        12345,
        source_dir="downloads",
        threat_score=75,
        signature_status="unsigned",
    )

    # 4) 验证 history 合并
    res = _get("http://127.0.0.1:7890/alerts/history?type=all&since=24h&limit=500")
    types = [it["type"] for it in res["items"]]
    url_n = types.count("url")
    proc_n = types.count("proc")
    quar_n = types.count("quarantine")
    check(f"合并后 url 计数 >= 5", url_n >= 5, f"url={url_n}")
    check(f"合并后 proc 计数 >= 1", proc_n >= 1, f"proc={proc_n}")
    check(f"合并后 quarantine 计数 >= 1", quar_n >= 1, f"quar={quar_n}")

    # 5) 验证 summary 统计
    s = _get("http://127.0.0.1:7890/alerts/summary?since=24h")
    check("summary.by_type.url >= 5", s["by_type"]["url"] >= 5,
          f"url={s['by_type']['url']}")
    check("summary.by_type.proc >= 1", s["by_type"]["proc"] >= 1,
          f"proc={s['by_type']['proc']}")
    check("summary.by_type.quarantine >= 1", s["by_type"]["quarantine"] >= 1,
          f"quar={s['by_type']['quarantine']}")
    # grayscale 应该 top
    url_rules = [r["rule"] for r in s["top_rules"].get("url", [])]
    check("URL top 规则中含 grayscale", "grayscale" in url_rules,
          f"url_rules={url_rules}")


# ---- Test 4: since 边界 ----

def test_since_boundary():
    print("\n--- API: since 边界 ---")
    for s in ("1h", "24h", "7d", "30d", "all"):
        r = _get(f"http://127.0.0.1:7890/alerts/history?type=all&since={s}")
        check(f"since={s} 正常返回", "items" in r and "count" in r,
              f"since={s}")


# ---- 主入口 ----

def main():
    print("=" * 60)
    print(" 告警历史 API 测试（P2-2）")
    print("=" * 60)
    print("⚠ 本测试假设服务已运行：http://127.0.0.1:7890")

    test_db_crud()
    test_alerts_url_block_endpoint()
    test_alerts_history_endpoint()
    test_alerts_summary_endpoint()
    test_simulate_extension_report()
    test_since_boundary()

    print("\n" + "=" * 60)
    print(f" 通过：{PASS}    失败：{FAIL}")
    print("=" * 60)
    sys.exit(0 if FAIL == 0 else 1)


if __name__ == "__main__":
    main()