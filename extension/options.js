// PC Guardian — 设置页脚本（MV3 扩展页面禁止内联脚本，故独立成文件）
'use strict';

const BACKEND = 'http://127.0.0.1:7890';

async function load() {
  try {
    const r = await fetch(BACKEND + '/whitelist');
    const data = await r.json();
    const items = (data.items || []).map((i) => i.pattern);
    document.getElementById('whitelist').value = items.join('\n');
  } catch (e) {
    document.getElementById('whitelist').value = '// 后台未启动：' + (e && e.message ? e.message : e);
  }

  const stored = await chrome.storage.local.get(['grayscale']);
  document.getElementById('grayscale').value = (stored.grayscale || []).join('\n');

  chrome.runtime.sendMessage({ type: 'get_stats' }, (resp) => {
    const el = document.getElementById('stats');
    if (chrome.runtime.lastError || !resp) {
      el.innerHTML = '<span class="bad">✗ 扩展后台未响应</span>：Service Worker 可能未加载。'
        + '请到 edge://extensions 确认已启用并点"重新加载"。';
      return;
    }
    const okWl = resp.whitelist_size >= 30;
    const okGl = resp.grayscale_size >= 10;
    el.innerHTML =
      `构建号：<strong>v${resp.build || '?'}</strong><br>`
      + `白名单：<span class="${okWl ? 'ok' : 'bad'}">${resp.whitelist_size} 条 ${okWl ? '✓' : '✗ 偏少'}</span> `
      + `/ 灰名单：<span class="${okGl ? 'ok' : 'bad'}">${resp.grayscale_size} 条 ${okGl ? '✓' : '✗ 偏少'}</span> `
      + `/ 恶意缓存：${resp.mal_cache_size}`;
  });
}

// ---- 安装自检 ----
document.getElementById('selftest').addEventListener('click', async () => {
  const box = document.getElementById('selftest-result');
  box.innerHTML = '<div class="stats">检测中…</div>';

  // 1) 扩展是否活着
  let ping = null;
  try {
    ping = await chrome.runtime.sendMessage({ type: 'ping' });
  } catch (_) {}

  // 2) 本地后端是否可达
  let backendOk = false, backendInfo = '';
  try {
    const r = await fetch(BACKEND + '/health');
    const j = await r.json();
    backendOk = !!j.ok;
    backendInfo = `RSS ${j.rss_mb} MB`;
  } catch (_) {}

  // 3) 决策自检：这些 URL 的期望结果
  const cases = [
    { url: 'https://www.baidu.com/', want: 'allow', why: '白名单' },
    { url: 'http://bit.ly/abc123', want: 'block', why: '灰名单（短链）' },
    { url: 'http://anything.tk/', want: 'block', why: '灰名单（高风险 TLD）' },
    { url: 'http://1.2.3.4/', want: 'block', why: '启发式（裸 IP）' },
  ];
  const rows = [];
  for (const c of cases) {
    let dec = 'error';
    try {
      const res = await chrome.runtime.sendMessage({ type: 'evaluate_url', url: c.url });
      dec = res && res.decision ? res.decision : 'error';
    } catch (_) {}
    const pass = dec === c.want;
    rows.push(
      `<tr><td><code>${c.url}</code></td><td>${c.why}</td>`
      + `<td>期望 <strong>${c.want}</strong></td>`
      + `<td class="${pass ? 'ok' : 'bad'}">实际 ${dec} ${pass ? '✓' : '✗'}</td></tr>`
    );
  }

  box.innerHTML =
    `<div class="stats">`
    + `扩展后台：${ping && ping.ok ? `<span class="ok">✓ 运行中（v${ping.build}）</span>` : '<span class="bad">✗ 未响应</span>'}<br>`
    + `本地后端：${backendOk ? `<span class="ok">✓ 已连接（${backendInfo}）</span>` : '<span class="bad">✗ 未连接（未启动 scripts\\start.bat？）</span>'}`
    + `</div>`
    + `<table><tr><th align="left">测试 URL</th><th align="left">依据</th><th align="left">期望</th><th align="left">实际</th></tr>`
    + rows.join('') + `</table>`;
});

document.getElementById('save').addEventListener('click', async () => {
  const wl = document.getElementById('whitelist').value.split('\n').map((s) => s.trim()).filter(Boolean);
  const gl = document.getElementById('grayscale').value.split('\n').map((s) => s.trim()).filter(Boolean);

  // 先清空旧白名单再逐条添加（POST 是 upsert）
  try {
    const cur = await (await fetch(BACKEND + '/whitelist')).json();
    for (const it of (cur.items || [])) {
      await fetch(BACKEND + '/whitelist/' + encodeURIComponent(it.pattern), { method: 'DELETE' });
    }
    for (const p of wl) {
      await fetch(BACKEND + '/whitelist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pattern: p }),
      });
    }
  } catch (e) {
    alert('后台写入失败：' + (e && e.message ? e.message : e));
    return;
  }

  await chrome.storage.local.set({ grayscale: gl });
  chrome.runtime.sendMessage({ type: 'reload_config' });
  alert('已保存，下次访问生效。');
  load();
});

document.getElementById('reload').addEventListener('click', load);

load();
