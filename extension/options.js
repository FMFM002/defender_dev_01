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
    if (resp) {
      document.getElementById('stats').textContent =
        `恶意缓存: ${resp.mal_cache_size} / 白名单: ${resp.whitelist_size} / 灰名单: ${resp.grayscale_size}`;
    }
  });
}

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
