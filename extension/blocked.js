// PC Guardian — 拦截页脚本（MV3 扩展页面禁止内联脚本，故独立成文件）
'use strict';

const params = new URLSearchParams(location.search);
const targetUrl = params.get('url') || '';
document.getElementById('target-url').textContent = targetUrl || '(未知)';

let evidence = [];
try {
  evidence = JSON.parse(decodeURIComponent(params.get('ev') || '[]'));
} catch (_) {
  evidence = [];
}

const layerName = {
  cloud: '云查（URLhaus 等）',
  grayscale: '灰查（已知可疑名单）',
  heuristic: '启发式（URL 异常特征）',
  sandbox: '沙查（行为监控）',
};

const el = document.getElementById('evidence-list');
if (!evidence.length) {
  el.textContent = '无证据记录（可能为手动拦截）。';
} else {
  el.innerHTML = evidence.map((e) => {
    const name = layerName[e.layer] || e.layer;
    const detail = e.detail ? `<br><span class="detail">${escapeHtml(e.detail)}</span>` : '';
    const sources = e.sources && e.sources.length ? `（来源: ${e.sources.join(',')}）` : '';
    const score = e.score != null ? `（评分: ${e.score}）` : '';
    return `<div class="evidence-item"><strong>${escapeHtml(name)}</strong>: ${escapeHtml(e.hit || '')} ${sources} ${score}${detail}</div>`;
  }).join('');
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

// 加入白名单
document.getElementById('whitelist-btn').addEventListener('click', async (ev) => {
  ev.preventDefault();
  if (!targetUrl) return;
  try {
    const r = await fetch('http://127.0.0.1:7890/whitelist', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pattern: targetUrl }),
    });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    alert('已加入白名单，下次访问将放行。');
    history.back();
  } catch (e) {
    alert('加入失败：本地后台服务未启动或不可达。\n' + (e && e.message ? e.message : e));
  }
});
