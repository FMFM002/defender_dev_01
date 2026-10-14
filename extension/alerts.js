// PC Guardian - 告警历史 Tab (P2-2)
// MV3 扩展页面禁止内联脚本，独立成文件。

'use strict';

const BACKEND = 'http://127.0.0.1:7890';

const ALERTS_STATE = {
  since: '24h',
  type: 'all',
  items: [],
  summary: null,
  autoTimer: null,
};

// ---- Tab 切换 ----
document.querySelectorAll('.tab-btn').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach((b) => b.classList.remove('active'));
    btn.classList.add('active');
    const tab = btn.dataset.tab;
    document.querySelectorAll('.tab-pane').forEach((p) => p.classList.remove('active'));
    document.getElementById('tab-' + tab).classList.add('active');
    if (tab === 'alerts') loadAlerts();
  });
});

// ---- chip 切换 ----
function bindChips(selector, onChange) {
  document.querySelectorAll(selector).forEach((chip) => {
    chip.addEventListener('click', () => {
      document.querySelectorAll(selector).forEach((c) => c.classList.remove('active'));
      chip.classList.add('active');
      onChange(chip.dataset);
      loadAlerts();
    });
  });
}

bindChips('.chip[data-since]', (d) => { ALERTS_STATE.since = d.since; });
bindChips('.chip[data-type]', (d) => { ALERTS_STATE.type = d.type; });

document.getElementById('alerts-refresh').addEventListener('click', loadAlerts);

// ---- 拉取 + 渲染 ----
async function loadAlerts() {
  const since = ALERTS_STATE.since;
  const type = ALERTS_STATE.type;

  // 并行拉
  const [historyRes, summaryRes] = await Promise.allSettled([
    fetch(BACKEND + '/alerts/history?type=' + type + '&since=' + since + '&limit=200').then(r => r.json()),
    fetch(BACKEND + '/alerts/summary?since=' + since).then(r => r.json()),
  ]);

  if (historyRes.status === 'fulfilled' && !historyRes.value.error) {
    ALERTS_STATE.items = historyRes.value.items || [];
  } else {
    ALERTS_STATE.items = [];
  }
  if (summaryRes.status === 'fulfilled') {
    ALERTS_STATE.summary = summaryRes.value;
  }

  renderSummary();
  renderList();
}

function renderSummary() {
  const s = ALERTS_STATE.summary;
  const box = document.getElementById('alerts-summary');
  if (!s || s.error) {
    box.innerHTML = '<div class="empty-state">无法连接到本地��台</div>';
    return;
  }

  const bt = s.by_type || {};
  const tr = s.top_rules || {};

  box.innerHTML =
    '<div class="summary-grid">'
    + summaryCard('总拦截', s.total || 0)
    + summaryCard('URL', bt.url || 0, '蓝色')
    + summaryCard('进程', bt.proc || 0, '橙色')
    + summaryCard('文件隔离', bt.quarantine || 0, '红色')
    + '</div>'
    + ruleList('按规则 Top 5 - URL 拦截', tr.url || [])
    + ruleList('按规则 Top 5 - 进程告警', tr.proc || [])
    + ruleList('按原因 Top 5 - 文件隔离', tr.quarantine || []);
}

function summaryCard(label, value) {
  return '<div class="summary-card">'
    + '<div class="label">' + escapeHtml(label) + '</div>'
    + '<div class="value">' + Number(value || 0) + '</div>'
    + '</div>';
}

function ruleList(title, items) {
  if (!items.length) {
    return '<div class="rule-list"><h4>' + escapeHtml(title) + '</h4><div class="empty-state">无</div></div>';
  }
  const lis = items.map((it) =>
    '<li><span class="rule-name">' + escapeHtml(it.rule) + '</span>'
    + '<span class="rule-count">' + it.count + '</span></li>'
  ).join('');
  return '<div class="rule-list"><h4>' + escapeHtml(title) + '</h4><ul>' + lis + '</ul></div>';
}

function renderList() {
  const items = ALERTS_STATE.items;
  const box = document.getElementById('alerts-list');
  if (!items.length) {
    box.innerHTML = '<div class="empty-state">该范围内没有告警事件</div>';
    return;
  }
  const html = items.map((it) => renderItem(it)).join('');
  box.innerHTML = html;
  // 绑定展开
  box.querySelectorAll('.alert-head').forEach((head) => {
    head.addEventListener('click', () => {
      const item = head.parentElement;
      item.classList.toggle('open');
    });
  });
}

function renderItem(it) {
  const type = it.type || 'unknown';
  const rule = it.rule || '';
  const ts = formatTs(it.ts);
  const primary = primaryText(it);
  let detailHtml = '';
  if (type === 'url') {
    detailHtml = '<strong>URL：</strong><code>' + escapeHtml(it.url || '') + '</code><br>'
      + '<strong>评分：</strong>' + (it.threat_score || 0)
      + ' / <strong>命中层：</strong>' + escapeHtml(it.layers || '-')
      + '<div style="margin-top:6px">' + renderEvidence(it.evidence) + '</div>';
  } else if (type === 'proc') {
    detailHtml = '<strong>进程：</strong>' + escapeHtml(it.name || '') + ' (pid=' + (it.pid || 0) + ')<br>'
      + '<strong>路径：</strong><code>' + escapeHtml(it.path || '') + '</code><br>'
      + '<strong>父进程：</strong>' + escapeHtml(it.parent_name || '-')
      + '<div style="margin-top:6px">' + renderEvidence(it.evidence) + '</div>';
  } else if (type === 'quarantine') {
    detailHtml = '<strong>路径：</strong><code>' + escapeHtml(it.path || '') + '</code><br>'
      + '<strong>来源：</strong>' + escapeHtml(it.source_dir || '-')
      + ' / <strong>签名：</strong>' + escapeHtml(it.signature_status || '-')
      + ' / <strong>评分：</strong>' + (it.threat_score || 0);
  }
  return '<div class="alert-item">'
    + '<div class="alert-head">'
    + '<span class="alert-type alert-type-' + type + '">' + typeLabel(type) + '</span>'
    + '<span class="alert-rule">' + escapeHtml(primary) + '</span>'
    + '<span class="alert-ts">' + ts + '</span>'
    + '</div>'
    + '<div class="alert-detail">' + detailHtml + '</div>'
    + '</div>';
}

function primaryText(it) {
  if (it.type === 'url') return it.url || '';
  if (it.type === 'proc') return (it.name || '') + ' ' + (it.rule || '');
  if (it.type === 'quarantine') return (it.path || '') + ' ' + (it.rule || '');
  return '';
}

function typeLabel(t) {
  if (t === 'url') return 'URL';
  if (t === 'proc') return '进程';
  if (t === 'quarantine') return '文件';
  return t;
}

function renderEvidence(evidence) {
  if (!Array.isArray(evidence) || !evidence.length) return '';
  return evidence.map((ev) => {
    const layer = ev.layer || ev.rule || '';
    const detail = ev.detail || ev.hit || '';
    return '<span class="ev"><strong>' + escapeHtml(layer) + '：</strong>' + escapeHtml(detail) + '</span>';
  }).join('');
}

function formatTs(ts) {
  if (!ts) return '';
  const d = new Date(ts * 1000);
  const pad = (n) => (n < 10 ? '0' + n : '' + n);
  return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate())
    + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
}

function escapeHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ---- 自动刷新（30s） ----
function startAutoRefresh() {
  if (ALERTS_STATE.autoTimer) clearInterval(ALERTS_STATE.autoTimer);
  ALERTS_STATE.autoTimer = setInterval(() => {
    // 只在告警 Tab 可见时刷新
    const active = document.querySelector('.tab-pane.active');
    if (active && active.id === 'tab-alerts') {
      loadAlerts().catch(() => {});
    }
  }, 30000);
}

startAutoRefresh();