// PC Guardian — Edge MV3 Service Worker
//
// 告警策略（用户硬性要求）：
//   云查（URLhaus）无异常 + 灰查（灰名单/启发式）无异常 + 沙查（本地行为）无异常
//   = 完全静默。
//   任一项异常 → chrome.notifications 弹窗示警，写明异常证据（哪一层命中什么）。
//
// 拦截策略：
//   1) 白名单（默认+用户）  → 放行
//   2) 已知恶意域缓存     → 阻断（declarativeNetRequest 静态规则）
//   3) 灰名单/启发式命中  → 阻断（动态规则，POST 评估证据回写）
//   4) 其余               → 放行（保持正常使用体验）
//
// 内存控制：
//   - 恶意域缓存上限 2000 条（LRU）
//   - 白名单/灰名单压缩为 Set（O(1) 查询）
//   - 30 分钟更新一次本地后端的灰名单（如启用）

const BACKEND = 'http://127.0.0.1:7890';
const WHITELIST_URL = BACKEND + '/whitelist/match';
const URLHAUS_URL = BACKEND + '/intel/url';
const ALARM_PERIOD = 'pc-guardian-refresh';
const MAL_CACHE_MAX = 2000;
const URL_MAX_LEN = 3500; // Edge URL 上限兼容

// 内存中的 Set/Map（service worker 重启会丢失，需要持久化的走 chrome.storage）
const defaultCfg = null; // 占位（实际通过 loadConfig 加载）
let CONFIG = { whitelist: new Set(), grayscale: new Set(), heuristics: null };
const MAL_CACHE = new Map(); // url -> {score, sources, ts}
let REFRESH_TIMER = null;

// ============ 启动 ============

chrome.runtime.onInstalled.addListener(init);
chrome.runtime.onStartup.addListener(init);

async function init() {
  await loadConfig();
  await refreshAllRules();
  setupAlarms();
  console.log('[PC Guardian] init done');
}

async function setupAlarms() {
  chrome.alarms.create(ALARM_PERIOD, { periodInMinutes: 30 });
  chrome.alarms.onAlarm.addListener(async (a) => {
    if (a.name === ALARM_PERIOD) {
      await refreshAllRules();
    }
  });
}

async function loadConfig() {
  // 默认白名单内嵌（首次安装直接可用），随后从本地后端拉取用户白名单合并。
  const defaults = await fetch(chrome.runtime.getURL('config/default_whitelist.json'))
    .then(r => r.json()).catch(() => null);

  // 从 chrome.storage 加载（被 Options 页面或本地后端写入）
  const stored = await chrome.storage.local.get(['whitelist', 'grayscale', 'heuristics']);

  CONFIG.whitelist = new Set(stored.whitelist || (defaults?.whitelist || []));
  CONFIG.grayscale = new Set(stored.grayscale || (defaults?.grayscale || []));
  CONFIG.heuristics = stored.heuristics || defaults?.heuristics || {
    block_ports: [22, 3389, 4444, 5900, 6667],
    suspicious_keywords_url: ['login','verify','account','update','wallet'],
    suspicious_tlds: ['.tk','.top','.xyz','.ml','.ga'],
    max_url_length: 350,
    max_subdomain_depth: 5,
    punycode_threshold: 'any',
  };
}

async function refreshAllRules() {
  // 拉取用户白名单（覆盖默认）
  try {
    const r = await fetch(BACKEND + '/whitelist', { method: 'GET' });
    if (r.ok) {
      const data = await r.json();
      const userList = (data.items || []).map(it => it.pattern);
      CONFIG.whitelist = new Set(userList);
      await chrome.storage.local.set({ whitelist: userList });
    }
  } catch (e) {
    console.warn('[PC Guardian] /whitelist 拉取失败（后端未启动？）', e?.message || e);
  }

  // 更新动态规则（移除旧的 PC Guardian 规则，重新生成）
  await rebuildDynamicRules();
}

async function rebuildDynamicRules() {
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  const removeRuleIds = existing.map(r => r.id);
  const addRules = [];

  // 把恶意缓存转为阻断规则（命中即拦截）
  let idx = 1;
  for (const [u, info] of MAL_CACHE.entries()) {
    if (info.score >= 50) {
      try {
        const host = new URL(u).hostname;
        addRules.push({
          id: idx++,
          priority: 100,
          action: { type: 'block' },
          condition: { urlFilter: '||' + host + '^' },
        });
      } catch (_) {}
    }
    if (idx > 5000) break;
  }
  await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules });
}

// ============ 决策 ============

function normalizeUrl(raw) {
  if (!raw || raw.length > URL_MAX_LEN) return null;
  try {
    const u = new URL(raw);
    return u;
  } catch (_) {
    return null;
  }
}

function isWhitelisted(urlObj) {
  const full = urlObj.origin + urlObj.pathname;
  for (const w of CONFIG.whitelist) {
    if (full.startsWith(w)) return w;
  }
  // 也允许 host 命中白名单
  const host = urlObj.hostname;
  for (const w of CONFIG.whitelist) {
    try {
      const wUrl = new URL(w);
      if (wUrl.hostname === host) return w;
    } catch (_) {}
  }
  return null;
}

function grayscaleHits(urlObj) {
  const host = urlObj.hostname;
  const matches = [];
  for (const g of CONFIG.grayscale) {
    if (g.startsWith('*.')) {
      const suf = g.slice(1); // ".tk"
      if (host.endsWith(suf)) matches.push(g);
    } else if (host === g || host.endsWith('.' + g)) {
      matches.push(g);
    }
  }
  return matches;
}

function heuristicsHits(urlObj, fullUrl) {
  const hits = [];
  const h = CONFIG.heuristics || {};
  // 端口
  const port = urlObj.port;
  if (port && (h.block_ports || []).includes(Number(port))) {
    hits.push({ rule: 'block_port', detail: `危险端口 ${port}` });
  }
  // URL 长度
  if (fullUrl.length > (h.max_url_length || 350)) {
    hits.push({ rule: 'long_url', detail: `URL 长度 ${fullUrl.length} > ${h.max_url_length}` });
  }
  // 可疑 TLD
  for (const t of (h.suspicious_tlds || [])) {
    if (urlObj.hostname.endsWith(t)) {
      hits.push({ rule: 'suspicious_tld', detail: `TLD ${t}` });
      break;
    }
  }
  // 可疑关键字（path/query 里）
  const haystack = (urlObj.pathname + urlObj.search).toLowerCase();
  for (const kw of (h.suspicious_keywords_url || [])) {
    if (haystack.includes(kw)) {
      hits.push({ rule: 'suspicious_keyword', detail: `关键词 "${kw}"` });
      break;
    }
  }
  // 子域深度
  const depth = urlObj.hostname.split('.').length;
  if (depth > (h.max_subdomain_depth || 5)) {
    hits.push({ rule: 'deep_subdomain', detail: `子域深度 ${depth}` });
  }
  // IDN 同形 / punycode
  if (urlObj.hostname.includes('xn--')) {
    hits.push({ rule: 'punycode_host', detail: `含 punycode 编码：${urlObj.hostname}` });
  }
  // IP 主机名（裸 IP 访问）
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(urlObj.hostname)) {
    hits.push({ rule: 'raw_ip_host', detail: `裸 IP 主机 ${urlObj.hostname}` });
  }
  return hits;
}

async function cloudQuery(url) {
  // 云查 URLhaus（仅在本机后端可用时调用）。失败不弹窗（云=无证据不算异常）。
  try {
    const r = await fetch(URLHAUS_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    if (!r.ok) return null;
    const data = await r.json();
    return data; // {_threat_score, malicious, threats, sources, ...}
  } catch (_) {
    return null; // 后端不可达 = 静默
  }
}

async function evaluate(url) {
  const u = normalizeUrl(url);
  if (!u) return { decision: 'allow', evidence: [] };

  // 1) 白名单直接放��
  const w = isWhitelisted(u);
  if (w) return { decision: 'allow', evidence: [{ layer: 'whitelist', hit: w }] };

  const evidence = [];

  // 2) 云查
  const cloud = await cloudQuery(url);
  if (cloud && cloud.malicious) {
    evidence.push({
      layer: 'cloud', hit: cloud.threats?.join(',') || 'malicious',
      sources: (cloud.sources || []).filter(s => s.malicious).map(s => s.source),
      score: cloud._threat_score,
    });
  } else if (cloud && (cloud._threat_score || 0) >= 50) {
    evidence.push({ layer: 'cloud', hit: 'score', score: cloud._threat_score });
  }

  // 3) 灰查（灰名单 + 启发式）
  const gray = grayscaleHits(u);
  if (gray.length) evidence.push({ layer: 'grayscale', hit: gray.join(',') });

  const heur = heuristicsHits(u, url);
  if (heur.length) {
    evidence.push({
      layer: 'heuristic',
      hit: heur.map(h => h.rule).join(','),
      detail: heur.map(h => `${h.rule}:${h.detail}`).join(' | '),
    });
  }

  // 4) 沙查（本地行为占位：可挂 ETW 子模块上报的实时进程事件）
  //    此处无实时事件则不计入异常。

  // 决策：任一证据 = 阻断 + 弹窗
  if (evidence.length) {
    return { decision: 'block', evidence, cloud };
  }
  return { decision: 'allow', evidence };
}

// ============ 拦截 ============

async function blockAndAlert(url, evidence) {
  // 写入恶意缓存（参与下次动态规则）
  if (evidence.some(e => e.layer === 'cloud')) {
    addToMalCache(url, 80, evidence);
  } else if (evidence.some(e => e.layer === 'grayscale')) {
    addToMalCache(url, 50, evidence);
  } else {
    addToMalCache(url, 30, evidence);
  }
  await rebuildDynamicRules();

  // 弹窗示告（任一异常）
  const layerSummary = evidence.map(e => `${e.layer}:${e.hit}`).join('\n');
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon-48.png',
    title: 'PC Guardian 已拦截可疑访问',
    message: evidence[0].hit || '命中防护规则',
    contextMessage: '异常证据（任一项即拦截）：\n' + layerSummary,
    priority: 2,
  });

  // 跳转到拦截页（在新标签里重定向，避免直接用 chrome.tabs.update 引发 race）
  // 实际拦截已由动态规则完成；此处只是给用户看详细证据。
  return layerSummary;
}

function addToMalCache(url, score, evidence) {
  MAL_CACHE.set(url, { score, evidence, ts: Date.now() });
  if (MAL_CACHE.size > MAL_CACHE_MAX) {
    // LRU: 删除最旧的
    const firstKey = MAL_CACHE.keys().next().value;
    MAL_CACHE.delete(firstKey);
  }
}

// ============ 导航拦截 ============
// Edge MV3 不允许 webRequest 阻塞，但可以用 webNavigation 监听 onBeforeNavigate
// + chrome.tabs.update 跳转到 blocked.html（实时）。对于缓存命中（已知恶意），
// 走 declarativeNetRequest 静态/动态规则直接阻断。

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return; // 只看顶层
  const url = details.url;
  if (!url || url.startsWith('chrome://') || url.startsWith('edge://') || url.startsWith('about:')) return;

  // 缓存命中：动态规则已直接 block，不会触发到这里；触发到这里 = 需要实时评估
  const result = await evaluate(url);

  if (result.decision === 'block') {
    const evidenceUrl = encodeURIComponent(JSON.stringify(result.evidence));
    const redirectUrl = chrome.runtime.getURL('blocked.html')
      + '?url=' + encodeURIComponent(url)
      + '&ev=' + evidenceUrl;
    chrome.tabs.update(details.tabId, { url: redirectUrl });
    // 异步告警（不 await，不阻塞）
    blockAndAlert(url, result.evidence);
  }
});

// ============ 下载拦截 ============
// 下载完成时计算 SHA256 推本地后端（P1：仅记录，P2 接 VT 真���拦截）
chrome.downloads.onChanged.addListener(async (delta) => {
  if (!delta.state || delta.state.current !== 'complete') return;
  // chrome.downloads API 在 MV3 service worker 中只能通过 search 获取完整信息
  try {
    const [info] = await chrome.downloads.search({ id: delta.id });
    if (!info || !info.finalUrl) return;
    // 仅作记录：本地后端没有在线哈希源时，hash 查询返回 unknown，不弹窗
    const sha256 = await sha256OfUrl(info.finalUrl);
    fetch(BACKEND + '/intel/hash', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sha256 }),
    }).catch(() => {});
  } catch (e) {
    console.warn('[PC Guardian] downloads hash failed', e?.message || e);
  }
});

async function sha256OfUrl(url) {
  // P1 简化：用 finalUrl 字符串哈希（避免下载整文件）。仅作占位指纹。
  const enc = new TextEncoder().encode(url);
  const buf = await crypto.subtle.digest('SHA-256', enc);
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
}

// ============ 消息接口（popup/options） ============

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === 'evaluate_url') {
    evaluate(msg.url).then(sendResponse);
    return true; // 异步
  }
  if (msg?.type === 'reload_config') {
    init().then(() => sendResponse({ ok: true }));
    return true;
  }
  if (msg?.type === 'get_stats') {
    sendResponse({
      mal_cache_size: MAL_CACHE.size,
      whitelist_size: CONFIG.whitelist.size,
      grayscale_size: CONFIG.grayscale.size,
    });
    return false;
  }
});