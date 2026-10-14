// PC Guardian — Edge MV3 Service Worker
//
// ---------------------------------------------------------------------------
// 设计要点（v2，2026-10-14 修复）
// ---------------------------------------------------------------------------
// 【为什么必须内联默认值】
//   MV3 的 Service Worker 会在空闲约 30 秒后被浏览器回收。回收后重新唤醒时，
//   onInstalled / onStartup 都【不会】再次触发，因此任何只在 init() 里加载的
//   配置（白名单/灰名单/启发式）在 SW 重启后都会变空 —— 表现为"扩展完全不拦截"。
//   所以默认名单必须写成模块级常量，在 SW 被唤醒的第一时间就可用。
//
// 【告警方式】
//   不使用系统通知（chrome.notifications）。命中的访问直接重定向到本地拦截页
//   blocked.html，证据在同一页展开，符合"直接在网页里拦截弹窗"的要求。
//
// 【决策顺序】（本地优先，保证零延迟）
//   1) 白名单         → 放行
//   2) 灰名单 / 启发式 → 立即拦截（不发网络请求，毫秒级）
//   3) 其余           → 本地后端云查（限时 2s，超时/失败即放行，避免拖慢上网）
//
// 【内存控制】
//   - 恶意缓存上限 2000 条（LRU）
//   - 白名单/灰名单压缩为 Set（O(1) 查询）
//   - 动态规则重建做 300ms 防抖，避免频繁写规则

// 构建号：每次改动扩展后 +1，用于在设置页"自检"里确认 Edge 是否加载了新代码。
// 如果自检显示的构建号 ≠ 本文件的 SW_BUILD，说明 edge://extensions 没有点"重新加载"。
const SW_BUILD = '0.3.2';

const BACKEND = 'http://127.0.0.1:7890';
const INTEL_URL = BACKEND + '/intel/url';
const ALERT_URL = BACKEND + '/alerts/url_block';
const ALARM_REFRESH = 'pc-guardian-refresh';
const MAL_CACHE_MAX = 2000;
const URL_MAX_LEN = 3500;
const CLOUD_TIMEOUT_MS = 2000;
const ALERT_QUEUE_MAX = 500;     // 离线队列上限（防止后端长时间不可达导致 chrome.storage 爆）

// ===========================================================================
// 内置默认名单（模块级常量 —— SW 唤醒即可用，不依赖任何异步加载）
// ===========================================================================

const DEFAULT_WHITELIST = [
  'https://www.baidu.com/',
  'https://baike.baidu.com/',
  'https://tieba.baidu.com/',
  'https://www.zhihu.com/',
  'https://zhuanlan.zhihu.com/',
  'https://juejin.cn/',
  'https://github.com/',
  'https://raw.githubusercontent.com/',
  'https://gist.github.com/',
  'https://stackoverflow.com/',
  'https://www.google.com/',
  'https://www.bing.com/',
  'https://duckduckgo.com/',
  'https://www.bilibili.com/',
  'https://www.youtube.com/',
  'https://www.youtube-nocookie.com/',
  'https://www.qq.com/',
  'https://weixin.qq.com/',
  'https://mail.qq.com/',
  'https://outlook.live.com/',
  'https://login.live.com/',
  'https://account.microsoft.com/',
  'https://www.taobao.com/',
  'https://www.jd.com/',
  'https://www.163.com/',
  'https://www.douban.com/',
  'https://www.csdn.net/',
  'https://developer.mozilla.org/',
  'https://www.npmjs.com/',
  'https://pypi.org/',
  'https://crates.io/',
  'https://docs.python.org/',
  'https://learn.microsoft.com/',
  'https://www.office.com/',
  'https://login.microsoftonline.com/',
];

const DEFAULT_GRAYSCALE = [
  '*.tk', '*.top', '*.xyz', '*.click', '*.download', '*.review',
  '*.country', '*.science', '*.stream', '*.gq', '*.cf', '*.ml',
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
];

const DEFAULT_HEURISTICS = {
  block_ports: [22, 3389, 4444, 5900, 6667],
  suspicious_keywords_url: [],   // 已停用：通用词误伤正常站点
  idn_homograph_keywords: ['paypal', 'apple', 'google', 'microsoft', 'amazon', 'bank'],
  suspicious_tlds: ['.tk', '.top', '.xyz', '.click', '.ml', '.ga', '.cf', '.gq'],
  max_url_length: 350,
  max_subdomain_depth: 5,
  punycode_threshold: 'any',
};

// ===========================================================================
// 运行时状态（同步初始化 —— 关键）
// ===========================================================================

const CONFIG = {
  defaultWhitelist: DEFAULT_WHITELIST,
  defaultGrayscale: DEFAULT_GRAYSCALE,
  whitelist: new Set(DEFAULT_WHITELIST),
  grayscale: new Set(DEFAULT_GRAYSCALE),
  heuristics: DEFAULT_HEURISTICS,
};

const MAL_CACHE = new Map(); // url -> {score, evidence, ts}
let SANDBOX_EVENTS = 0;

const SELF_PREFIX = chrome.runtime.getURL('');

// ===========================================================================
// 启动 / 配置合并（异步增强，失败不影响内置默认值）
// ===========================================================================

async function hydrate() {
  // 1) 读取扩展内置 JSON（可能与常量略有出入，作为补充）
  try {
    const j = await fetch(chrome.runtime.getURL('config/default_whitelist.json')).then(r => r.json());
    if (Array.isArray(j?.whitelist) && j.whitelist.length) CONFIG.defaultWhitelist = j.whitelist;
    if (Array.isArray(j?.grayscale) && j.grayscale.length) CONFIG.defaultGrayscale = j.grayscale;
    if (j?.heuristics) CONFIG.heuristics = { ...DEFAULT_HEURISTICS, ...j.heuristics };
  } catch (_) { /* 用内置常量即可 */ }

  // 2) 用户自定义（chrome.storage）
  let userWhite = [];
  let userGray = [];
  try {
    const stored = await chrome.storage.local.get(['whitelist', 'grayscale', 'heuristics']);
    userWhite = Array.isArray(stored.whitelist) ? stored.whitelist : [];
    userGray = Array.isArray(stored.grayscale) ? stored.grayscale : [];
    if (stored.heuristics) CONFIG.heuristics = { ...CONFIG.heuristics, ...stored.heuristics };
  } catch (_) {}

  // 3) 本地后端维护的用户白名单（合并，不覆盖）
  try {
    const r = await fetch(BACKEND + '/whitelist');
    if (r.ok) {
      const data = await r.json();
      const backendWhite = (data.items || []).map(it => it.pattern).filter(Boolean);
      userWhite = [...new Set([...userWhite, ...backendWhite])];
    }
  } catch (_) { /* 后端没起就跳过 */ }

  // 防御：万一某一路来源异常导致集合为空，绝不能把内置默认值覆盖掉
  // （早期版本曾因"后端白名单为空 → 整体覆盖 → 全部放行"而完全不拦截）
  const wl = new Set([...CONFIG.defaultWhitelist, ...userWhite]);
  if (wl.size) CONFIG.whitelist = wl;
  const gl = new Set([...CONFIG.defaultGrayscale, ...userGray]);
  if (gl.size) CONFIG.grayscale = gl;

  console.log('[PC Guardian] hydrate done v' + SW_BUILD,
    'whitelist=' + CONFIG.whitelist.size, 'grayscale=' + CONFIG.grayscale.size);

  // P2-2: hydrate 完成后尝试 flush 离线告警队列
  flushAlertQueue().catch(() => {});
}

// 顶层立即触发一次；SW 每次唤醒都会执行到这里
hydrate();

chrome.runtime.onInstalled.addListener(() => { hydrate(); setupAlarms(); });
chrome.runtime.onStartup.addListener(() => { hydrate(); setupAlarms(); });

function setupAlarms() {
  chrome.alarms.create(ALARM_REFRESH, { periodInMinutes: 30 });
}

chrome.alarms.onAlarm.addListener(async (a) => {
  if (a.name === ALARM_REFRESH) {
    await hydrate();
    await rebuildDynamicRules();
  }
});

// ===========================================================================
// 动态规则（已知恶意域 → 网络层直接阻断）
// ===========================================================================

let _rebuildTimer = null;
function scheduleRebuild() {
  if (_rebuildTimer) clearTimeout(_rebuildTimer);
  _rebuildTimer = setTimeout(() => { rebuildDynamicRules().catch(() => {}); }, 300);
}

async function rebuildDynamicRules() {
  let existing = [];
  try { existing = await chrome.declarativeNetRequest.getDynamicRules(); } catch (_) {}
  const removeRuleIds = existing.map(r => r.id);
  const addRules = [];
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
  try {
    await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules });
  } catch (e) {
    console.warn('[PC Guardian] updateDynamicRules failed', e?.message || e);
  }
}

// ===========================================================================
// 决策
// ===========================================================================

function normalizeUrl(raw) {
  if (!raw || raw.length > URL_MAX_LEN) return null;
  let u;
  try { u = new URL(raw); } catch (_) { return null; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  return u;
}

function isWhitelisted(urlObj) {
  const full = urlObj.origin + urlObj.pathname;
  for (const w of CONFIG.whitelist) {
    if (full.startsWith(w)) return w;
  }
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
  const port = urlObj.port;
  if (port && (h.block_ports || []).includes(Number(port))) {
    hits.push({ rule: 'block_port', detail: `危险端口 ${port}` });
  }
  if (fullUrl.length > (h.max_url_length || 350)) {
    hits.push({ rule: 'long_url', detail: `URL 长度 ${fullUrl.length} > ${h.max_url_length}` });
  }
  for (const t of (h.suspicious_tlds || [])) {
    if (urlObj.hostname.endsWith(t)) {
      hits.push({ rule: 'suspicious_tld', detail: `高风险 TLD ${t}` });
      break;
    }
  }
  const haystack = (urlObj.pathname + urlObj.search).toLowerCase();
  for (const kw of (h.suspicious_keywords_url || [])) {
    if (haystack.includes(kw)) {
      hits.push({ rule: 'suspicious_keyword', detail: `关键词 "${kw}"` });
      break;
    }
  }
  const depth = urlObj.hostname.split('.').length;
  if (depth > (h.max_subdomain_depth || 5)) {
    hits.push({ rule: 'deep_subdomain', detail: `子域深度 ${depth}` });
  }
  if (urlObj.hostname.includes('xn--')) {
    hits.push({ rule: 'punycode_host', detail: `含 punycode 编码：${urlObj.hostname}` });
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(urlObj.hostname)) {
    hits.push({ rule: 'raw_ip_host', detail: `裸 IP 主机 ${urlObj.hostname}` });
  }
  return hits;
}

async function cloudQuery(url, timeoutMs = CLOUD_TIMEOUT_MS) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetch(INTEL_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
      signal: ctrl.signal,
    });
    if (!r.ok) return null;
    return await r.json();
  } catch (_) {
    return null; // 后端不可达 / 超时 → 视为无云证据（放行）
  } finally {
    clearTimeout(t);
  }
}

async function evaluate(url) {
  const u = normalizeUrl(url);
  if (!u) return { decision: 'allow', evidence: [] };

  // 1) 白名单
  const w = isWhitelisted(u);
  if (w) return { decision: 'allow', evidence: [{ layer: 'whitelist', hit: w }] };

  const evidence = [];

  // 2) 灰查（灰名单 + 启发式）—— 纯本地，立即判定
  const gray = grayscaleHits(u);
  if (gray.length) evidence.push({ layer: 'grayscale', hit: gray.join(','), detail: `命中灰名单：${gray.join(', ')}` });

  const heur = heuristicsHits(u, url);
  if (heur.length) {
    evidence.push({
      layer: 'heuristic',
      hit: heur.map(h => h.rule).join(','),
      detail: heur.map(h => `${h.rule}：${h.detail}`).join(' | '),
    });
  }

  if (evidence.length) {
    // 本地已命中 → 立即拦截；后台补一次云查丰富缓存（不阻塞本次导航）
    enrichInBackground(url);
    return { decision: 'block', evidence };
  }

  // 3) 云查（限时 2s；失败/超时即放行，避免拖慢正常上网）
  const cloud = await cloudQuery(url);
  if (cloud && cloud.malicious) {
    evidence.push({
      layer: 'cloud',
      hit: (cloud.threats && cloud.threats.length ? cloud.threats.join(',') : 'malicious'),
      sources: (cloud.sources || []).filter(s => s.malicious).map(s => s.source),
      score: cloud._threat_score,
      detail: `云查命中：${(cloud.sources || []).filter(s => s.malicious).map(s => s.source).join(', ') || 'threat-intel'}`,
    });
    return { decision: 'block', evidence, cloud };
  }

  return { decision: 'allow', evidence };
}

function enrichInBackground(url) {
  cloudQuery(url)
    .then(cloud => {
      if (cloud && cloud.malicious) {
        addToMalCache(url, cloud._threat_score || 60, [{ layer: 'cloud', hit: 'malicious', score: cloud._threat_score }]);
        scheduleRebuild();
      }
    })
    .catch(() => {});
}

// ===========================================================================
// 拦截
// ===========================================================================

function addToMalCache(url, score, evidence) {
  MAL_CACHE.set(url, { score, evidence, ts: Date.now() });
  if (MAL_CACHE.size > MAL_CACHE_MAX) {
    const firstKey = MAL_CACHE.keys().next().value;
    MAL_CACHE.delete(firstKey);
  }
}

function scoreFor(evidence) {
  if (evidence.some(e => e.layer === 'cloud')) return 80;
  if (evidence.some(e => e.layer === 'grayscale')) return 60;
  if (evidence.some(e => e.layer === 'heuristic')) return 45;
  return 30;
}

async function blockAndCache(url, evidence) {
  addToMalCache(url, scoreFor(evidence), evidence);
  scheduleRebuild();
  // P2-2: 上报拦截事件给后端（失败时入离线队列）
  reportUrlBlock(url, evidence).catch(() => {});
}

// ===========================================================================
// 上报拦截事件（P2-2：告警历史可视化）
//   - 失败时入 chrome.storage.local 离线队列
//   - hydrate / alarm 触发时 flush 一次
// ===========================================================================

function scoreForEvidence(evidence) {
  if (evidence.some(e => e.layer === 'cloud')) return 80;
  if (evidence.some(e => e.layer === 'grayscale')) return 60;
  if (evidence.some(e => e.layer === 'heuristic')) return 45;
  return 30;
}

function deriveRule(evidence) {
  const layers = evidence.map(e => e.layer).filter(Boolean);
  if (layers.includes('cloud')) return 'cloud';
  if (layers.includes('grayscale')) return 'grayscale';
  if (layers.includes('heuristic')) {
    const heurHit = evidence.find(e => e.layer === 'heuristic')?.hit || '';
    return 'heuristic:' + heurHit.split(',')[0];
  }
  return 'unknown';
}

async function reportUrlBlock(url, evidence) {
  const payload = {
    url,
    rule: deriveRule(evidence),
    threat_score: scoreForEvidence(evidence),
    layers: evidence.map(e => e.layer).filter(Boolean).join('+'),
    evidence,
    tab_id: 0,  // SW 拿不到 sender.tab.id（已回收），先记录为 0
  };
  try {
    const r = await fetch(ALERT_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!r.ok) throw new Error('http ' + r.status);
    // 成功后顺便 flush 一次离线队列
    flushAlertQueue().catch(() => {});
    return true;
  } catch (_) {
    await enqueueAlert(payload);
    return false;
  }
}

async function enqueueAlert(payload) {
  try {
    const stored = await chrome.storage.local.get(['alert_queue']);
    const queue = Array.isArray(stored.alert_queue) ? stored.alert_queue : [];
    queue.push(payload);
    // 超过上限：丢最早的（保留最近事件）
    while (queue.length > ALERT_QUEUE_MAX) queue.shift();
    await chrome.storage.local.set({ alert_queue: queue });
  } catch (_) {}
}

async function flushAlertQueue() {
  let stored;
  try {
    stored = await chrome.storage.local.get(['alert_queue']);
  } catch (_) {
    return;
  }
  const queue = Array.isArray(stored.alert_queue) ? stored.alert_queue : [];
  if (!queue.length) return;
  const stillPending = [];
  for (const p of queue) {
    try {
      const r = await fetch(ALERT_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(p),
      });
      if (!r.ok) stillPending.push(p);
    } catch (_) {
      stillPending.push(p);
    }
  }
  try {
    await chrome.storage.local.set({ alert_queue: stillPending });
  } catch (_) {}
}

async function alertQueueSize() {
  try {
    const stored = await chrome.storage.local.get(['alert_queue']);
    return Array.isArray(stored.alert_queue) ? stored.alert_queue.length : 0;
  } catch (_) {
    return 0;
  }
}

// ===========================================================================
// 导航拦截
// ===========================================================================

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const url = details.url;
  if (!url) return;
  if (url.startsWith(SELF_PREFIX)) return;                     // 自己的拦截页，避免循环
  if (/^(chrome|edge|about|devtools|extension|moz-extension):/i.test(url)) return;

  let result;
  try {
    result = await evaluate(url);
  } catch (e) {
    console.warn('[PC Guardian] evaluate failed', e?.message || e);
    return;
  }

  if (result.decision === 'block') {
    const redirectUrl = chrome.runtime.getURL('blocked.html')
      + '?url=' + encodeURIComponent(url)
      + '&ev=' + encodeURIComponent(JSON.stringify(result.evidence));
    try {
      await chrome.tabs.update(details.tabId, { url: redirectUrl });
    } catch (e) {
      console.warn('[PC Guardian] tabs.update failed', e?.message || e);
    }
    blockAndCache(url, result.evidence);
    console.log('[PC Guardian] BLOCKED', url, result.evidence.map(e => e.layer).join('+'));
  }
});

// ===========================================================================
// 下载钩子（P1：仅记录）
// ===========================================================================

chrome.downloads.onChanged.addListener(async (delta) => {
  if (!delta.state || delta.state.current !== 'complete') return;
  try {
    const [info] = await chrome.downloads.search({ id: delta.id });
    if (!info || !info.finalUrl) return;
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
  const enc = new TextEncoder().encode(url);
  const buf = await crypto.subtle.digest('SHA-256', enc);
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ===========================================================================
// 消息接口
// ===========================================================================

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.type === 'evaluate_url') {
    evaluate(msg.url).then(sendResponse).catch(() => sendResponse({ decision: 'allow', evidence: [] }));
    return true;
  }
  if (msg?.type === 'reload_config') {
    hydrate().then(() => sendResponse({ ok: true }));
    return true;
  }
  if (msg?.type === 'sandbox_events') {
    SANDBOX_EVENTS += (msg.items || []).length;   // P1 仅观测
    sendResponse({ ok: true, total: SANDBOX_EVENTS });
    return false;
  }
  if (msg?.type === 'get_stats') {
    alertQueueSize().then((q) => {
        sendResponse({
          build: SW_BUILD,
          mal_cache_size: MAL_CACHE.size,
          whitelist_size: CONFIG.whitelist.size,
          grayscale_size: CONFIG.grayscale.size,
          sandbox_events: SANDBOX_EVENTS,
          alert_queue_size: q,
        });
      });
    return true;
  }
  if (msg?.type === 'ping') {
    sendResponse({ ok: true, build: SW_BUILD });
    return false;
  }
});
