// PC Guardian — Content Script
// 运行在 document_start，监控页面里的可疑 JS 行为（沙查层）。
// 仅做轻量监控，不影响页面正常运行。

(function () {
  'use strict';

  const REPORT_INTERVAL_MS = 1500;
  const SUSPICIOUS_PATTERNS = [
    /eval\s*\(/,
    /Function\s*\(\s*['"][^'"]+['"]\s*\)/,
    /document\.write\s*\(/,
    /setTimeout\s*\(\s*['"][^'"]+['"]\s*,\s*\d+\s*\)/,
    /atob\s*\(\s*['"][A-Za-z0-9+/=]{200,}['"]\s*\)/,
  ];

  let pending = [];

  function report(kind, evidence) {
    pending.push({ kind, evidence, url: location.href, ts: Date.now() });
  }

  // 拦截可疑 JS 模式（仅观察，不阻断——阻断会让页面崩溃）
  const origEval = window.eval;
  window.eval = function (...args) {
    if (typeof args[0] === 'string' && SUSPICIOUS_PATTERNS.some(p => p.test(args[0]))) {
      report('eval_suspicious', args[0].slice(0, 200));
    }
    return origEval.apply(this, args);
  };

  // 监控动态 script 注入
  const obs = new MutationObserver((muts) => {
    for (const m of muts) {
      m.addedNodes.forEach((n) => {
        if (n.tagName === 'SCRIPT' && n.src) {
          // 外链脚本
          if (/^https?:\/\//.test(n.src) && !n.src.startsWith(location.origin)) {
            report('external_script', n.src);
          }
        }
        if (n.tagName === 'IFRAME' && n.src) {
          report('iframe_inject', n.src);
        }
      });
    }
  });
  obs.observe(document.documentElement || document, { childList: true, subtree: true });

  // 周期性上报（不阻塞，失败丢弃）
  setInterval(() => {
    if (!pending.length) return;
    const batch = pending.splice(0, pending.length);
    try {
      chrome.runtime.sendMessage({ type: 'sandbox_events', items: batch });
    } catch (_) {}
  }, REPORT_INTERVAL_MS);

  // 暴露调试钩子（开发期）
  window.__logger_test = () => pending.length;
})();