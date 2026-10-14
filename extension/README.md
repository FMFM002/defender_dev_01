# PC Guardian Edge 扩展

Manifest V3 浏览器侧防线。

## 加载方式（开发期）

1. 打开 Edge：`edge://extensions/`
2. 右下角打开"开发人员模式"
4. 点击"加载解压缩的扩展" → 选择本目录（包含 `manifest.json` 的目录）
5. 加载成功后，工具栏出现图标

## 加载方式（生产期）

待 P2：打包为 `.crx` 或使用 Edge 策略键 `ExtensionInstallForcelist`。

## 目录说明

- `background.js` — Service Worker。负责白名单加载、URL 决策、云查、动态规则生成、下载钩子
- `content_script.js` — 每个页面注入。监控可疑 `eval` / 外链脚本 / iframe 注入
- `blocked.html` — 拦截页（紧凑 + 点详情展开）
- `options.html` — 白名单 / 灰名单管理页
- `config/default_whitelist.json` — 默认白名单（35 个通用域名）+ 灰名单 + 启发式规则

## 决策流程（每次导航）

```
URL  →  白名单? → 是 → 放行
      ↓ 否
     云查 (URLhaus)
      ↓ 任一异常?
     灰查 (灰名单 + 启发式)
      ↓ 任一异常?
     沙查 (content_script 上报的事件)
      ↓ 任一异常?
     ── 拦截 + 跳 blocked.html  + chrome.notifications 弹窗
      ↓ 全无异常
     放行
```

## 弹窗内容

每条弹窗都会写明：哪一层命中了哪条规则（异常证据），用户可点击查看详情。

例：`PC Guardian 已拦截可疑访问 — 命中防护规则`
    `异常证据：`
    `cloud:malware_download`
    `heuristic:suspicious_tld: TLD .tk`

## 已知限制

- 仅支持 Edge（Manifest V3 完整支持）
- 后台服务必须运行在 `127.0.0.1:7890`，否则云查/白名单同步不可用
- WMI/ETW 进程告警需管理员权限（不影响 URL 拦截）