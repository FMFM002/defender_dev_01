# PC Guardian Edge 扩展

Manifest V3 浏览器侧防线。

## 加载方式（开发期）

1. 打开 Edge：`edge://extensions/`
2. 左下角打开「开发人员模式」
3. 点击「加载解压缩的扩展」→ 选择本目录（包含 `manifest.json` 的目录）
4. 加载成功后，工具栏出现绿色盾牌图标

> 若 Edge 提示"清单文件缺失或不可读"之类错误，通常是 `manifest.json` 里引用的文件不存在。
> 本目录已包含全部依赖（`icons/`、`blocked.js`、`options.js`、`config/`），可直接加载。

## 加载方式（生产期）

待 P2：打包为 `.crx` 或使用 Edge 策略键 `ExtensionInstallForcelist`。

## 目录说明

- `manifest.json` — 扩展清单（MV3）
- `background.js` — Service Worker。白名单加载、URL 决策、云查、动态规则、下载钩子、拦截跳转
- `content_script.js` — 每个页面注入。观测可疑 `eval` / 外链脚本 / iframe 注入（沙查层，仅上报计数）
- `blocked.html` + `blocked.js` — 拦截页（紧凑 + 点详情展开）。**注意：MV3 扩展页面禁止内联脚本，JS 必须独立成文件**
- `options.html` + `options.js` — 白名单 / 灰名单管理页
- `icons/` — 16 / 48 / 128 图标
- `config/default_whitelist.json` — 默认白名单（35 个通用域名）+ 灰名单（19 条）+ 启发式规则

## 决策流程（每次导航）

```
URL  →  白名单（默认 ∪ 用户）? → 是 → 放行（静默）
      ↓ 否
     灰查 (灰名单 + 启发式)  ← 纯本地，毫秒级
      ↓ 有命中 → 立即拦截 → 跳 blocked.html（网页内展示证据）
      ↓ 无命中
     云查 (本地后端 /intel/url，限时 2s；超时即放行)
      ↓ 命中 → 拦截 → 跳 blocked.html
      ↓ 三层全无异常
     放行（完全静默）
```

> **白名单=默认 ∪ 用户**：内置默认白名单（百度/GitHub/知乎等）始终生效，用户白名单从本地后端合并进来，二者不会互相覆盖。

> **重要（MV3 生命周期）**：Service Worker 空闲约 30 秒会被浏览器回收，重新唤醒时 `onInstalled/onStartup`
> **不会**再次触发。因此白名单 / 灰名单 / 启发式的默认值必须写成 `background.js` 的**模块级常量**，
> 不能只放在 `init()` 里异步加载 —— 否则 SW 重启后名单为空，扩展将"完全不拦截"。

## 启发式规则（灰查层）

| 规则 | 说明 | 误报风险 |
|---|---|---|
| `block_port` | 访问危险端口（22/3389/4444/5900/6667） | 低 |
| `long_url` | URL 长度 > 350 | 低 |
| `suspicious_tld` | 高危 TLD（.tk/.top/.xyz/.click/.ml/.ga/.cf/.gq） | 中 |
| `deep_subdomain` | 子域层级 > 5 | 低 |
| `punycode_host` | 主机名含 `xn--`（同形字钓鱼） | 低 |
| `raw_ip_host` | 直接用裸 IP 访问 | 低 |

> **已停用** `suspicious_keywords_url`（login/account/update 等词）：这类词在正常网址路径中极其常见，
> 启用会误拦大量正常站点。如需启用，应只针对主机名并使用更具体的钓鱼特征。

## 告警呈现

**不使用系统通知弹窗**（已移除 `chrome.notifications` 与 `notifications` 权限）。
命中后直接把当前标签页重定向到扩展内置的 `blocked.html`，并附带该次拦截的完整证据。
页面上点「查看异常证据」展开，逐条显示"哪一层命中了哪条规则"。

例（展开后）：
```
云查（威胁情报）: phishing_domain（来源: blocklist）（评分: 70）
灰查（已知可疑名单）: bit.ly  命中灰名单：bit.ly
启发式（URL 异常特征）: suspicious_tld  suspicious_tld：高风险 TLD .tk
```

## 已知限制

- 仅支持 Edge（Manifest V3 完整支持）
- 后台服务必须运行在 `127.0.0.1:7890`，否则云查 / 白名单同步不可用（此时扩展仍按默认白名单+启发式工作）
- **沙查层（content_script）P1 仅观测计数，不参与拦截**：正常页面也会大量注入外链脚本/iframe，直接当异常会误拦几乎所有网站；待 P2 用更精确的行为规则后再纳入决策
- 首次访问某恶意站点时，重定向存在极短竞态（网络查询耗时），重复访问由动态规则硬阻断
