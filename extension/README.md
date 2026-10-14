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
- `background.js` — Service Worker。白名单加载、URL 决策、云查、动态规则、下载钩子、弹窗
- `content_script.js` — 每个页面注入。观测可疑 `eval` / 外链脚本 / iframe 注入（沙查层，仅上报计数）
- `blocked.html` + `blocked.js` — 拦截页（紧凑 + 点详情展开）。**注意：MV3 扩展页面禁止内联脚本，JS 必须独立成文件**
- `options.html` + `options.js` — 白名单 / 灰名单管理页
- `icons/` — 16 / 48 / 128 图标（通知弹窗也用它）
- `config/default_whitelist.json` — 默认白名单（35 个通用域名）+ 灰名单（19 条）+ 启发式规则

## 决策流程（每次导航）

```
URL  →  白名单（默认 ∪ 用户）? → 是 → 放行（静默）
      ↓ 否
     云查 (URLhaus，经本地后端)
      ↓
     灰查 (灰名单 + 启发式)
      ↓
     ── 任一层有异常证据 → 拦截 + 跳 blocked.html + chrome.notifications 弹窗
      ↓ 三层全无异常
     放行（完全静默）
```

> **白名单=默认 ∪ 用户**：内置默认白名单（百度/GitHub/知乎等）始终生效，用户白名单从本地后端合并进来，二者不会互相覆盖。

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

## 弹窗内容

每条弹窗都写明"哪一层命中了哪条规则"（异常证据），拦截页可点开查看详情。

例：
```
PC Guardian 已拦截可疑访问
异常证据：
  cloud:malware_download（来源: urlhaus）(评分: 80)
  heuristic:suspicious_tld  TLD .tk
```

## 已知限制

- 仅支持 Edge（Manifest V3 完整支持）
- 后台服务必须运行在 `127.0.0.1:7890`，否则云查 / 白名单同步不可用（此时扩展仍按默认白名单+启发式工作）
- **沙查层（content_script）P1 仅观测计数，不参与拦截**：正常页面也会大量注入外链脚本/iframe，直接当异常会误拦几乎所有网站；待 P2 用更精确的行为规则后再纳入决策
- 首次访问某恶意站点时，重定向存在极短竞态（网络查询耗时），重复访问由动态规则硬阻断
