# PC Guardian — 本地电脑防护系统

> 基于《项目构建指南.txt》的实现。
> 目标：在不干扰正常使用的前提下，防止个人信息被盗取和电脑被病毒感染。

## 设计原则

- **确定性优先**：规则层做决策，LLM 只处理灰区
- **用户可审计**：每条拦截都有完整证据链
- **先拦后放**：默认拦截，用户手动放行
- **分层防御**：任何单一层被绕过，其他层仍能兜底
- **零日常操作**：一次安装授权，之后完全静默运行（仅命中规则时在**网页内**展示拦截页）

## 架构

```
┌─ 用户层：安装时点两次"同意"，之后静默
├─ Edge 扩展（MV3 主防线）：白名单 + 灰名单 + 启发式 + declarativeNetRequest 动态规则 + 拦截页
├─ 本地后台服务（数据中枢）：FastAPI 端口 7890
│   ├─ 威胁情报聚合：本地域名黑名单（Phishing Army，免 Key）+ URLhaus（可选，需 Auth-Key）+ sec-mcp
│   ├─ **文件监控 fsmon（P2-1）**：5 个用户态关键目录轮询 → MalwareBazaar 云查 + 文件启发式 → ≥70 自动隔离
│   ├─ 文件哈希云查：MalwareBazaar（abuse.ch Key，与 URLhaus 通用）
│   ├─ 隔离区管理（开发期复制 + 保留原文件，30 天后自动清理）
│   ├─ WMI/ETW 进程监控（高风险父进程 + 危险命令行 + 投放路径）
│   ├─ ASR 规则写入（独立工具，需管理员）
│   └─ 用户白名单 / 灰名单
└─ 系统基础防护：Windows Defender ASR 规则（HKLM 注册表策略）
```

## 告警触发规则（用户硬性要求）

| 层 | 触发条件 | 证据来源 |
|---|---|---|
| 云查 | 本地域名黑名单命中（Phishing Army）/ URLhaus 返回 malicious=True | 命中域名 / 评分 ≥ 50 |
| 灰查 | 灰名单（*.tk / 短链 等）+ 启发式（TLD/端口/裸IP/punycode/URL过长） | 命中规则名 + 详情 |
| 沙查 | 父进程浏览器/Office/脚本宿主 + 命令行含 `-enc` / `certutil -decode` 等 + 路径在 %TEMP% 等 | 命中规则名 + 详情 |

**任一项异常 → 拦截，并在网页内展示拦截页（写明异常证据）。三层全部无异常 → 完全静默。**

> 告警呈现方式：**不使用系统通知弹窗**，命中后直接把当前标签页重定向到扩展内置拦截页，
> 证据在同一页展开（点击「查看异常证据」）。本地规则命中为毫秒级、零网络等待。

## 目录结构

```
电脑防毒/
├── 项目构建指南.txt          # 用户原始需求
├── .workbuddy/memory/        # 项目记忆
├── src/
│   └── guardian/             # 本地后台服务（Python）
│       ├── core/             # config / logger / memguard / db / proxy
│       ├── intel/            # 本地域名黑名单 + URLhaus + sec-mcp + aggregator
│       ├── monitor/          # WMI/ETW 进程监控
│       ├── asr/              # ASR 规则注册表写入
│       ├── quarantine/       # 隔离区管理
│       ├── tools/            # 独立工具（ASR 启用）
│       ├── api/              # FastAPI HTTP 接口
│       └── main.py           # 启动入口
├── extension/                # Edge 扩展（Manifest V3）
│   ├── manifest.json
│   ├── background.js         # Service Worker（评估 + 决策）
│   ├── content_script.js     # 沙查层（页面行为监控）
│   ├── blocked.html/.js      # 拦截页（紧凑 + 详情展开）
│   ├── options.html/.js      # 白名单 / 灰名单管理
│   ├── icons/                # 扩展图标（16/48/128）
│   └── config/
│       └── default_whitelist.json
├── scripts/
│   ├── start.bat             # 双击启动本地服务
│   ├── stop.bat              # 双击停止服务（释放 7890 端口）
│   └── apply_asr.bat         # 双击运行（自动提权）启用 P1 ASR 规则
├── config/
│   └── default_whitelist.json
├── data/                     # 运行时（不入 git）
│   ├── db/guardian.db
│   ├── blocklist/phishing_army.txt
│   ├── logs/guardian-YYYY-MM-DD.log
│   └── quarantine/
└── tests/
```

## 关键决策（2026-10-14 与用户确认）

- **浏览器覆盖**：仅 Edge（Manifest V3）
- **威胁情报**：本地域名黑名单（Phishing Army，免 Key 免费）为主；URLhaus 因 abuse.ch 2025-06-30 起强制 Auth-Key，改为**可选**（在项目根目录 `.env` 写 `URLHAUS_AUTH_KEY=...` 后启用，未配置则静默跳过）
- **LLM 裁决**：可选项，默认不启用
- **拦截深度**：ASR 注册表规则 + WMI/ETW 进程监控
- **运行方式**：开发期直接跑 Python
- **拦截严格度**：命中任一异常证据即拦截（白名单直放，其余默认放行，避免误伤正常上网）
- **数据存放**：全在工作区文件夹内
- **隔离区**：用户可手动还原 + 30 天后自动清理
- **默认白名单**：内置一份通用可信域名列表（35 个）
- **告警方式**：**不使用系统通知**，命中后在网页内展示拦截页（必带证据）；三层全无异常 = 完全静默
- **VPN**：SakuraCat-VPN，端口 7897（SOCKS5+HTTP），代码主动探测代理是否可用
- **日志**：全量进文件，按天切 30 天
- **低内存硬指标**：RSS idle ≤ 80 MB / peak ≤ 150 MB

## 参考项目

- [uBlock Origin](https://github.com/gorhill/uBlock) + [uAssets](https://github.com/uBlockOrigin/uAssets) - declarativeNetRequest 标准答案
- [MDE_Enum](https://github.com/0xsp-SRD/MDE_Enum) - ASR Rule GUID 完整列表
- [usn-parser-rs](https://github.com/wangfu91/usn-parser-rs) - NTFS USN Journal 参考
- [WatchFS](https://github.com/berki6/WatchFS) - Python ETW 实践
- [PlanqX_EDR](https://github.com/h4vox/PlanqX_EDR) - 分层 EDR 架构

## 启动方式

### 后台服务

**方式一（推荐）**：双击 `scripts\start.bat` 启动；停止双击 `scripts\stop.bat`。

**方式二**：命令行
```bash
# 用 venv 的 Python 跑（依赖齐全）
"C:\Users\farma\.workbuddy\binaries\python\envs\pc-guardian\Scripts\python.exe" \
    -m src.guardian.main
```

> 端口冲突时：服务会提示占用进程的 PID，或双击 `scripts\stop.bat` 一键清理。

> **双击 `.bat` 闪退、看不到报错？** 批处理脚本必须使用 Windows 原生格式（CRLF 换行 + ASCII 内容）。
> 本仓库的 `start.bat` / `stop.bat` / `apply_asr.bat` 已统一为该格式，并在出错时自动 `pause` 停留以便查看原因。
> 若自行改动，请保持 CRLF 换行、不要写入非 ASCII 字符（否则 cmd 会按 GBK 误解析导致乱码报错）。

### Edge 扩展
1. 打开 `edge://extensions/`
2. 打开"开发者模式"
3. 点"加载解压缩的扩展"→ 选择本项目 `extension/` 目录
4. **改过扩展代码后**：回到 `edge://extensions/`，点扩展卡片上的**"重新加载"**（⟳）。
   Edge 不会自动热更新，不点这一步跑的还是旧代码。
5. **验证是否加载成功**：点扩展的"扩展选项"，页首"安装自检"会显示**构建号**和四条测试用例的实际判定。
   若自检里出现 ✗，说明 ①构建号不是最新（没点重新加载），或 ②本地后端没启动（先双击 `scripts\start.bat`）。

### ASR 规则（需管理员）
- 双击 `scripts\apply_asr.bat`（自动请求管理员权限）
- 或手动：`python -m src.guardian.tools.apply_asr --p1`

## API 端点

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/health` | 健康检查 + RSS |
| POST | `/intel/url` | URL 云查 + 缓存 |
| POST | `/intel/hash` | 文件哈希云查 + 缓存 |
| GET | `/intel/status` | 威胁情报状态（本地黑名单条数 + URLhaus Key/云查状态） |
| GET | `/whitelist` | 列出白名单 |
| POST | `/whitelist` | 添加白名单 |
| DELETE | `/whitelist/{pattern}` | 移除白名单 |
| POST | `/whitelist/match` | 检查 URL 是否命中白名单 |
| GET | `/quarantine` | 列出隔离区 |
| POST | `/quarantine` | 隔离文件 `{path, reason}` |
| POST | `/quarantine/{id}/restore` | 恢复 |
| DELETE | `/quarantine/{id}` | 彻底删除 |
| GET | `/asr/rules` | 列出 ASR 规则 + 当前状态 |
| GET | `/proc_alerts?limit=N` | 最近进程告警 |
| GET | `/intel/blocklist/status` | 本地域名黑名单状态（条数 / 上次刷新） |
| POST | `/intel/blocklist/refresh` | 立即刷新本地域名黑名单 |
| POST | `/system/check_file` | 同步评分单个文件 + 自动隔离（与 fsmon.feed 同款） |
| GET | `/system/fsmon/status` | 文件监控状态（启动 / 监控目录数 / worker 数 / 队列 / 阈值） |
| POST | `/system/fsmon/feed` | 手动注入文件路径（测试 / 扩展调用） |

## 文件监控 P2-1 评分规则

| 维度 | 加分 | 备注 |
|---|---|---|
| 可执行后缀 (.exe/.bat/.ps1/.vbs/.js/.lnk/.msi/.com 等 24 类) | +30 | 落地文件后缀 |
| 文件名含可疑关键词 (crack/keygen/patch/installer/setup/activator/loader 等 11 词) | +20 | 落地文件名 |
| 无数字签名（仅对可执行类检查） | +20 | `WinVerifyTrust` |
| 来源目录落入 Startup 启动项 | +30 | 持久化意图 |
| 来源目录落入 %TEMP% | +15 | 解压/脚本中转 |
| 来源目录落入 Desktop | +10 | 钓鱼诱导 |
| 来源目录落入 Downloads | +5 | 浏览器落地 |
| 来源目录落入 AppData\Local（**非已知厂商子目录**）| +5 | 厂商目录已豁免 |
| 大文件（>100MB） | -5 | 多为合法安装包 |
| **EICAR 标准测试串**命中（文件内容嗅探） | +50 | 业内公认测试样本 |
| MalwareBazaar 云查命中 | +80 | abuse.ch 数据库 |

**阈值 ≥ 70 自动移入 `data/quarantine/`** 并写 SQLite。可疑但未达阈值的放行，只记录哈希缓存。

### 安装行为豁免

5 秒滑动窗口内同一目录新增 ≥ 3 个可执行后缀文件 → 标记为"安装噪声"，**单文件仍走评分但日志聚合**。
合法安装包（如 `%LOCALAPPDATA%\Programs\xxx\`）会被 `NOISY_VENDOR_DIRS`（Microsoft/Google/VSCode/Discord/Spotify/Steam/NVIDIA/JetBrains/Docker/Python/nodejs 等）**完全豁免**——监控器对其内新文件 0 开销。

## 测试方法（真机验收）

后端与扩展都启动后，逐个尝试下列 URL，观察是否出现**拦截页**（在同一标签内，不走系统通知）：

| 访问 | 预期 | 命中的层 |
|---|---|---|
| `https://www.baidu.com/` | 正常打开 | 白名单 |
| `http://bit.ly/abc123` | 拦截页 | 灰查（短链灰名单） |
| `http://anything.tk/` | 拦截页 | 灰查（高风险 TLD） |
| `http://1.2.3.4/` | 拦截页 | 启发式（裸 IP 主机） |
| 任意 Phishing Army 黑名单域名 | 拦截页 | 云查（本地域名黑名单） |

> 🔎 **URLhaus 云查（已启用）**：Key 已写入 `.env` 并**实测有效**，可识别"活跃恶意软件分发 URL"
> （例如 Mozi 僵尸网络的下载点 `http://<ip>:<port>/bin.sh`）。测试时从 https://urlhaus.abuse.ch/browse/
> 取一条当前在线 URL 访问即可命中。注意 `malware.wicar.org` 本身不在 URLhaus 库里（返回 `no_results`），
> 不适用作验证样本。
>
> **状态一眼可见**：设置页点「运行自检」会多显示两行——
> `本地黑名单：159508 条 ✓` 与 `URLhaus 云查：✓ 已启用（Key 有效）`；
> 若 Key 无效则显示 `✗ Key 无效（unknown_auth_key）`。后端对应 `GET /intel/status`。
>
> **常见坑**：abuse.ch 返回 `{"query_status":"unknown_auth_key"}` 表示 Key 无效/写错/生成时未点 Save profile。
> 服务日志会给出明确提示，但**不影响**本地黑名单与启发式的拦截。

### 启用 URLhaus（可选）

在项目根目录新建 `.env`（可复制 `.env.example`），写入一行后**重启服务**：

```
URLHAUS_AUTH_KEY=你的Auth-Key
```

- 申请：https://auth.abuse.ch/ 登录 → 个人资料(Profile) 的 **Optional** 区域点 **Generate Key** → 复制完整 Key。
- `.env` 已在 `.gitignore` 中，不会被提交。
- 也可用系统环境变量 `URLHAUS_AUTH_KEY`（优先级高于 `.env`）。

## 状态

**P2-1 阶段完成**（自动文件隔离）：

✅ **MalwareBazaar 文件哈希云查**（复用 abuse.ch Key，与 URLhaus 通用）  
✅ **文件启发式评分**（可执行后缀 + 文件名关键词 + 来源目录 + 数字签名 + EICAR 标准串嗅探）  
✅ **ReadDirectoryChangesW 风格的文件监控 fsmon**（5 个用户态关键目录轮询，1s 粒度，可忽略系统/厂商子目录）  
✅ **自动隔离链路**（评分 ≥70 → 复制到 `data/quarantine/<ts>_<sha16>_<name>` + 写 SQLite）  
✅ **安装行为豁免**（5s 内同目录 ≥3 个可执行后缀 → 聚合日志但单文件仍评）  
✅ **API 扩展**：`POST /system/check_file`、`GET /system/fsmon/status`、`POST /system/fsmon/feed`  
✅ **还原/彻底删除** 端到端实测通过  
✅ 端到端实测：用 `kms_auto.exe` / `photoshop_crack_setup.exe` 落到 Downloads 静默击中，score=70~75 自动 quarantine

**P1 阶段完成**：

✅ 后台服务（FastAPI，16 个端点）  
✅ Edge MV3 扩展（manifest / SW / content script / 拦截页 / 设置页）  
✅ 默认白名单（35 个通用域名）+ 灰名单 + 启发式  
✅ 本地域名黑名单（Phishing Army，约 16 万条，免 Key，24h 自动刷新）  
✅ URLhaus 集成（Auth-Key 已写入 `.env` 并实测有效 + 代理感知 + 24h 缓存）  
✅ WMI 进程监控（高风险父进程 / 命令行 / 投放路径）  
✅ ASR 规则管理（独立工具 + 自动提权 bat）  
✅ 用户白名单 + 隔离区  
✅ 内存守护（idle ≤ 80 / peak ≤ 150）

**P1 修复记录（2026-10-14 真机验收）**：

- **扩展完全不拦截** → 根因：MV3 Service Worker 空闲被回收后重新唤醒时 `onInstalled/onStartup` 不再触发，
  而白/灰名单只在 `init()` 中异步加载 → SW 重启后名单为空。已改为**模块级常量内联**，唤醒即生效。
- **告警方式** → 去掉 `chrome.notifications`（系统通知），改为**网页内拦截页**（用户要求）。
- **URLhaus 全部 401** → abuse.ch 2025-06-30 起强制 Auth-Key。已支持可选 Auth-Key，并新增免 Key 的
  本地域名黑名单源（Phishing Army）。
- **拦截页按钮点不动** → MV3 CSP 禁止 `javascript:` 链接与内联脚本，已改为独立 `blocked.js` 事件绑定。

**v0.2.0 更新（2026-10-14 下午）**：

- **URLhaus Auth-Key 持久化** → 新增项目根目录 `.env` 加载（`config.py` 自动读取），
  Key 不再依赖临时环境变量；`.env` 已加入 `.gitignore`。Key 被 abuse.ch 拒绝时（`unknown_auth_key`）
  会给出明确的一次性警告日志。
- **扩展"自检"** → 设置页页首新增安装自检：显示 Service Worker **构建号**、白/灰名单条数、
  后端连通性，并对 4 条测试 URL 跑真实决策，逐条给出 ✓/✗。用于一眼判断"是否加载了新代码"。
  （背景：多次出现"改了代码但 `edge://extensions` 没点重新加载 → 跑的还是旧 SW"。）
- **名单覆盖防御** → `hydrate()` 合并后若结果为空则**保留内置默认值**，杜绝早期"名单被清空 → 完全不拦截"复现。
- **进程误报修复** → Edge 正常派生的 `identity_helper.exe` 等官方 helper 不再告警；
  新增"可执行文件是否位于��览器官方安装目录"判定，比进程名白名单更稳。恶意程序从浏览器目录外落地仍然告警。

**v0.2.1 更新（2026-10-14 16:10）**：

- **URLhaus 云查打通** → 用户重新生成的有效 Auth-Key 已写入 `.env`；实测
  `http://<ip>:<port>/bin.sh`（Mozi）经聚合器判为 `malicious=true / malware_download / 评分 80`。
- **威胁情报状态可见** → 后端新增 `GET /intel/status`（本地黑名单条数 + URLhaus 配置/最近状态）；
  扩展自检面板新增两行：`本地黑名单：N 条` 与 `URLhaus 云查：✓ 已启用 / ✗ Key 无效 / ✗ 未配置`。
  新增 `urlhaus.status()` 记录最近一次云查的可观测状态（disabled / valid / invalid / unreachable）。
- **URLhaus 启动探针** → 服务启动时后台对 URLhaus 做一次无害探针（查询 `example.com`），
  让自检面板**无需先访问网页**即可显示 `URLhaus 云查 ✓ 已启用`（否则首次查询前一直显示"待验证"）。

**P2 计划**：

- ETW 原生订阅（pyetwkit）
- 文件哈希接 VirusTotal
- USN Journal 持久化文件监控
- 开机自启 + 单实例锁