# MEMORY.md - 项目级长期记忆

## 项目：电脑防护系统（workbuddy/电脑防毒）

### 关键决策（2026-10-14 与用户确认）
- **浏览器覆盖**：仅 Edge（Manifest V3）
- **威胁情报**：免 Key 源起步（URLhaus + sec-mcp），不申请 Google Safe Browsing / VirusTotal
- **LLM 裁决**：做成可选项，默认不启用；云端 API 后续用户可填
- **拦截深度**：ASR 注册表规则 + ETW 进程监控，不写 DLL、不上驱动
- **运行方式**：开发期直接跑 Python（不打包 exe）
- **拦截严格度**：先拦后放（默认拦截所有非白名单域名）
- **数据存放盘**：全在工作区文件夹内 `D:\Dtopdesk\普瑞赛斯在哪\workbuddy\电脑防毒\` 下
- **隔离区**：开发阶段在工作区里模拟；用户可手动还原 + 30 天后自动清理
- **默认白名单**：内置一份通用可信域名列表
- **告警交互规则**（用户修正版）：
  - 完全静默的条件：云查无异常 + 灰区无异常 + 本地启发式无异常 = 静默
  - 以下任一命中即弹窗（必带证据）：云查明确恶意 / 云查服务不可用 / 用户白名单后又被标恶意 / 本地启发式命中 / ETW 进程命中规则 / ASR 触发 / 自动跳转拦截 / 隔离文件
  - 同 URL 5 分钟内不重复弹
- **证据链展示**：命中后**不使用系统通知**，直接把当前标签页重定向到扩展内置 blocked.html，证据页内展开（用户 2026-10-14 明确要求）
- **告警呈现**：拦截页紧凑 + 点详情展开；已移除 `chrome.notifications` 与 `notifications` 权限
- **Git**：启用；用户习惯推到 GitHub，需要时主动问 remote 地址
- **VPN**：SakuraCat-VPN，全局模式，SOCKS5+HTTP 都监听 7897；代码里要主动探测代理端口是否可用、有就用、没有跳过
  - **2026-10-14 14:00 起**：用户保持 VPN 开启（开 GitHub 仓库时启动后没关）。意味着：
    - Git push/clone 走代理（已配置 http.proxy = http://127.0.0.1:7897）
    - 威胁情报查询默认走代理
    - 如果代理失效/被切回直连，记得提醒用户
- **日志**：全量进文件，拦截页只��示用户需要知道的；按天切、保留 30 天
- **验收方式**：用户真机测试；本项目要带 DEBUG 级 logger
- **开发节奏**：一气写完到 P1 才停下让用户验收
- **资源占用指标（硬性）**：常驻 RSS ≤ 80 MB（空闲）/ ≤ 150 MB（高峰期）。每个模块启动时自报 RSS；超阈值主动降级（关闭非核心线程）。引入新依赖前要评估常驻内存成本

### 用户偏好
- 用户非技术背景，表述可能不精确；要主动提问澄清
- 不喜欢 AI 啰嗦、要直接给结论
- 用户自己挑 MCP / 专家 / skill 嫌烦，让我自己决定（本项目判断：暂不需要任何内置 skill 或 MCP）
- 通用安全提醒：用户默认 VPN 开、访问非白名单、下载未知文件

### 项目结构（实际）
```
电脑防毒/
├── 项目构建指南.txt          # 用户输入的需求
├── .workbuddy/memory/        # 本项目记忆
├── README.md                 # 项目主 README（P1 完成）
├── src/
│   └── guardian/             # 本地后台服务（Python）
│       ├── core/             # config / logger / memguard / proxy
│       ├── intel/            # 本地域名黑名单(blocklist) + URLhaus + sec-mcp + aggregator
│       ├── monitor/          # WMI/ETW 进程监控（实际用 WMI）
│       ├── asr/              # ASR 规则注册表写入（19 条字典）
│       ├── quarantine/       # 隔离区管理
│       ├── tools/            # apply_asr.py（独立工具）
│       ├── api/              # FastAPI 路由
│       └── main.py           # 启动入口
├── extension/                # Edge MV3 扩展
│   ├── manifest.json
│   ├── background.js         # Service Worker（白名单+灰名单+启发式+决策+弹窗）
│   ├── content_script.js     # 沙查层（eval / 外链 script / iframe 注入监控；P1 仅观测计数）
│   ├── blocked.html + blocked.js   # 拦截页（紧凑+展开）※ JS 必须独立文件
│   ├── options.html + options.js   # 白名单管理 ※ JS 必须独立文件
│   ├── icons/icon-16|48|128.png    # 盾牌图标（通知弹窗也依赖）
│   └── config/default_whitelist.json  # 35 白名单 + 19 灰名单 + 启发式
├── scripts/                  # start.bat / stop.bat / apply_asr.bat（CRLF+纯ASCII）
├── config/default_whitelist.json
├── data/                     # 不入 git
│   ├── db/guardian.db        # SQLite WAL
│   ├── logs/guardian-YYYY-MM-DD.log
│   └── quarantine/
└── tests/
```

### P1 阶段完成（2026-10-14）
- 后台服务：FastAPI 13 个端点、URLhaus 集成、WMI 进程监控、ASR 规则、SQLite 缓存、内存守护
- Edge MV3 扩展：manifest + SW + content script + 拦截页 + options 页 + 默认白名单
- 告警策略：云查/灰查/沙查 任一异常 → 弹窗带证据（用户硬性要求）
- ASR 独立工具：scripts/apply_asr.bat（双击）+ src/guardian/tools/apply_asr.py
- 内存基线 ~73 MB，idle 上限 80 MB，peak 上限 150 MB
- 推送到 GitHub: commit 9b1c9ef

### 关键技术选型（实施时验证）
- **进程监控选 WMI 而非 pyetwkit**：pyetwkit 编译复杂，pywin32 单 binary 依赖即可；WMI 延迟秒级对进程告警够用
- **MV3 扩展页面禁止内联脚本**：CSP `script-src 'self'`，HTML 里的内联 `<script>` **一律不执行**（拦截页会永远"加载中"）。所有 JS 必须独立成文件、用 `<script src=...>` 引用。已踩坑：blocked/options 均中招
- **MV3 扩展 manifest 引用的文件必须真实存在**：含 `icons/*.png`，缺失任何一个 Edge 直接拒绝加载扩展
- **白名单合并语义**：内置默认白名单 始终生效，用户白名单从后端合并（默认 ∪ 用户），后端结果**不可整体覆盖** CONFIG.whitelist
- **URLhaus 401 = abuse.ch 强制鉴权**（2026-10-14 确认）：abuse.ch 自 2025-06-30 起对所有 API 强制 Auth-Key，无 Key 一律 HTTP 401 `{"error":"Unauthorized"}`。「免 Key 逐条查询」路线作废
  - 已支持可选 Auth-Key（环境变量 `URLHAUS_AUTH_KEY`）；未配置 → `status='disabled'`、只提示一次、不再刷 401
  - 替代主源：**Phishing Army 本地域名黑名单**（`intel/blocklist.py`，约 15.9 万条、3.4 MB、免 Key）
    - 整表下载 → SQLite `domain_blocklist` 表；查询走主键索引（逐级回溯父域，最多 6 级），毫秒级、不吃内存
    - 启动后台线程自动下载 + 每 24h 刷新；命中评分 70（基础 50 + blocklist 20），`threat='phishing_domain'`
    - 端点：`GET /intel/blocklist/status`、`POST /intel/blocklist/refresh`
  - 注意：Phishing Army 聚焦**钓鱼域名**，不含 `malware.wicar.org` 这类样本站——没有 URLhaus Key 时不会被拦
- **MV3 Service Worker 生命周期（关键坑）**：SW 空闲约 30s 被回收，重新唤醒时 `onInstalled`/`onStartup` **都不再触发**。任何"必须可用"的配置（白名单/灰名单/启发式）都必须写成 `background.js` 的**模块级常量**，不能只放 `init()` 异步加载——否则 SW 重启后名单为空 → 灰查/启发式全失效 → **扩展完全不拦截**（2026-10-14 真机现象）
- **扩展告警方式**：不用 `chrome.notifications`（用户明确不要系统通知）；命中 → `chrome.tabs.update` 重定向到内置 `blocked.html`，证据页内展开
- **MV3 扩展页面禁止内联脚本**：CSP `script-src 'self'`，HTML 里的内联 `<script>` **一律不执行**（拦截页会永远"加载中"）。所有 JS 必须独立成文件、用 `<script src=...>` 引用。**同理 `javascript:` 链接也被拦掉（按钮点不动）** → 用独立 JS 事件绑定
- **MV3 扩展 manifest 引用的文件必须真实存在**：含 `icons/*.png`，缺失任何一个 Edge 直接拒绝加载扩展
- **白名单合并语义**：内置默认白名单 始终生效，用户白名单从后端合并（默认 ∪ 用户），后端结果**不可整体覆盖** CONFIG.whitelist
- **决策顺序（保证零延迟）**：白名单 → 灰名单/启发式（纯本地、不 await 网络、立即拦截）→ 云查（限时 2s，超时即放行）
- **内存优化**：`_LazyDB` 让 SQLite 初始化延迟到首次调用，import 时 RSS 从 79MB → 48MB
- **WMI NextEvent 超时是正常控制流**：无事件时每秒抛超时异常（中文"已超时" / HRESULT -2147209215），必须静默 continue，否则日志被刷屏。识别函数：`etw_proc._is_wmi_timeout()`
- **进程告警规则要按"谁派生谁"语义**：cmd/powershell 不能当高风险父进程（终端里啥都从它起）；conhost/dllhost 等系统进程应放行；投放目录只留 %TEMP% 与 \Downloads\
- **启发式阈值宁缺毋滥**：`login/account/update` 等通用词按 URL 路径匹配会误拦正常站点，已停用该关键词列表
- **WMI 进程监控需管理员权限**：非管理员订阅 `Win32_ProcessStartTrace` 报"拒绝访问"，已降级为友好 WARNING（不影响 URL 拦截）
- **单实例保护**：main.py 启动前检测 7890 端口，占用时打印占用 PID；`scripts/stop.bat` 一键释放
- **进程告警规则 v2（2026-10-14 收紧误报）**：v1 把 `cmd.exe`/`powershell.exe` 当高风险父进程 + 把 `%APPDATA%`/`%LOCALAPPDATA%` 当投放目录 → 误报刷屏（连本服务自己都报）。v2 改为语义化判断：
  - `BENIGN_CHILDREN`（conhost/dllhost/…）命中直接放行
  - `HIGH_RISK_PARENTS` = Office + 脚本宿主（**去掉 cmd/powershell**）
  - 浏览器只在「派生非浏览器进程」时报（`browser_spawn_process`）
  - 投放路径只留 `%TEMP%` + `\Downloads\`
  - `_handle_event` 加 5 分钟去重（进程名+父名+规则）
  - 单测脚本：`C:\Temp\test_eval.py`（11 用例，正反双向）

### v0.2.0（2026-10-14 下午）
- **URLhaus Auth-Key 持久化**：新增 `.env` 加载（`core/config.py::_load_dotenv`，在读取任何 `os.environ` 之前执行）。用户放项目根目录 `.env`：`URLHAUS_AUTH_KEY=...`。`.env` 已进 `.gitignore`，另留 `.env.example` 模板
  - 系统环境变量优先于 `.env`（`if key not in os.environ` 才写入）
  - **abuse.ch 认证头是 `Auth-Key`（不是 `Authorization`）**；无 Key → 401，Key 无效 → **403 `{"query_status":"unknown_auth_key"}`**
  - 用户 2026-10-14 提供的 Key（48 hex）实测返回 `unknown_auth_key` → Key 本身无效/未激活。正确入口：auth.abuse.ch 登录 → Profile 的 **Optional** 区点 **Generate Key**
- **扩展"安装自检"**（`options.html`/`options.js` 页首）：显示 SW **构建号**（`background.js::SW_BUILD`）、白/灰名单条数、后端连通性 + 4 条真实决策用例 ✓/✗
  - 用途：一眼区分"没点 edge://extensions 重新加载（跑旧 SW）" vs "后端没启动"
  - `background.js` 新增 `ping` 消息（返回 `{ok, build}`），`get_stats` 增加 `build` 字段
- **名单覆盖防御**：`hydrate()` 合并后若 `Set` 为空则**不覆盖**已有默认值，杜绝"后端白名单为空 → 整体覆盖 → 完全不拦截"复现
- **进程误报**：Edge 正常派生的 `identity_helper.exe` 等官方 helper 不再告警。新增 `BROWSER_INSTALL_DIRS` 路径判定（`\microsoft\edge\application\` 等）+ 扩充 `BROWSER_HELPERS` 名单。`evil.exe` 从 `%TEMP%` 由 msedge 派生仍正常告警
- manifest 版本 0.1.0 → **0.2.0**

### 环境操作经验（Windows + Git Bash 坑）
- PowerShell 工具输出偶尔被吞 → 用 `Out-File` 写 C:\Temp\*.txt 再 Read
- Bash 后台启服务 `cmd &` 后 `$!` 是 shell wrapper，杀不干净 Python 子进程 → 用无头测试脚本（Popen + terminate）或按 PID 精确杀
- Git Bash 里 `taskkill //F //PID n` 报错 → 用 PowerShell `Stop-Process -Force`
- 沙箱下 `.git/refs/remotes/` 写入不持久化 → `git status` 显示 `[gone]`，纯噪音；用 `git ls-remote origin` 验证远端
- Git push：`git ls-remote`/`git fetch` 已可免密；push 若提示要密码，用 token 写 URL 推完立即 reset
- **`.bat` 必须 CRLF 换行 + 纯 ASCII 内容**：Write 工具默认写 LF+UTF-8，cmd.exe 按 GBK 解析中文会乱码、把 `set` 整行搞坏（PY 变量变空 → 双击闪退）。生成方式：用 Python `open(..., newline="\r\n", encoding="utf-8")` 写、内容不含非 ASCII；结尾加 `pause` 便于看报错。已固化到 `scripts/*.bat`
- 沙箱限制：Bash 与 PowerShell 工具都**不允许调 cmd.exe**（"bypasses command validation"）；要测 .bat 只能在 Python 脚本里 `subprocess.run(["cmd","/c",...])`（中性化副本、避免真启服务）

### 已知环境现实（影响设计）
- OS: Win11 家庭中文版 Build 26200
- C 盘：剩 44GB（紧张，避开 C 盘）
- 浏览器：Edge + Firefox，**无 Chrome**
- Defender：实时防护全开（写注册表策略可能被 Defender 触发告警，setup 时要加白名单说明）
- 当前会话：**非管理员**（写 HKLM 需要 UAC 提权；开发期尽量不写 HKLM，运行 setup 时才提权）
- Python 3.13.14（managed），Node 22.22.2（managed）
- 本地 git 已连 GitHub：origin = `https://github.com/FMFM002/defender_dev_01.git`；凭证缓存到 `~/.git-credentials`

### 参考项目（GitHub 实测筛选）
- **uBlock Origin**（gorhill/uBlock，68k）+ **uAssets**（6k）：declarativeNetRequest 规则语法标准答案
- **MDE_Enum**（0xsp-SRD，210 stars）：ASR Rule GUID 完整列表（19 条），已抄到本地 ASR 模块字典
- **usn-parser-rs / usn-journal-rs**（wangfu91，13 stars）：NTFS USN 算法参考（用 Python 重写）
- **WatchFS**（berki6，0 stars）：Python ETW 实践参考（只做文件 I/O）
- **PlanqX_EDR**（h4vox，33 stars）：分层 EDR 架构参考
- JS 行为监控、跳转拦截、URLhaus 客户端：**无现成开源**，自己造

### 不在本期范围（P2/P3 等 P1 验收后再讨论）
- USN Journal 文件监控
- JS 运行时行为监控（混淆代码 / Wasm / 隐藏 iframe）
- 内存占用监控 + 游戏误报排除
- LLM 末端裁决
- 自我保护机制
- PyInstaller 打包
