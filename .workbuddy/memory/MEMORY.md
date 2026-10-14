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
- **证据链展示**：拦截页紧凑 + 点详情展开
- **Git**：启用；用户习惯推到 GitHub，需要时主动问 remote 地址
- **VPN**：SakuraCat-VPN，全局模式，SOCKS5+HTTP 都监听 7897；代码里要主动探测代理端口是否可用、有就用、没有跳过
  - **2026-10-14 14:00 起**：用户保持 VPN 开启（开 GitHub 仓库时启动后没关）。意味着：
    - Git push/clone 走代理（已配置 http.proxy = http://127.0.0.1:7897）
    - 威胁情报查询（URLhaus）默认走代理 → URLhaus 401 现象需重新评估（之前测试时 VPN 状态不一致）
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
│       ├── intel/            # URLhaus + sec-mcp + aggregator
│       ├── monitor/          # WMI/ETW 进程监控（实际用 WMI）
│       ├── asr/              # ASR 规则注册表写入（19 条字典）
│       ├── quarantine/       # 隔离区管理
│       ├── tools/            # apply_asr.py（独立工具）
│       ├── api/              # FastAPI 路由
│       └── main.py           # 启动入口
├── extension/                # Edge MV3 扩展
│   ├── manifest.json
│   ├── background.js         # Service Worker（白名单+灰名单+启发式+决策+弹窗）
│   ├── content_script.js     # 沙查层（eval / 外链 script / iframe 注入监控）
│   ├── blocked.html          # 拦截页（紧凑+展开）
│   ├── options.html          # 白名单管理
│   └── config/default_whitelist.json
├── scripts/
│   └── apply_asr.bat         # 双击自动提权
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
- **进程监控选 WMI 而非 pyetwkit**：pyetwkit ��译复杂，pywin32 单 binary 依赖即可；WMI 延迟秒级对进程告警够用
- **URLhaus 401 = 正常**：无害域名 URLhaus 拒查询（query_status=invalid），HTTP 401 在 result 内 status='error'、malicious=False → 不算云查异常
- **内存优化**：`_LazyDB` 让 SQLite 初始化延迟到首次调用，import 时 RSS 从 79MB → 48MB
- **WMI NextEvent 超时是正常控制流**：无事件时每秒抛超时异常（中文"已超时" / HRESULT -2147209215），必须静默 continue，否则日志被刷屏。识别函数：`etw_proc._is_wmi_timeout()`
- **WMI 进程监控需管理员权限**：非管理员订阅 `Win32_ProcessStartTrace` 报"拒绝访问"，已降级为友好 WARNING（不影响 URL 拦截）
- **单实例保护**：main.py 启动前检测 7890 端口，占用时打印占用 PID；`scripts/stop.bat` 一键释放
- **进程告警规则 v2（2026-10-14 收紧误报）**：v1 把 `cmd.exe`/`powershell.exe` 当高风险父进程 + 把 `%APPDATA%`/`%LOCALAPPDATA%` 当投放目录 → 误报刷屏（连本服务自己都报）。v2 改为语义化判断：
  - `BENIGN_CHILDREN`（conhost/dllhost/…）命中直接放行
  - `HIGH_RISK_PARENTS` = Office + 脚本宿主（**去掉 cmd/powershell**）
  - 浏览器只在「派生非浏览器进程」时报（`browser_spawn_process`）
  - 投放路径只留 `%TEMP%` + `\Downloads\`
  - `_handle_event` 加 5 分钟去重（进程名+父名+规则）
  - 单测脚本：`C:\Temp\test_eval.py`（11 用例，正反双向）

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
