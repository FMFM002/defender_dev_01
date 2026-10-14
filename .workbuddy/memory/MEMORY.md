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
- **日志**：全量进文件，拦截页只��示用户需要知道的；按天切、保留 30 天
- **验收方式**：用户真机测试；本项目要带 DEBUG 级 logger
- **开发节奏**：一气写完到 P1 才停下让用户验收

### 用户偏好
- 用户非技术背景，表述可能不精确；要主动提问澄清
- 不喜欢 AI 啰嗦、要直接给结论
- 用户自己挑 MCP / 专家 / skill 嫌烦，让我自己决定（本项目判断：暂不需要任何内置 skill 或 MCP）
- 通用安全提醒：用户默认 VPN 开、访问非白名单、下载未知文件

### 项目结构（拟）
```
电脑防毒/
├── 项目构建指南.txt          # 用户输入的需求
├── .workbuddy/memory/        # 本项目记忆
├── src/
│   ├── guardian/             # 本地后台服务（Python）
│   │   ├── core/             # 启动 / 配置 / 日志
│   │   ├── intel/            # 威胁情报聚合（URLhaus + sec-mcp）
│   │   ├── monitor/          # ETW 进程监控 + USN Journal + 内存监控
│   │   ├── asr/              # ASR 规则注册表写入
│   │   ├── quarantine/       # 隔离区管理
│   │   └── api/              # FastAPI：与扩展通信的 HTTP 接口
│   └── extension/            # Edge 扩展（Manifest V3）
│       ├── manifest.json
│       ├── background/       # Service Worker
│       ├── content/          # Content Script（JS 行为监控）
│       ├── rules/            # declarativeNetRequest 规则
│       └── pages/            # 拦截页 / 设置页
├── data/                     # 不入 git
│   ├── quarantine/
│   ├── db/
│   └── logs/
├── config/                   # 默认白名单等
└── tests/
```

### 已知环境现实（影响设计）
- OS: Win11 家庭中文版 Build 26200
- C 盘：剩 44GB（紧张，避开 C 盘）
- 浏览器：Edge + Firefox，**无 Chrome**
- Defender：实时防护全开（写注册表策略可能被 Defender 触发告警，setup 时要加白名单说明）
- 当前会话：**非管理员**（写 HKLM 需要 UAC 提权；开发期尽量不写 HKLM，运行 setup 时才提权）
- Python 3.13.14（managed），Node 22.22.2（managed）

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
