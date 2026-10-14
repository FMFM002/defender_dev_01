# PC Guardian — 本地电脑防护系统

> 基于《项目构建指南.txt》的实现。
> 目标：在不干扰正常使用的前提下，防止个人信息被盗取和电脑被病毒感染。

## 设计原则

- **确定性优先**：规则层做决策，LLM 只处理灰区
- **用户可审计**：每条拦截都有完整证据链
- **先拦后放**：默认拦截，用户手动放行
- **分层防御**：任何单一层被绕过，其他层仍能兜底
- **零日常操作**：一次安装授权，之后完全静默运行（仅命中规则时弹窗）

## 架构

```
┌─ 用户层：安装时点两次"同意"，之后静默
├─ Edge 扩展（MV3 主防线）：白名单 + 灰名单 + 启发式 + declarativeNetRequest 动态规则 + 拦截页
├─ 本地后台服务（数据中枢）：FastAPI 端口 7890
│   ├─ 威胁情报聚合：URLhaus + sec-mcp（免 Key）
│   ├─ 文件哈希云查（P1 占位，P2 接 VirusTotal）
│   ├─ 隔离区管理（开发期复制 + 保留原文件）
│   ├─ WMI/ETW 进程监控（高风险父进程 + 危险命令行 + 投放路径）
│   ├─ ASR 规则写入（独立工具，需管理员）
│   └─ 用户白名单 / 灰名单
└─ 系统基础防护：Windows Defender ASR 规则（HKLM 注册表策略）
```

## 告警触发规则（用户硬性要求）

| 层 | 触发条件 | 证据来源 |
|---|---|---|
| 云查 | URLhaus 返回 malicious=True | 评分 ≥ 50 |
| 灰查 | 灰名单（*.tk / 短链 等）+ 启发式（TLD/端口/可疑关键字/裸IP/punycode/URL过长） | 命中规则名 + 详情 |
| 沙查 | 父进程浏览器/Office/脚本宿主 + 命令行含 `-enc` / `certutil -decode` 等 + 路径在 %TEMP% 等 | 命中规则名 + 详情 |

**任一项异常 → 拦截 + 弹窗（写明异常证据）。三层全部无异常 → 完全静默。**

## 目录结构

```
电脑防毒/
├── 项目构建指南.txt          # 用户原始需求
├── .workbuddy/memory/        # 项目记忆
├── src/
│   └── guardian/             # 本地后台服务（Python）
│       ├── core/             # config / logger / memguard / db / proxy
│       ├── intel/            # URLhaus + sec-mcp + aggregator
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
│   ├── blocked.html          # 拦截页（紧凑 + 详情展开）
│   ├── options.html          # 白名单 / 灰名单管理
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
│   ├── logs/guardian-YYYY-MM-DD.log
│   └── quarantine/
└── tests/
```

## 关键决策（2026-10-14 与用户确认）

- **浏览器覆盖**：仅 Edge（Manifest V3）
- **威胁情报**：免 Key 源起步（URLhaus + sec-mcp）
- **LLM 裁决**：可选项，默认不启用
- **拦截深度**：ASR 注册表规则 + WMI/ETW 进程监控
- **运行方式**：开发期直接跑 Python
- **拦截严格度**：先拦后放（默认拦截所有非白名单域名）
- **数据存放**：全在工作区文件夹内
- **隔离区**：用户可手动还原 + 30 天后自动清理
- **默认白名单**：内置一份通用可信域名列表（35 个）
- **告警规则**：云查/灰查/沙查任一异常即弹窗（必带证据），全静默需三层全无异常
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

### ASR 规则（需管理员）
- 双击 `scripts\apply_asr.bat`（自动请求管理员权限）
- 或手动：`python -m src.guardian.tools.apply_asr --p1`

## API 端点

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/health` | 健康检查 + RSS |
| POST | `/intel/url` | URL 云查 + 缓存 |
| POST | `/intel/hash` | 文件哈希云查 + 缓存 |
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

## 状态

**P1 阶段完成**：

✅ 后台服务（FastAPI，13 个端点）  
✅ Edge MV3 扩展（manifest / SW / content script / 拦截页 / 设置页）  
✅ 默认白名单（35 个通用域名）+ 灰名单 + 启发式  
✅ URLhaus 集成（代理感知 + 24h 缓存）  
✅ WMI 进程监控（高风险父进程 / 命令行 / 投放路径）  
✅ ASR 规则管理（独立工具 + 自动提权 bat）  
✅ 用户白名单 + 隔离区  
✅ 内存守护（idle ≤ 80 / peak ≤ 150）

**P2 计划**：

- ETW 原生订阅（pyetwkit）
- 文件哈希接 VirusTotal
- USN Journal 持久化文件监控
- 弹窗 → Windows Toast
- 开机自启 + 单实例锁