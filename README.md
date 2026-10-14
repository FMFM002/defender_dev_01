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
├─ Edge 扩展（MV3 主防线）：declarativeNetRequest 白名单拦截 + 跳转拦截 + 下载钩子
├─ 本地后台服务（数据中枢）：FastAPI 端口 7890
│   ├─ 威胁情报聚合：URLhaus + sec-mcp（免 Key）
│   ├─ 文件哈希云查
│   ├─ 隔离区管理
│   ├─ ETW 进程监控（Microsoft-Windows-Kernel-Process）
│   ├─ ASR 规则写入
│   └─ 用户白名单
└─ 系统基础防护：Windows Defender ASR 规则
```

## 目录结构

```
电脑防毒/
├── 项目构建指南.txt          # 用户原始需求
├── .workbuddy/memory/        # 项目记忆
├── src/
│   ├── guardian/             # 本地后台服务（Python）
│   │   ├── core/             # 启动 / 配置 / 日志
│   │   ├── intel/            # 威胁情报聚合
│   │   ├── monitor/          # ETW 进程监控
│   │   ├── asr/              # ASR 规则注册表写入
│   │   ├── quarantine/       # 隔离区管理
│   │   └── api/              # FastAPI HTTP 接口
│   └── extension/            # Edge 扩展（Manifest V3）
│       ├── manifest.json
│       ├── background/       # Service Worker
│       ├── content/          # Content Script
│       ├── rules/            # declarativeNetRequest 规则
│       └── pages/            # 拦截页 / 设置页
├── data/                     # 不入 git
│   ├── quarantine/
│   ├── db/
│   └── logs/
├── config/                   # 默认白名单等
└── tests/
```

## 关键决策（2026-10-14 与用户确认）

- **浏览器覆盖**：仅 Edge（Manifest V3）
- **威胁情报**：免 Key 源起步（URLhaus + sec-mcp）
- **LLM 裁决**：可选项，默认不启用
- **拦截深度**：ASR 注册表规则 + ETW 进程监控
- **运行方式**：开发期直接跑 Python
- **拦截严格度**：先拦后放（默认拦截所有非白名单域名）
- **数据存放**：全在工作区文件夹内
- **隔离区**：用户可手动还原 + 30 天后自动清理
- **默认白名单**：内置一份通用可信域名列表
- **告警规则**：云查/灰区/本地启发式任一异常即弹窗（必带证据），全静默需三层全无异常
- **VPN**：SakuraCat-VPN，端口 7897（SOCKS5+HTTP），代码主动探测代理是否可用
- **日志**：全量进文件，按天切 30 天
- **节奏**：一气写完到 P1 再验收

## 参考项目

- [uBlock Origin](https://github.com/gorhill/uBlock) + [uAssets](https://github.com/uBlockOrigin/uAssets) - declarativeNetRequest 标准答案
- [MDE_Enum](https://github.com/0xsp-SRD/MDE_Enum) - ASR Rule GUID 完整列表
- [usn-parser-rs](https://github.com/wangfu91/usn-parser-rs) - NTFS USN Journal 参考
- [WatchFS](https://github.com/berki6/WatchFS) - Python ETW 实践
- [PlanqX_EDR](https://github.com/h4vox/PlanqX_EDR) - 分层 EDR 架构

## 状态

**筹备阶段**：环境探测、决策收敛、Git 仓库初始化完成。
下一步：搭建项目骨架（src/ 目录、Python venv、FastAPI 本地服务最小可用链路）。
