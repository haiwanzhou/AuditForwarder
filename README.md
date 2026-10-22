# AuditForwarder

面向「多操作员共同管理一套受管系统」场景的**行为审计 + 跨操作员合谋检测**系统。

采集端装在每台操作员主机上，把「谁、在什么时间、对什么对象、做了什么」上报到服务端；
服务端按操作员身份贯通存储，并用**关联规则 + 资产画像 + 操作员图谱**识别单人越权与多人合谋，
输出可复核的分级告警与证据链报告，而不是只给一个风险分数。

---

## 核心能力

| 能力 | 说明 |
|------|------|
| 跨平台采集 | Windows（文件 / 进程 / 网络 / 注册表 / ETW 安全日志）与 Linux（文件 / 进程 / 网络 / audit / 命令） |
| HTTP 行为采集 | 内置本机正向代理，把浏览器对受管 Web 系统的访问记成结构化事件（方法 / 主机 / URI / 状态码） |
| 采集降噪 | 借鉴 Sysmon / osquery / Zeek 的过滤思路：路径与进程排除、连接级去重、ETW 事件白名单 |
| 身份贯通 | 心跳、事件批次、操作日志三路携带操作员身份；服务端维护操作员台账与主机绑定关系 |
| 可信存证 | SHA-256 哈希链 + Merkle 树，批次可验签，防篡改可追溯 |
| OCSF 子集事件模型 | 统一 `actor / activity_name / object / outcome / severity_id / target_system / metadata` 七个字段 |
| 资产画像 | 每个受管系统一份 YAML：资源类型、敏感度分级、角色操作基线 |
| 危害规则 | Sigma 风格：支持 `group-by`、微秒级 `timespan`、有序序列；规则热加载，无需重启 |
| 合谋图谱 | 操作员节点 + 同对象共现边 + 角色互补边 + 时间窗稠密度指标 |
| 分级告警与处置 | HIGH / MID / LOW 分级、告警降噪、人工处置闭环、风险事件证据链导出 |
| 危害定级报告 | 一键导出 Markdown 报告：规则汇总、评分构成、涉及操作员、时间线证据 |
| 模拟与演示 | CERT r4.2 风格多操作员行为模拟器，正常行为 + 合谋攻击剧本可复现 |
| 远程管理 | 心跳、资源指标、审计摘要、远程命令下发与结果回传、策略热加载 |
| Web 控制台 | 主机管理、操作员台账、数据库检索、告警与合谋风险页面；登录鉴权、会话 Token、失败锁定 |

**硬约束**：时间载荷统一微秒粒度；ML/图谱因子只作线索（`ml_factor ≤ 30`、graph 因子受上限约束）；无规则命中时总分强制 < 80，不直接触发 HIGH。

---

## 系统组成

```
                 ┌──────────── 操作员主机 A ────────────┐
                 │ collector → normalizer → schema      │
                 │   → pii_masker → deduper → 检测规则  │
                 │   哈希链批次 ──┐                     │
                 └────────────────┼─────────────────────┘
                                  │  HTTPS / 压缩 / 验签
  操作员主机 B、C …  ─────────────┼──────────►  ┌──────────────────────────┐
                                               │ 服务端                    │
  受管系统（如图书管理系统）◄── 操作员浏览器 ──► │ · 批次入库 / SQLite      │
     ▲ 经本机 HTTP 代理采集                     │ · 操作员台账 / 主机管理   │
     └──────────────────────────────────────── │ · 关联规则 + 资产画像     │
                                               │ · 合谋图谱 + 风险定级     │
                                               │ · Web 控制台 / 报告       │
                                               └──────────────────────────┘
```

---

## 快速开始（Windows / MSYS2）

```powershell
# 1. 配置与构建（MSYS2 UCRT64 或 MINGW64 环境）
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
C:\msys64\mingw64\bin\ninja.exe -C build

# 2. 预建数据目录
New-Item -ItemType Directory -Force data\server, data\client | Out-Null

# 3. 启动服务端（工作目录保持项目根目录）
.\build\auditforwarder-server.exe -c .\config\server_windows.yaml
#    Web 控制台：http://127.0.0.1:8443/
#    默认账号 admin，密码为 manager.login_password_sha256 对应的明文

# 4. 启动客户端（首次建议用 GUI 填写服务端地址与操作员标识）
.\build\auditforwarder-client-gui.exe
#    或命令行：
.\build\auditforwarder-client.exe -c .\config\client_windows.yaml
```

### Linux

```bash
sudo apt install -y build-essential cmake pkg-config libssl-dev zlib1g-dev libaudit-dev
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
sudo ./scripts/install_linux.sh --start
```

生产环境请务必修改默认账号密码、配置共享 HMAC 密钥并启用 HTTPS/TLS。

---

## 合谋检测演示

```powershell
# 生成 CERT r4.2 风格的多操作员行为（含 4 组合谋攻击剧本）
.\build\auditforwarder-sim.exe --scenario cert_r42 --operators 4 --output data\sim_events.jsonl

# 一键演示：登录 → 生成事件 → 单批次投递 → 导出危害定级报告
powershell -ExecutionPolicy Bypass -File scripts\demo_m8.ps1 -Server http://127.0.0.1:8443 -Password <密码>
```

报告接口：`GET /collusion/incident-report?days=7`（Markdown）。

---

## 关键配置

| 配置 | 位置 | 说明 |
|------|------|------|
| 操作员身份 | `config/client_windows.yaml` → `operator.id / operator.name` | 每人唯一 ID，随事件贯通 |
| 采集降噪 | 同上 → `collectors.filter.*` | 列表留空即用内置默认值；支持路径/进程/端口/ETW 过滤 |
| HTTP 采集 | 同上 → `collectors.http_proxy` | 默认关闭；`target_hosts` 限定受管子域 |
| 资产画像 | `config/asset_profiles/*.yaml` | 资源类型、敏感度、角色基线；运行期加载 |
| 危害规则 | `data/server/policies/collusion_rules.json` | 支持热加载（客户端 `load_rules` 指令 / 服务端接口） |
| 检测参数 | `data/server/policies/collusion_config.json` | 时间窗、评分上限、图分析阈值 |

YAML / JSON 配置改动无需重新编译，仅 C++ 源码变更需要重新构建。

---

## 目录结构

```
client/     采集端：采集器、处理器链、传输、远程客户端、GUI
server/     服务端：管理接口、合谋检测引擎、Web 控制台
shared/     共享库：事件模型、哈希链、数据库、图算法、模拟器
tools/      模拟器入口（auditforwarder-sim）
include/    公共头文件
config/     客户端/服务端/资产画像配置样例
tests/      单元测试（全量 695 项）
scripts/    安装、演示、压测脚本
docs/       设计、协议、操作与实验文档
```

---

## 文档

**总体**

- [项目操作手册](项目操作手册.md)
- [M5–M8 工作总结与合谋实验方案](docs/M5_M8_工作总结与合谋实验方案.md)
- [M5–M8 路线与实施记录](docs/ROADMAP_M5_M8.md)
- [项目规格说明](docs/PROJECT_SPEC.md)
- [架构说明](docs/ARCHITECTURE.md)
- [项目结构说明](docs/PROJECT_STRUCTURE.md)

**接口与数据**

- [通信协议](docs/PROTOCOL.md)
- [API 文档](docs/API_REFERENCE.md)
- [数据库设计](docs/DATABASE_DESIGN.md)
- [数据库 API 与示例](docs/DATABASE_API.md)

**实验与运维**

- [合谋检测实验方案](docs/EXPERIMENT_DESIGN.md)
- [实验全流程操作指引](docs/EXPERIMENT_GUIDE.md)
- [多节点联调指引](docs/MULTI_NODE_GUIDE.md)
- [测试计划](docs/TEST_PLAN.md)
- [运维说明](docs/OPERATIONS.md)
- [开发文档](docs/DEVELOPMENT_GUIDE.md)
- [用户手册](docs/USER_MANUAL.md)
- [跨操作员合谋协同行为检测子系统-系统设计方案](跨操作员合谋协同行为检测子系统-系统设计方案.docx)

---

## 测试

```powershell
.\build\auditforwarder_tests.exe
```

当前全量 695 项断言通过，覆盖采集过滤、事件模型、哈希链、规则引擎、资产画像、关联规则、操作员图谱、模拟器与报告生成。

---

## 许可证

Apache 2.0
