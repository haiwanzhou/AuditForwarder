# AuditForwarder M5-M8 任务规划文档

> 目标：升级为「多操作员共同管理一套管理系统（示例：自建 HTTP 图书管理系统）」的行为审计 + 合谋检测系统
> 采集端 agent 装在各操作员主机上采集本机操作并上传；服务端集中存储操作员台账并做合谋检测
> 调研对标：OCSF（事件模型）/ Sigma（关联规则）/ Wazuh（主机检测）/ Zeek（HTTP 行为日志）/ CS224W（图分析）/ CERT r4.2（ insider threat 剧本）

---

## 阶段总览

| 阶段 | 主题 | 状态 |
|------|------|------|
| M5 | 采集与身份贯通 | 主体已完成，剩余采集器与 Web 页面 |
| M6 | 事件模型与危害规则 | 未开始 |
| M7 | 合谋图谱增强 | 未开始 |
| M8 | 模拟与演示 | 未开始 |

---

## M5：采集与操作员身份贯通

### 5.1 已完成（本次提交）

**客户端（采集端）**

| 文件 | 改动 |
|------|------|
| `config/client_windows.yaml`、`config/agent_windows.yaml` | 新增 `operator:` 配置段（`id` / `name`） |
| `client/src/gui/client_gui.cpp` | GUI 新增「操作员标识」输入框；保存配置时写入 YAML，避免配置被 GUI 重写丢失 |
| `client/src/core/agent.cpp` | 解析 `operator.id / operator.name`，传入 Enricher 与 RemoteClientConfig |
| `client/src/processor/processor.cpp` | Enricher 为每条事件 attrs 注入 `operator_id / operator_name`（身份随事件贯通） |
| `client/src/core/remote_client.cpp` | 心跳、批次摘要、操作日志三路上报 JSON 全部携带操作员身份 |

**服务端（管理端）**

| 文件 | 改动 |
|------|------|
| `server/src/manager/manager_server.cpp` | 操作员台账 `data/operators.json`（operator_id / display_name / bound_host_id / status / last_seen / last_client_ip）；`upsert_operator_locked` 自动登记，换机绑定变更记审计日志 |
| 同上 | 新增 `GET /operators`（台账列表）与 `POST /operators/register`（手工注册/绑定）；心跳与操作日志到达时自动登记 actor↔host 绑定 |
| `shared/src/database/sqlite_db.cpp` | events 表新增 `operator` 列 + 索引；旧库 `ALTER TABLE` 自动迁移 |

**验证**：349 个单元测试全部通过；端到端冒烟（心跳登记 → 日志登记 → 手工注册 → SQLite operator 列写入）全部通过。

### 5.2 待做

#### 任务 1：本地 HTTP 代理行为采集 collector（M5-3，高优先级）

- **目标**：采集本机操作员对目标系统（如图书管理系统）的 HTTP 操作行为
- **字段**：对齐 Zeek http.log 子集——`method` / `host` / `uri` / `user_agent` / `status_code` / `request_body_len`
- **要点**：
  - 新建 `http_proxy` collector（Windows/Linux 各一份或共用骨架），注册到 `logmeta::collector` 常量表
  - 事件 category 映射 network，action 按 method 推断（GET=read / POST=create / DELETE=delete 等）
  - 生产模式要求对请求体 PII 脱敏（复用 PIIMasker）
  - 配置段 `collectors.http_proxy: { enabled, listen_port, target_hosts }`，未配置时默认关闭
- **验收**：浏览器访问示例系统后，服务端操作日志能按 operator_id 检索到带 method/uri 的记录

#### 任务 2：Web 控制台操作员台账页面（M5-4，中优先级）

- **目标**：控制台展示 `GET /operators` 数据（操作员 ID、显示名、绑定主机、在线状态、最近上报）
- **要点**：仿现有「主机管理」页风格；显示绑定变更告警入口

---

## M6：事件模型与危害规则

### 任务 1：事件模型 schema 对齐 OCSF 子集（M6-1）

- **目标**：统一跨系统事件模型，为规则引擎与图谱提供稳定输入
- **字段**：`actor`（操作员）/ `activity_name` / `object` / `outcome` / `severity_id` / `target_system` / `metadata`
- **要点**：
  - 在 Normalizer 后新增 Schema 映射阶段（或在 Normalizer 内扩展第 7 步）
  - 保持现有 attrs 机制与哈希链兼容（不改 EventBatch 结构）
  - 时间戳一律微秒粒度（项目硬约束）

### 任务 2：资产画像 YAML（M6-2）

- **目标**：每个受管系统一份画像配置，实现方案通用化（图书系统只是实例）
- **字段**：系统标识、访问方式（HTTP/DB/终端）、资源类型枚举、敏感度分级、角色基线（哪些操作员角色可执行哪些 action）
- **要点**：服务端加载，规则引擎与图谱按画像解释 `object` 与 `target_system`

### 任务 3：Sigma correlation 风格危害规则（M6-3）

- **目标**：跨事件/跨操作员的危害行为规则
- **要点**：
  - 支持 `group-by`（按操作员/对象分组）、`timespan`（微秒粒度时间窗）、`ordered sequence`（有序事件序列）
  - 规则命中直接驱动危害定级；无规则命中时总分保持 < 80（项目硬约束）
  - 规则文件走现有 `load_rules` 热加载通道，无需重启

---

## M7：合谋图谱增强

- **节点重构**：图谱节点从「主机」升级为「操作员」（operator_id 为主键）
- **边类型**：
  1. 同对象共现边：两个操作员在时间窗内操作同一 `object`
  2. 角色互补边：两个操作员的操作构成画像中的危险组合（如一人删备份、一人卸载磁盘）
- **时间窗稠密度指标**：窗口内操作员两两交互频次密度，作为 graph_factor 输入
- **硬约束（不得回归）**：
  - `ml_factor ≤ 30`（ML 评分仅提供补充线索）
  - 无规则命中时总分 < 80，不得直接触发 HIGH
  - 复用 M4 已有纯 C++ 图算法（度中心性 / Louvain / 三角计数 / Jaccard）

---

## M8：模拟与演示

- **模拟器**：按 CERT r4.2 insider threat 剧本改编，生成多操作员正常行为 + 合谋攻击序列
- **危害定级报告**：输出每条规则的命中证据链（涉及操作员、对象、时间窗、图谱指标）
- **多机联调**：≥2 台客户端 + 1 台服务端（Radmin VPN 或局域网），端到端演示采集 → 身份贯通 → 规则命中 → 图谱分析 → 报告

---

## 里程碑依赖与建议顺序

```
M5-3 采集器 ──► M5-4 Web 台账页 ──► M6-1 schema ──► M6-2 资产画像 ──► M6-3 规则
                                                                        │
                              M7 图谱增强 ◄─────────────────────────────┘
                                    │
                              M8 模拟与演示
```

- M5 剩余任务与 M6-1 可并行（schema 映射不依赖 HTTP 采集器）
- M6-3 规则引擎依赖 M6-1/M6-2 完成
- M8 依赖全部前序阶段

## 工程约束提醒

- 构建：MSYS2 UCRT64 + Ninja，产物在 `build/`；YAML 配置改动无需重编译
- 提交作者必须使用 GitHub noreply 匿名邮箱（QQ 邮箱会被 GH007 拒绝）
- 服务端 SQLite：不得在持锁状态下调用 `exec()`（曾发生自死锁）
- 客户端心跳与审计上传保持独立线程
