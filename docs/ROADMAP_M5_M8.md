# AuditForwarder M5-M8 任务规划文档

> 目标：升级为「多操作员共同管理一套管理系统（示例：自建 HTTP 图书管理系统）」的行为审计 + 合谋检测系统
> 采集端 agent 装在各操作员主机上采集本机操作并上传；服务端集中存储操作员台账并做合谋检测
> 调研对标：OCSF（事件模型）/ Sigma（关联规则）/ Wazuh（主机检测）/ Zeek（HTTP 行为日志）/ CS224W（图分析）/ CERT r4.2（ insider threat 剧本）

---

## 阶段总览

| 阶段 | 主题 | 状态 |
|------|------|------|
| M5 | 采集与身份贯通 | 已完成 |
| M6 | 事件模型与危害规则 | 已完成（M6-1、M6-2、M6-3） |
| M7 | 合谋图谱增强 | 已完成 |
| M8 | 模拟与演示 | 工具与报告已完成（多机联调待现场执行） |

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

### 5.2 已完成（M5-3 HTTP 采集器）

#### 任务 1：本地 HTTP 代理行为采集 collector（M5-3）

- 实现：`client/src/collector/http_proxy_collector.{h,cpp}`（跨平台，WinSock/POSIX 共用骨架）
- 形态：本机回环正向代理；普通 HTTP 解析绝对 URL/Host 并转发，CONNECT 走盲隧道（HTTPS 仅记录 host:port）
- 字段：`http.method/host/uri/user_agent/status_code/request_body_len`，`capture_body` 开启时额外留 `http.request_body`（下游 PIIMasker 脱敏）
- 映射：category=network；GET/HEAD=read、POST=create、PUT/PATCH=write、DELETE=delete、CONNECT=connect
- 配置：`collectors.http_proxy: { enabled, bind, listen_port, capture_body, target_hosts }`，未配置默认关闭；`target_hosts` 支持通配子域
- 验证：新增单测（映射/URL/主机过滤 + 真实转发端到端）；本机冒烟确认事件带 `operator_id` 且 `password=***REDACTED***`

### 5.3 已完成（M5-4 Web 台账页）

#### 任务 2：Web 控制台操作员台账页面（M5-4）

- 侧边栏新增「操作员台账」视图（`server/web/index.html#operators`），风格对齐主机管理页
- 展示 `GET /operators`：操作员 ID / 显示名 / 绑定主机 / 在线状态 / 最近上报 / 注册时间 / 客户端 IP
- 支持按关键词与状态（在线 / 离线 / 禁用）筛选，顶部统计总数、在线、已绑定、未绑定
- 手工登记/更新表单对接 `POST /operators/register`，支持绑定主机下拉（取 `/hosts`）与启用/禁用
- 绑定变更告警：浏览器本地保存绑定基线，检测换机/换绑并列出 `旧主机 → 新主机`，可联跳到对应主机数据库
- 验证：本机启动服务端，浏览器实测登录 → 建两台主机 → 登记操作员 → 换绑 → 刷新，告警正确出现；JS 语法检查通过

### 5.4 M5 阶段收尾验收记录（2026-10-22）

**环境**：本机 Windows；服务端 `127.0.0.1:18443`（独立临时数据目录）；客户端节点 `accept-node`（操作员 `op_accept`）；受管系统用本地 mock HTTP `127.0.0.1:18080` 模拟。

**用例与结果**

| # | 验证项 | 结果 |
|---|--------|------|
| 1 | 单元测试全量回归 | 387 项全部通过 |
| 2 | 客户端 http_proxy 监听并转发 | 监听 `127.0.0.1:18888`；经代理 `POST /books?id=7` 成功转发，上游收到 origin-form 请求，返回 200 |
| 3 | 服务端操作日志落盘 | `operation_logs/accept-node/http_proxy.jsonl` 单条含 `operator_id` / `operator_name` / `collector=http_proxy` / `http.method=POST` / `http.host` / `http.uri=/books?id=7` / `http.status_code=200` / `http.request_body_len=31` |
| 4 | 请求体 PII 脱敏 | `http.request_body` 中密码落盘为 `***REDACTED***` |
| 5 | SQLite events 表写入 | `operator` 列为 `op_accept`；`GET /db/query?...&search=POST 127.0.0.1:18080` 命中目标记录 |
| 6 | 操作员自动登记 | `GET /operators` 中 `op_accept` 绑定 `accept-node` 且在线 |
| 7 | 控制台检索 | 「操作员台账」可见登记信息；「数据库管理」选择 accept-node/events 可按关键词命中该 HTTP 操作，列头含 `operator` |

**结论**：M5 全链路（采集 → 身份贯通 → 落库 → 台账与控制台检索）验收通过。

**观察项（不阻塞）**

- 同一次 HTTP 操作在 events 表出现 2 条（ingest 批量通道与 operation-logs 通道各写一份），跨通道未去重。
- 仅用 `operator_id` 作关键词检索时，结果会被主机文件采集噪音占满分页；需叠加 `collector` 或 URI 关键词缩小范围。建议 M6 为 `/db/query` 增加 `collector` 过滤参数。
- 手工登记操作员会刷新 `last_seen`，新登记的操作员会短暂显示在线。
- 修复：`/db/query` 与 `/db/export` 的 events 列表头此前漏了 `operator` 列，已补上，避免表头与数据列错位。

---

## M6：事件模型与危害规则

### 任务 1：事件模型 schema 对齐 OCSF 子集（M6-1）

- **目标**：统一跨系统事件模型，为规则引擎与图谱提供稳定输入
- **字段**：`actor`（操作员）/ `activity_name` / `object` / `outcome` / `severity_id` / `target_system` / `metadata`
- **要点**：
  - 在 Normalizer 后新增 Schema 映射阶段（或在 Normalizer 内扩展第 7 步）
  - 保持现有 attrs 机制与哈希链兼容（不改 EventBatch 结构）
  - 时间戳一律微秒粒度（项目硬约束）

#### M6-1 实施记录（2026-10-22）

实现方式：新增独立处理器 `processor::SchemaMapper`（`name()=schema_mapper`），注册在 Normalizer 之后、PIIMasker 之前（`client/src/core/agent.cpp`）。所有映射字段写入 attrs 保留键，不改 `AuditEvent` / `EventBatch` 结构。

| attrs 键 | 含义 | 映射来源 |
|----------|------|----------|
| `ocsf.actor` | 操作员（图谱主键口径） | `operator_id` → `actor.user` → `actor.name` |
| `ocsf.activity_name` | 动作规范名 | `EventAction` 规范名（read/create/delete...） |
| `ocsf.object` | 被操作对象 | `target.path` → `http.uri` → `target.address:port` |
| `ocsf.outcome` | 执行结果 | `EventOutcome`（success/failure/denied/unknown） |
| `ocsf.severity_id` | OCSF 数值严重度 | Info=1, Notice=2, Warning=3, Error=4, Critical/Alert=5, Emergency=6 |
| `ocsf.target_system` | 受管系统标识 | `http.host`（补端口）→ `target.address:port` → `local` |
| `ocsf.metadata` | 元数据 JSON 文本 | version/product/collector/source/host/agent_id/operator_id/logged_time_us/schema_ver |

- 兼容性：映射字段仅进入 attrs（canonical JSON 已包含 attrs），哈希链与批次结构不变；已显式设置的映射字段不被覆盖（适配器可预置）
- 时间：metadata 的 `logged_time_us` 直接取 `ts_micros`，保持微秒粒度
- 脱敏：SchemaMapper 位于 PIIMasker 之前，映射出的元数据同样经过脱敏
- 验证：新增单测 `test_schema_mapper`（完整映射 / actor 兜底 / object 兜底 / 不覆盖 / severity_id 逐级 / JSON 转义 / to_json 携带），全量 416 项通过

### 任务 2：资产画像 YAML（M6-2）

- **目标**：每个受管系统一份画像配置，实现方案通用化（图书系统只是实例）
- **字段**：系统标识、访问方式（HTTP/DB/终端）、资源类型枚举、敏感度分级、角色基线（哪些操作员角色可执行哪些 action）
- **要点**：服务端加载，规则引擎与图谱按画像解释 `object` 与 `target_system`

#### M6-2 实施记录（2026-10-22）

实现方式：新增共享模块 `include/auditforwarder/asset_profile.h` + `shared/src/common/asset_profile.cpp`，服务端懒加载 `<data_dir>/asset_profiles/*.yaml`。

**画像字段**

| 字段 | 说明 |
|------|------|
| `system_id` / `display_name` | 系统标识（必填，唯一，重复加载覆盖）与展示名 |
| `access_mode` | 访问方式：`http` / `db` / `terminal`（兼容 web/sql/ssh 等同义词） |
| `target_systems` | 事件 `target_system` 别名（host / host:port，大小写不敏感） |
| `resources` | 资源规则列表：`pattern`（`*`/`?` 通配）+ `type` + `sensitivity`，按顺序首个命中生效 |
| `default_sensitivity` / `default_resource_type` | 未命中资源规则时的默认解释 |
| `roles` | 角色基线：`allowed_actions` / `denied_actions`（`denied` 优先，支持通配） |
| `operator_roles` | `operator_id -> role` 映射 |

**资源类型枚举**：`data_record` / `table` / `backup` / `credential` / `config` / `log` / `system` / `other`
**敏感度分级**：`public`(0) / `internal`(1) / `confidential`(2) / `secret`(3)

**服务端接入**

- `GET /asset-profiles`（`server/src/manager/manager_server.cpp`）：首次访问懒加载画像目录，返回全部画像 JSON；目录不存在时返回空列表，不影响启动
- 违规规则复查 `evaluate_operation_log_rules`：按 `target_system`（回落 `http.host` / `target_host`）定位画像，按 `object`（回落 `http.uri` / `target_path`）匹配资源类型与敏感度，再按操作员角色判定动作；仅当「角色已登记 + 明确越权 + 敏感度 ≥ confidential」时写 `asset_role_violation` 告警（secret→high，confidential→medium）。画像未登记的角色不做判定，避免误报
- 加载失败只记 WARN，不影响其他画像与主流程

**示例配置**：`config/asset_profiles/book_system.yaml`（图书系统实例，含 reader/editor/admin 三角色基线）

**验证**：新增单测 `test_asset_profile`（解析 / 通配符 / 注册表定位 / object 分类 / 角色基线 denied 优先 / 操作员判定 / 热加载覆盖 / JSON 输出 / 必填校验 / 目录加载容错），全量 473 项通过

### 任务 3：Sigma correlation 风格危害规则（M6-3）

- **目标**：跨事件/跨操作员的危害行为规则
- **要点**：
  - 支持 `group-by`（按操作员/对象分组）、`timespan`（微秒粒度时间窗）、`ordered sequence`（有序事件序列）
  - 规则命中直接驱动危害定级；无规则命中时总分保持 < 80（项目硬约束）
  - 规则文件走现有 `load_rules` 热加载通道，无需重启

#### M6-3 实施记录（2026-10-22）

实现方式：在合谋检测引擎内新增 Sigma correlation 关联规则评估链路（`include/auditforwarder/collusion.h` + `server/src/collusion/collusion.cpp`），复用现有 `policies/collusion_rules.json` 规则文件与文件热加载通道（`maybe_reload_locked`，每 2 秒检查），无需重启。

| 能力 | 实现 |
|------|------|
| `group_by` | `operator`（同一操作员跨事件）/ `object`（同一对象跨操作员）/ `asset_group`（默认，沿用原资产组+时间窗口聚合） |
| `timespan_us` | 微秒时间窗，从有序序列首事件起算；`0` 表示不限 |
| `ordered sequence` | `op_sequence` 按时间升序依次匹配，允许跳过无关事件；乱序接入先按微秒稳定排序 |
| 事件时间戳 | `CleanEvent.ts_us` 优先取 `event_timestamp_us` / `logged_time_us` / `ts_micros`，缺失时由毫秒换算 |
| 危害定级 | 命中直接以 `base_score` 定级（≥ `score_high` → HIGH），写入统一风险事件存储与平台告警；同规则+同分组在 `alert_dedup_seconds` 内降噪 |
| 硬约束 | 关联规则仅在命中时落事件；资产组路径保持「规则零命中总分 < 80」钳制；`ml_factor ≤ 30` 不变 |

预置示例规则 R-006（`operator`，10 分钟导出→清除）、R-007（`object`，5 分钟提权→外泄）。

验证：新增 `test_collusion_correlation_rules` / `test_collusion_correlation_engine`（分组隔离、微秒 timespan 边界、有序序列、object 跨操作员、毫秒回退、规则文件解析、HIGH 定级与降噪），全量 503 项测试通过。

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

#### M7 实施记录（2026-10-22）

实现方式：新增共享模块 `include/auditforwarder/operator_graph.h` + `shared/src/graph/operator_graph.cpp`，合谋引擎 `detect()` 的图分析阶段改由该模块完成（节点从主机/资产升级为操作员）。

| 能力 | 实现 |
|------|------|
| 节点重构 | 节点仅含 `operator_id`，同一操作员多次操作折叠为一个节点 |
| 同对象共现边 | 同一 `object_key`（`res_key`）且事件时间差 ≤ `graph_window_us` 的操作员两两加边，记录共现次数与对象证据 |
| 角色互补边 | 不同操作员在窗口内命中 `complementary_action_pairs`（如 `delete`/`rm` + `unmount`/`format`），且目标系统相同（或对象相同）时加边，记录组合标签 |
| 时间窗稠密度 | 滑动窗口内「不同操作员对数量 / 理论两两组合数」的最大值，超 `graph_density_threshold` 计入稠密度分量 |
| 图算法复用 | 由操作员图构建 `BehaviorGraph`，直接复用 M4 的度中心性 / Louvain 社区 / 三角形计数 / Jaccard 相似度 |
| 评分 | `graph_factor = min(graph_max_factor, (M4 分量 + 稠密度分量 + 互补分量) × graph_max_factor)`，默认上限 25 |
| 边界处理 | 无协作/互补边时直接返回 `graph_factor=0`，避免孤立节点被社区算法误判 |
| 配置 | `graph_window_minutes` / `graph_density_threshold_pct` / `complementary_action_pairs`，随 `collusion_config.json` 热加载；旧配置缺失互补组合时使用内置默认值 |

**硬约束保持**：`graph_factor ≤ 25`，规则零命中时总分钳制 < 80；`ml_factor ≤ 30` 不变。

**验证**：新增 `test_operator_graph`（同对象共现、窗口边界微秒精度、角色互补、上下文不一致、超窗、因子上限），全量 530 项测试通过。

---

## M8：模拟与演示

- **模拟器**：按 CERT r4.2 insider threat 剧本改编，生成多操作员正常行为 + 合谋攻击序列
- **危害定级报告**：输出每条规则的命中证据链（涉及操作员、对象、时间窗、图谱指标）
- **多机联调**：≥2 台客户端 + 1 台服务端（Radmin VPN 或局域网），端到端演示采集 → 身份贯通 → 规则命中 → 图谱分析 → 报告

#### M8 实施记录（2026-10-22）

**1. 多操作员行为模拟器**

- 模块：`include/auditforwarder/simulator.h` + `shared/src/sim/cert_simulator.cpp`（纯逻辑，不涉及 IO）
- 命令行：`tools/sim_main.cpp` → 可执行文件 `build/auditforwarder-sim.exe`
- 场景 `cert_r42`：正常操作员（默认 4 人 × 8 条图书系统读/建/改）+ 4 组合谋攻击
  - 攻击 A：备份销毁合谋（删备份 → 卸载备份卷 → 快照），命中 R-001 与图谱角色互补
  - 攻击 B：数据批量外泄（提权 → 导出 → 清除），命中 R-004
  - 攻击 C：同一操作员导出后清除，命中 R-006（`group_by=operator`）
  - 攻击 D：同对象提权后外泄，命中 R-007（`group_by=object`）
- 可复现：`--seed`（内置 xorshift64*，避免 `<random>` 平台差异）；事件统一 `event_timestamp_us` 微秒时间戳并按时间升序输出
- 用法：`auditforwarder-sim --list` / `--scenario cert_r42 --operators 4 --output data/sim_events.jsonl` / `--no-attacks` 生成对照组

**2. 危害定级报告**

- `build_incident_report_markdown`（`server/src/collusion/collusion.cpp`）：把 `collusion_events.jsonl` 聚合为 Markdown
  - 概览：统计区间、风险事件总数（HIGH/MID/LOW 分布）、涉及规则数
  - 规则汇总表：命中次数、最高等级、最高评分
  - 逐事件证据链：证据规则、涉及操作员、资产组/分组维度、时间窗（微秒跨度）、评分构成（规则/画像/ML/图）、图谱指标、`evidence_timeline` 明细表
  - 单规则最多展示 20 条（按评分降序），`days<=0` 表示全量
- 接口：`GET /collusion/incident-report?days=7`，返回 `text/markdown`；`Engine::incident_report_markdown` 同步提供

**3. 演示脚本**

- `scripts/demo_m8.ps1`：登录 → 调用模拟器生成事件（默认回溯 120 分钟）→ **单批次**投递 `/collusion/ingest` → 导出 `incident_report.md` → 打印 overview
- 关键约束：事件必须**一次性批量投递**；逐条投递会即时冲刷资产组窗口，导致多步规则无法命中

**本机冒烟结果**（服务端 `127.0.0.1:18443`，数据目录 `data/demo_server_m8`）

| # | 检查项 | 结果 |
|---|--------|------|
| 1 | 模拟器生成 | 42 条事件（4 正常操作员 × 8 + 10 条攻击） |
| 2 | 单批次投递 | `cleaned_events=42`，`rules_count=7` |
| 3 | 风险事件 | HIGH=6 / MID=2 / LOW=3，全部待复核 |
| 4 | 规则命中 | R-001、R-004、R-006、R-007 各命中 2 次（长窗口弱线索 + 短窗口强线索） |
| 5 | 危害定级报告 | 规则汇总 + 证据时间线完整，含操作员、对象、动作与微秒时间窗 |

**多机联调**：需 ≥2 台客户端 + 1 台服务端现场执行（Radmin VPN / 局域网），依赖现场环境，尚未执行。

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
