# 客户端-服务端协同日志分类与优先级管理系统 - 实施计划

> 切片原则：先定元数据契约（T1），再并行推进客户端标识/检测（T2/T3），随后打通优先传输（T4/T5）与服务端存储/过滤（T6/T7/T8），最后做界面（T9）、测试（T10）、端到端验证（T11）与文档（T12）。

## Task 1: 日志元数据契约与序列化（shared 基础层）
- **Status**: `done`
- **Priority**: high
- **Depends On**: None
- **Description**:
  - 新增 `include/auditforwarder/log_meta.h`：定义采集器规范 ID 常量（`file_win/process_win/network_win/command_win/registry_win/etw_win` 及 Linux 对应）、保留 attrs 键名（`collector/source/priority/priv_level/priv_operation/priv_ts/client_ts/raw_xml/event_id`）、优先级与权限级别常量，以及 inline helper：`tag_collector(ev,id)`、`collector_id(ev)`、`is_etw(ev)`、`mark_privileged(ev,level)`、`is_high_priority(ev)`、`stamp_client_ts(ev)`。
  - 核查并补全 `AuditEvent::to_json/from_json`（`shared` 中 event 序列化）：确保 `attrs`、新元数据进入 canonical JSON（/ingest 路径），哈希规范化确定且默认空值不改变既有事件哈希形态。
  - 提供 `sanitize_collector_id()`（供服务端目录名安全化，白名单字符 `[a-z0-9_]`，兜底 `unknown`）。
- **Acceptance Criteria Addressed**: AC-6, AC-9
- **Test Requirements**:
  - `rule` TR-1.1: 单元测试覆盖 helper 的打标/读取往返：打标后 collector_id/is_etw/mark_privileged/is_high_priority 取值正确；非法采集器名经 sanitize 后为 `unknown`，证据为 ctest 输出。
  - `rule` TR-1.2: 一个默认构造 AuditEvent 序列化→反序列化后 attrs 一致；含新元数据的事件 JSON 可被 from_json 完整还原，证据为单元测试断言。
  - `rubric` TR-1.3: 侵入性；scale 1-5；1=修改采集器主循环才能用，5=纯追加 helper/零结构体改动；threshold >= 4；证据为 diff 审查（仅新增头文件 + 序列化分支）。

## Task 2: 客户端采集器打标 + ETW 详情丰富
- **Status**: `done`
- **Priority**: high
- **Depends On**: T1
- **Description**:
  - Windows 六个采集器在构造事件后、submit 前统一调用 `tag_collector(ev, name())`（file/process/network/command/registry/etw）。
  - ETW 采集器：`source=etw_security`；取消 256 字符截断（上限可配，默认 4096），解析 XML 填充 attrs：`event_id`、`subject_user`、`subject_domain`、`logon_id`、`process_name`、`raw_xml`；按 EventID 继续现有分类。
  - Linux 各采集器同样打标（`*_linux` 规范 ID）。
- **Acceptance Criteria Addressed**: AC-1, AC-5
- **Test Requirements**:
  - `rule` TR-2.1: 编译通过且运行客户端后，服务端收到的日志每条 collector 非空，ETW（或注入 ETW）记录含 source=etw_security 且含 ≥6 个扩展字段，证据为 /logs/query 抽样输出。
  - `rule` TR-2.2: 现有 56 项测试仍通过，证据为 ctest 输出。
  - `rubric` TR-2.3: 采集器改动局部性；scale 1-5；1=改动采集判定逻辑，5=每个采集器仅追加 1~2 行打标调用；threshold >= 4；证据为 collectors_win.cpp / collectors_linux.cpp diff。

## Task 3: 高权限检测与事件标注
- **Status**: `done`
- **Priority**: high
- **Depends On**: T1
- **Description**:
  - 新增共享工具 `proc::is_elevated(pid)` 与 `proc::privilege_level(pid)`：
    - Windows：`OpenProcessToken` + `GetTokenInformation(TokenElevation)`，并通过 TokenUser SID 比对 `S-1-5-18` 判定 SYSTEM，输出 `elevated/system/none`；打不开令牌（权限不足/进程已退出）静默返回 none。
    - Linux：读 `/proc/<pid>/status` 的 Uid，0 → `root`。
  - 在进程启动、命令（shell）启动事件上调用并 `mark_privileged()`（priority=high + priv_level + priv_operation=1 + priv_ts）；ETW 4688/4624 从 XML 提权字段/主体 SID 标注。文件/注册表/网络事件不调用。
  - 加配置开关 `privilege_detect.enabled`（默认 true）与点到点缓存（pid→level 短 TTL）避免重复令牌查询。
- **Acceptance Criteria Addressed**: AC-2, AC-9
- **Test Requirements**:
  - `rule` TR-3.1: 注入/真实提权场景下产出的高权限记录含 priority=high、priv_level(elevated/system/root)、priv_operation=1、priv_ts、operation_type 五字段，证据为 /logs/query?priority=high 抽样 10 条断言。
  - `rule` TR-3.2: 单元测试对 privilege_level 解析逻辑（伪造 /proc/status 文本、SID 字符串判定）覆盖 root/SYSTEM/普通三类，证据为 ctest。
  - `rubric` TR-3.3: 性能影响；scale 1-5；1=对所有事件做令牌查询，5=仅启动类事件且带 TTL 缓存；threshold >= 4；证据为调用点代码审查。

## Task 4: 客户端双优先级传输通道
- **Status**: `done`
- **Priority**: high
- **Depends On**: T1, T3
- **Description**:
  - `HttpsTransport`：拆 `hi_queue_`/`queue_`；`send_batch` 按批次内最高事件优先级入队；worker 始终先排空高队列；以 condition_variable 替代固定 sleep，高优先级入队立即唤醒；上传失败的批次回到原优先级队列头部。
  - `RemoteAgentClient`：audit 队列拆高/普通两级；高权限事件最多合并 100ms 即发独立 POST `/agent/operation-logs`（信封 `priority=high`、`client_ts`），不等 5 秒摘要周期；普通日志维持现节奏；每条日志 JSON 输出 collector/source/priority/priv_*/client_ts 元数据。
  - 高/普通通道各自维护发送计数与入队→响应时间采样（内存滚动窗口），供服务端延迟统计以外的客户端自查（写日志即可）。
- **Acceptance Criteria Addressed**: AC-3, AC-6
- **Test Requirements**:
  - `rule` TR-4.1: 压送混合批次（含 1 条高优先级）时，高批次先于队列中先入的普通批次出队；高优先级入队到 worker 被唤醒 <50ms，证据为单元测试（队列顺序断言）。
  - `rule` TR-4.2: 抓包/服务端收到的 envelope 中高优先级请求带 `priority:"high"` 与 `client_ts`，普通请求不带或为 normal，证据为服务端接收日志/记录。
  - `rule` TR-4.3: 上传失败重试不把高优先级批次降级到普通队列，证据为单元测试。

## Task 5: 测试注入开关（可验证性保障）
- **Status**: `done`
- **Priority**: high
- **Depends On**: T2, T3
- **Description**:
  - 客户端配置新增 `test_injection: { enabled: false, interval_ms: 1000 }`（client_windows.yaml 中默认 false 并加注释「仅测试」）。
  - 启用后起轻量注入线程，周期合成两类事件走完整 `Agent::submit()`：① 打 `etw_win` 标的富字段事件（含 raw_xml/event_id 等 ≥8 字段）；② 模拟 SYSTEM/elevated 高权限进程启动事件（priority=high）。
  - 事件内容带可识别注入标记（attrs `injected=1`），便于测试后清理与断言；生产配置默认关闭。
- **Acceptance Criteria Addressed**: AC-1, AC-2, AC-3
- **Test Requirements**:
  - `rule` TR-5.1: enabled=false 时无任何 injected=1 事件到达服务端（运行 20 秒计数为 0）；enabled=true 时两类注入事件均可在服务端查到，证据为接口计数。
  - `rule` TR-5.2: 注入事件经过哈希链并在 /ingest 与 operation-logs 两边都出现，证据为 batch_id 关联查询。

## Task 6: 服务端主机/采集器两级存储与自动迁移
- **Status**: `done`
- **Priority**: high
- **Depends On**: T1
- **Description**:
  - 入库路由：`/agent/operation-logs` 每条记录按 `host_id` + `collector`（缺省 `unknown`）写入 `data/operation_logs/<host_id>/<collector>.jsonl`；高权限记录同时追加到 `<host_id>/privileged.jsonl` 索引视图（同一条记录，不复制大字段，仅引用或精简行）。
  - 每条记录入库时补 `server_ts`（毫秒 epoch）与归一化的 `collector/priority` 字段。
  - 启动迁移：扫描旧扁平文件 `<host>.jsonl` → 建 `<host>/` 并移动为 `legacy.jsonl`（逐行流式复制后删源，计数校验一致才删）；无旧文件、重复启动均安全；迁移失败仅 WARN 不阻断启动。
  - 改造 `read_jsonl_dir_filtered` 支持新目录结构（递归 host 子目录）与 `host_id`/`collector` 过滤；保留旧扁平文件读取兼容（迁移窗口期）。
  - 留存策略按 collector 文件维度保留（默认沿用 50000 行，可被 T7 策略覆盖）。
- **Acceptance Criteria Addressed**: AC-4, AC-10
- **Test Requirements**:
  - `rule` TR-6.1: 准备含 N 行的旧扁平文件，启动后生成 `<host>/legacy.jsonl` 行数=N、源文件消失；再次启动行数不变且无重复，证据为迁移前后行数与目录列表。
  - `rule` TR-6.2: 新日志落到 `<host>/<collector>.jsonl`，且 /logs/query 带/不带 host_id 都能读到新结构数据，证据为磁盘与接口双重断言。
  - `rule` TR-6.3: 高权限记录在 privileged.jsonl 中可查且字段完整，证据为文件/接口抽样。

## Task 7: 分采集器过滤策略档与配置 API
- **Status**: `done`
- **Priority**: high
- **Depends On**: T6
- **Description**:
  - 新增策略文件 `data/server/policy/log_filter_profiles.json`（不存在则用内置默认种子）：每采集器配置 `mode(strict/lenient)`、`message_max_len`、`retain_fields`（空=全保留）、`retention_lines`；内置 `etw_win=lenient`（上限 8192、全保留）、其他=strict（上限 512、收敛扩展字段）。
  - 入库管线按 collector 应用策略：截断 message、按字段白名单收敛（严格档丢弃 raw_xml 等重字段）；宽松档保留全部。
  - 新增管理 API：`GET /status/log-filter-profiles`、`PUT /status/log-filter-profiles`（与现有 violation-rules 接口同样的 Bearer 鉴权），保存后内存策略即时刷新。
- **Acceptance Criteria Addressed**: AC-5, AC-7
- **Test Requirements**:
  - `rule` TR-7.1: 同形状长消息（≥2000 字符、含 8 个扩展字段）分别打 etw_win 与 file_win 标入库，ETW 记录字段数/消息长度显著多于普通记录，平均字段数比值 ≥1.3，证据为字段计数脚本。
  - `rule` TR-7.2: PUT 修改 etw_win 为 strict 后新 ETW 记录立即按严格档收敛；GET 回读与 PUT 一致，证据为 API+入库双断言。
  - `rule` TR-7.3: 策略文件被删后重启能重新生成内置默认且服务正常，证据为重启验证。

## Task 8: 查询/统计增强（采集器、优先级、延迟）
- **Status**: `done`
- **Priority**: high
- **Depends On**: T6
- **Description**:
  - `/logs/query` 增加 `collector`、`priority` 查询参数（与既有 host_id/operation_type/时间范围可组合）。
  - 新增 `/logs/collector-counts?host_id=&from=&to=`：按 collector 分组计数（含 ETW 单独一行）。
  - 新增 `/stats/transfer-latency?host_id=`：基于记录内 client_ts/server_ts 输出 high/normal 两类样本数与平均、P95 延迟（毫秒）；仅统计两个时间戳都存在的记录。
  - 既有 `/logs/analytics` 兼容不破坏（在其基础上追加 collector 维度）。
- **Acceptance Criteria Addressed**: AC-1, AC-2, AC-3
- **Test Requirements**:
  - `rule` TR-8.1: collector-counts 返回分组且 etw_win 与非 ETW 计数与文件行数一致（误差 0），证据为接口值对比 `Get-Content | Measure-Object -Line`。
  - `rule` TR-8.2: transfer-latency 在两类各 ≥20 样本时输出 high_avg ≤ normal_avg/2（注入节流 100ms vs 普通 5s 周期下应显著成立），证据为接口 JSON 与脚本断言。
  - `rule` TR-8.3: 组合查询 host+collector+priority 结果均满足过滤条件（随机抽 20 条），证据为脚本断言。

## Task 9: Web「日志策略」配置页
- **Status**: `done`
- **Priority**: medium
- **Depends On**: T7, T8
- **Description**:
  - 在 index.html/app.js 现有单页框架内新增「日志策略」导航页：采集器策略表（档位严格/宽松下拉、消息截断长度、留存条数）、高权限检测开关展示（服务端侧策略项）、保存/重置按钮；保存调用 T7 的 PUT 接口并提示成功。
  - 页内展示 collector-counts 与 transfer-latency 两组统计（表格 + 简单数字卡片，复用现有样式）。
  - 日志查询页（已有）增加采集器与优先级筛选下拉。
- **Acceptance Criteria Addressed**: AC-7
- **Test Requirements**:
  - `rule` TR-9.1: 浏览器实际打开页面，策略表正确加载当前配置；修改 file_win 截断长度保存后刷新仍为新值，证据为浏览器 DOM 快照/截图。
  - `rule` TR-9.2: 修改后新入库 file_win 记录按新长度截断，证据为入库记录断言。
  - `rubric` TR-9.3: 可用性与风格一致性；scale 1-5；1=新页面风格割裂/无响应反馈，5=复用现有组件风格、有加载/成功/失败反馈；threshold >= 4；证据为浏览器实测。

## Task 10: 单元测试与全量回归
- **Status**: `done`
- **Priority**: high
- **Depends On**: T1, T4, T6, T7
- **Description**:
  - 新增测试：log_meta helper、事件 JSON 往返、传输优先级队列顺序/重试不降级、存储路径路由与迁移幂等、过滤策略截断/字段白名单、collector 名安全化。
  - 全量 `ctest` 通过；新增可执行测试纳入既有 CMake 测试目标。
- **Acceptance Criteria Addressed**: AC-8
- **Test Requirements**:
  - `rule` TR-10.1: `cmake --build` 零错误完成，证据为构建日志。
  - `rule` TR-10.2: `ctest --output-on-failure` 全部通过（原 56 项 + 新增项，数量在完成证据中列明），证据为 ctest 汇总输出。

## Task 11: 端到端验证（脚本 + 真实链路复核）
- **Status**: `done`
- **Priority**: high
- **Depends On**: T5, T8, T9, T10
- **Description**:
  - 编写一次性验证脚本（PowerShell，置于会话证据中，不入库或放 scripts/test/ 均可）：从零启动 server + 开注入的 client，采集 AC-1/AC-3/AC-5 所需数据并自动断言；检查目录结构与迁移行数；对比 /ingest 与 operation-logs 元数据。
  - 管理员 PowerShell 中做一次真实 ETW/提权链路复核（如环境允许；不可行则记录为部署后人工项，以注入证据为准）。
- **Acceptance Criteria Addressed**: AC-1, AC-2, AC-3, AC-4, AC-5, AC-6, AC-8
- **Test Requirements**:
  - `rule` TR-11.1: 脚本一次运行输出 AC-1/AC-3/AC-5 三个量化断言全部 PASS（字段非空率、延迟比 ≤0.5、字段数比 ≥1.3），证据为脚本完整输出。
  - `rule` TR-11.2: 目录结构含 <host>/etw_win.jsonl、legacy.jsonl，迁移行数守恒，证据为目录与行数输出。
  - `rule` TR-11.3: ≥3 个 batch_id 在两条路径元数据一致；真实链路复核结果记录（通过或注明阻塞原因），证据为比对输出。

## Task 12: 操作手册更新
- **Status**: `done`
- **Priority**: low
- **Depends On**: T7, T9
- **Description**:
  - 在《项目操作手册.md》新增小节：日志分类/优先级机制说明、存储目录结构、过滤策略配置（API + Web 页）、测试注入开关的用途与安全警告、管理员运行客户端获取真实 ETW 的步骤。
- **Acceptance Criteria Addressed**: AC-7
- **Test Requirements**:
  - `rubric` TR-12.1: 文档可操作性；scale 1-5；1=只描述概念无操作步骤，5=含配置示例/验证命令/故障提示且与最终实现一致；threshold >= 4；证据为文档审读。
