# 客户端-服务端协同日志分类与优先级管理系统 - 产品需求文档

## Overview
- **Summary**: 为 AuditForwarder 增加日志来源（采集器）标识、高权限操作识别、多级优先传输、服务端按「主机/采集器」物理隔离存储、ETW 安全日志宽松过滤、可配置策略管理界面，形成客户端与服务端协同的日志管理闭环。
- **Purpose**: 现有系统所有采集器日志混在一起、高权限操作无特殊通道、ETW 安全日志在客户端被截断到 256 字符、服务端扁平存储无法按来源区分，导致安全事件（尤其提权操作、Windows 安全日志）无法快速识别与完整保全。
- **Target Users**: 安全运维人员（Web 管理台使用者）、本机高权限操作员、项目开发者/测试人员。

## Goals
- 每条日志携带采集器类型元数据，ETW 安全日志可被唯一识别与统计。
- 高权限操作（Windows 提权管理员/SYSTEM、Linux root）自动标注并走高优先级通道，端到端延迟较普通日志降低 ≥50%。
- 服务端按「主机 → 采集器」两级目录物理隔离存储；ETW 日志走宽松过滤，保留字段数比普通日志多 ≥30%。
- Web 端提供日志分类、优先级、过滤规则的可视化配置并即时生效。
- 元数据在两条传输路径（operation-logs JSON 与 /ingest 编码批次）中均不丢失。

## Non-Goals
- 不重写现有哈希链/Merkle 存证机制；高权限事件仍必须入链，不脱离证据链。
- 不做内核态监控；Windows 文件采集器（ReadDirectoryChangesW）本身不提供 PID，文件事件不做进程级提权归属。
- 不做日志全文检索引擎（ES/Lucene 类），仍沿用 JSONL 文件存储。
- 不实现真实 ETW 之外的新操作系统日志源（如 Sysmon）。
- 不改动服务端告警规则引擎的既有判定语义。

## Background & Context
- 客户端 6 个 Windows 采集器（file/process/network/command/registry/etw）各自构造 `AuditEvent` 后调 `Agent::submit()`，事件已含 `attrs`（map）扩展字段，结构定义见 `include/auditforwarder/event.h`。
- 两条上传路径：① `RemoteAgentClient` 每 5 秒把批次展开为逐条 JSON POST 到 `/agent/operation-logs`（Web 页面读这个）；② `HttpsTransport` 实时把编码批次 POST 到 `/ingest`。两者目前都是 FIFO，无优先级。
- 服务端操作日志扁平存储为 `data/operation_logs/<host_id>.jsonl`（保留最近 50000 条/主机），无采集器维度。
- ETW 采集器（`WindowsEtwCollector`）订阅 Security 通道 4624/4625/4688/4689，非管理员运行时订阅失败（仅 WARN，非致命）；当前 XML 被截断到 256 字符存入 message。
- Web 前端为原生单页应用：`server/web/index.html` + `server/web/assets/app.js`（约 1200 行）。
- 用户已确认的决策：
  1. 「root」= Windows 高完整性提权令牌/SYSTEM + Linux uid=0；
  2. 验证采用「真实采集 + 默认关闭的测试注入开关」双轨；
  3. 配置界面为表单式「日志策略」页；
  4. 旧扁平日志在服务端启动时自动迁移到 `<host>/legacy.jsonl`。

## Functional Requirements

### 客户端：来源标识
- **FR-1**: 每个采集器在提交事件时写入统一的采集器标识元数据（规范 ID，如 `etw_win`、`file_win`），ETW 事件另加唯一来源标记（`source=etw_security`）。
- **FR-2**: ETW 采集器保留更完整的事件详情：不做 256 字符截断，解析并填充 EventID、主体用户、域、登录 ID、进程名等结构化字段，原始 XML 存入扩展字段。

### 客户端：高权限检测与标注
- **FR-3**: Windows 侧通过进程令牌检测提权（`TokenElevation` 高完整性 / SYSTEM 账户 S-1-5-18），Linux 侧检测 uid=0；命中时为事件写入：高优先级标识、权限级别、操作类型、检测时间戳。
- **FR-4**: 检测覆盖进程启动、命令（shell）启动、ETW 4688/4624 三类可归属的事件；文件/注册表/网络事件因无 PID 归属不做提权标注。

### 客户端：优先传输
- **FR-5**: operation-logs 通道维护高/普通两级队列：高权限事件立即发送（独立请求、信封带 `priority` 字段与客户端时间戳），普通日志维持现有摘要节奏。
- **FR-6**: /ingest 编码批次通道同样具备高优先级队列，高优先级批次先于队列中既有普通批次发送，且入队即唤醒工作线程。
- **FR-7**: 提供默认关闭的测试注入开关，开启后按间隔合成 ETW 标记事件与高权限事件，走完整 submit/链/传输链路。

### 服务端：存储与过滤
- **FR-8**: 操作日志按 `data/operation_logs/<host_id>/<collector>.jsonl` 存储；无采集器字段的历史数据在启动时自动迁移到 `<host_id>/legacy.jsonl`，迁移可重复执行不丢数据。
- **FR-9**: 入库时按采集器应用过滤策略档：默认档对消息截断/字段收敛；ETW 档宽松（大截断上限、保留扩展详情字段）；策略可通过 API 与 Web 页配置并即时生效。
- **FR-10**: 高优先级请求走快速处理路径并先落盘；记录中保存服务端接收时间戳。
- **FR-11**: 查询/统计接口支持按采集器、优先级过滤，并输出分采集器日志计数与分优先级平均传输延迟（基于客户端/服务端时间戳）。

### Web 配置界面
- **FR-12**: 新增「日志策略」页：按采集器配置过滤档位（严格/宽松）、消息截断长度、留存条数；高权限检测开关；保存后服务端即时生效，并可查看分采集器计数与延迟统计。

## Non-Functional Requirements
- **NFR-1（最小影响）**: 注入开关与提权检测默认行为不影响既有采集器；关闭注入时事件流量与现状一致；现有 56 项单元测试全部通过。
- **NFR-2（元数据完整性）**: 采集器/优先级/权限标注在 operation-logs 与 /ingest 两条路径端到端保持一致，服务端可直接读取。
- **NFR-3（性能）**: 提权检测（OpenProcessToken）仅在进程/命令启动事件上执行，不得对高频文件/网络事件做令牌查询；客户端 CPU 占用相对现状增幅可忽略。
- **NFR-4（可验证性）**: 全部验收指标可用自动化脚本（curl + JSON 断言）复现，不依赖人工目测。

## Constraints
- **Technical**: C++17、MSYS2 UCRT64 GCC、原生 WinAPI；无新第三方依赖；前端继续用原生 HTML/JS；JSONL + 文件锁存储。
- **Business**: Windows 测试环境客户端默认非管理员，真实 ETW 订阅可能失败，因此验证依赖 FR-7 注入开关；真实链路需在管理员 PowerShell 中人工复核一次。
- **Dependencies**: 现有 `AuditEvent.attrs`、哈希链、HttpsTransport、manager_server 路由与 Web 单页框架。

## Assumptions
- 同一主机时钟误差对延迟测量影响可接受（客户端与服务端在同一台机器验证；跨机部署时指标仅作参考）。
- 高权限事件量占比很低，单独立即发送不会造成请求风暴（默认节流：每 100ms 合并一次高优先级批次）。
- 旧 `data/operation_logs/*.jsonl` 均为测试数据，迁移失败时仅告警不阻断启动。
- 采集器规范 ID 直接使用现有 `Collector::name()` 返回值（`file_win`/`etw_win`/…），保持单一事实来源。

## Acceptance Criteria

### AC-1: 日志带来源标识且 ETW 可唯一识别与统计
- **Type**: `rule`
- **Given**: 客户端开启测试注入并运行 ≥30 秒
- **When**: 查询服务端日志计数接口
- **Then**: 返回结果按 collector 分组计数，`etw_win` 与其他采集器计数分别 > 0；每条 ETW 记录含 `collector=etw_win` 且 `source=etw_security`
- **Pass Condition**: 计数接口存在且 collector 分组中 `etw_win ≥ 1`、非 ETW 合计 ≥ 1；随机抽取 10 条记录全部含非空 `collector` 字段
- **Evidence**: 脚本对 `/logs/analytics`（或新增计数接口）的 JSON 断言输出

### AC-2: 高权限操作被完整标注
- **Type**: `rule`
- **Given**: 注入开关开启（或管理员身份真实启动一个提权进程）
- **When**: 高权限事件到达服务端
- **Then**: 对应记录含 `priority=high`、`priv_level ∈ {elevated, system, root}`、`priv_operation=1`、`priv_ts`（时间戳）、`operation_type`
- **Pass Condition**: 抽样高优先级记录 10 条（不足全取），5 个字段全部非空且取值合法
- **Evidence**: `/logs/query?priority=high` 返回记录的字段断言

### AC-3: 高优先级日志传输延迟降低 ≥50%
- **Type**: `rule`
- **Given**: 注入开关开启，高/普通两类日志各产生 ≥20 条
- **When**: 服务端统计两类记录的 `server_ts - client_ts` 平均值
- **Then**: avg(高优先级延迟) ≤ 0.5 × avg(普通延迟)
- **Pass Condition**: 统计接口返回两类平均值且布尔断言 `high_avg <= normal_avg/2` 为真
- **Evidence**: 延迟统计接口 JSON + 脚本计算输出

### AC-4: 服务端按主机/采集器物理隔离存储且旧数据完成迁移
- **Type**: `rule`
- **Given**: 服务端启动前存在旧文件 `data/operation_logs/<host>.jsonl`
- **When**: 服务端启动并接收新日志后检查磁盘
- **Then**: 出现 `data/operation_logs/<host>/etw_win.jsonl` 等采集器文件与 `<host>/legacy.jsonl`；旧 `<host>.jsonl` 不再存在；legacy 记录数 = 迁移前记录数
- **Pass Condition**: 目录结构断言 + 迁移前后行数相等
- **Evidence**: `Get-ChildItem -Recurse` 输出与行数统计

### AC-5: ETW 宽松过滤保留字段数多 ≥30%
- **Type**: `rule`
- **Given**: 注入产生同批 ETW 与非 ETW 记录各 ≥10 条
- **When**: 统计入库后两类记录的平均 JSON 字段（含嵌套扩展字段）数量
- **Then**: avg(ETW 字段数) ≥ 1.3 × avg(普通记录字段数)
- **Pass Condition**: 脚本逐行统计 JSON 键数量并做比值断言
- **Evidence**: 字段计数脚本输出（含两组均值与比值）

### AC-6: 元数据在两条传输路径完整保持
- **Type**: `rule`
- **Given**: 注入开启且服务端同时接收 operation-logs 与 /ingest 数据
- **When**: 对比两条路径落盘的同一 batch_id 数据
- **Then**: collector / priority / priv_level 等元数据在两边均可读到且取值一致
- **Pass Condition**: 从 ingested 批次中解码出的事件 attrs 与 operation-logs 记录字段一一对应（至少 3 个 batch_id 全部一致）
- **Evidence**: 脚本比对输出

### AC-7: Web 日志策略页可配置并即时生效
- **Type**: `rule`
- **Given**: 管理员已登录 Web 台
- **When**: 在「日志策略」页修改某采集器截断长度/档位并保存，再发一条该采集器日志
- **Then**: 保存接口返回成功；重新加载页面显示新值；新入库记录按新策略截断/保留
- **Pass Condition**: API GET/PUT 往返一致 + 入库记录验证策略生效；浏览器中页面真实渲染
- **Evidence**: API 断言 + 浏览器截图/DOM 快照

### AC-8: 回归与构建
- **Type**: `rule`
- **Given**: 全部改动完成
- **When**: 从零重新构建并运行 ctest
- **Then**: 编译零错误（既有警告不增加），全部单元测试通过（原 56 项 + 新增项）
- **Pass Condition**: `cmake --build` 成功且 `ctest` 全绿
- **Evidence**: 构建与测试命令输出

### AC-9: 对既有流程影响最小化
- **Type**: `rubric`
- **Dimension**: 关闭新功能时的行为一致性与代码侵入性
- **Scale**: 1-5
- **Anchors**: 1 = 改动侵入既有采集器主循环逻辑、关闭功能仍改变日志形态/流量；3 = 侵入但有开关隔离，默认行为基本不变；5 = 仅追加式改动（元数据 helper/新文件/新端点），默认关闭时日志字节与流量与现状无差异
- **Pass Threshold**: >= 4
- **Evidence**: 代码 diff 结构审查 + 关闭注入时客户端日志样本对比

### AC-10: 迁移幂等且不丢数据
- **Type**: `rule`
- **Given**: 已经迁移过一次的数据目录
- **When**: 服务端再次启动
- **Then**: 不重复迁移、不报错、legacy.jsonl 行数不变；无旧文件时启动也正常
- **Pass Condition**: 连续启动两次服务端，legacy 行数恒定，日志无迁移错误
- **Evidence**: 两次启动日志与行数统计

## Open Questions
- 无（4 个关键决策已通过澄清确认；如管理员真实提权验证无法在当前环境完成，以注入链路证据为准，真实链路留作部署后人工复核项）。
