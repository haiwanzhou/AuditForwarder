# AuditForwarder 开发文档

## 项目目标

AuditForwarder 是跨平台安全审计代理与集中管理系统，目标是采集主机审计事件、进行规则检测、生成可信批次、上报中心服务，并提供 Web 管理界面。

## 核心需求

- 采集系统事件、进程事件、文件事件、网络事件、命令事件。
- 使用规则引擎检测异常行为。
- 使用 SHA-256、Merkle Root 和 Ed25519 保护审计数据完整性。
- 支持 Agent 心跳、资源指标、审计摘要主动上报。
- 支持远端命令下发、Agent 拉取执行和结果回传。
- 支持多主机管理、状态监控、历史数据查询。
- 支持 Token、TLS/mTLS、命令白名单和加密命令队列。

## 非功能需求

- 稳定性：断线重试、本地缓存、服务重启后数据不丢失。
- 安全性：生产环境强制 HTTPS/TLS，敏感队列加密保存。
- 可维护性：模块接口清晰，跨平台逻辑通过条件编译隔离。
- 性能：批量处理审计摘要，避免高频小请求。
- 可扩展性：新增采集器、处理器、规则和远控命令时不影响主流程。

## 模块划分

| 模块 | 主要文件 | 职责 |
| --- | --- | --- |
| Agent | `include/auditforwarder/agent.h`, `client/src/core/agent.cpp` | 调度采集器、处理器、检测器、链、传输和管理服务 |
| Collector | `client/src/collector/*` | 采集本地操作和系统事件 |
| Processor | `client/src/processor/processor.cpp` | 事件补全、脱敏、去重 |
| Detector | `shared/src/detector/rule_engine.cpp` | 规则加载、匹配和响应 |
| Chain | `shared/src/crypto/chain.cpp` | 批次生成、Merkle Root、签名、持久化 |
| Remote Client | `client/src/core/remote_client.cpp` | 心跳、指标、审计摘要上报、命令拉取和结果回传 |
| Manager | `server/src/manager/manager_server.cpp` | HTTP/TLS API、主机管理、前端页面 |
| Web UI | `server/web/index.html`, `server/web/assets/*` | 图形化管理界面 |

## 远端监控闭环

```text
Agent 启动
→ 读取 remote.servers
→ 定时 POST /hosts/heartbeat
→ 定时 POST /agent/metrics
→ 批次生成后 POST /agent/audit-summaries
→ 定时 GET /hosts/commands?host_id=...
→ 执行白名单命令
→ POST /hosts/command-results
```

## 配置重点

Windows 本地测试使用：

```yaml
remote:
  enabled: true
  servers:
    - "http://127.0.0.1:8443"
  host_id: "test-agent-001"
  heartbeat_interval_sec: 10
  command_poll_interval_sec: 5
  allowed_commands:
    - collect_status
    - echo
```

生产环境建议：

```yaml
remote:
  production_mode: true
  require_tls: true

transport:
  verify_tls: true
  ca_cert: "/etc/auditforwarder/ca.pem"
  client_cert: "/etc/auditforwarder/client.pem"
  client_key: "/etc/auditforwarder/client.key"

manager:
  use_tls: true
  require_client_cert: true
  tls_ca_cert: "/etc/auditforwarder/ca.pem"
```

## 安全开发约束

- 不允许把远控接口实现为任意 shell 执行入口。
- 新增远控命令必须加入白名单，并实现明确的参数校验。
- 审计事件必须保持单行日志输出，禁止未清洗换行符进入日志。
- 批次文件必须保留原始审计数据，不做派生内容转换。
- 配置文件中的 URL 建议加引号，避免 YAML 冒号解析歧义。

## 新增功能流程

1. 在头文件定义清晰接口。
2. 在对应模块实现逻辑，避免跨模块直接访问内部状态。
3. 添加配置项并补齐解析映射。
4. 为 API 增加字段校验和错误提示。
5. 更新前端入口。
6. 更新文档和测试计划。
7. 执行构建、接口和系统验证。
