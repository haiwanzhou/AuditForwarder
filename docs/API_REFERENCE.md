# AuditForwarder API 文档

本文档说明管理端和 Agent 主动上报相关接口。所有受保护接口默认使用：

```http
Authorization: Bearer <manager.auth_token>
```

生产环境应启用 HTTPS/TLS；如开启 mTLS，应同时配置客户端证书。

## 数据库存储说明

当前服务端 API 路径保持稳定，关系型数据库升级方案见：

- `docs/DATABASE_DESIGN.md`：数据库 ER 图、表结构、字段说明、索引、权限模型和备份策略。
- `docs/DATABASE_API.md`：主机 CRUD、操作日志、管理员账号、权限控制的 SQL/API 映射和示例代码。
- `scripts/database/postgresql/001_schema.sql`：PostgreSQL 建表脚本。
- `scripts/database/postgresql/002_seed.sql`：基础角色、管理员占位账号和测试主机初始化脚本。
- `scripts/database/postgresql/backup_restore.ps1`：备份与恢复脚本。

## 认证与登录

### POST /auth/login

用途：管理员登录。前端会先使用 Web Crypto 计算密码 SHA-256，再提交到服务端；服务端与配置中的 `manager.login_username` 和 `manager.login_password_sha256` 做严格匹配。

请求示例：

```json
{
  "username": "admin",
  "password_sha256": "<你的密码SHA256哈希，请自行生成>"
}
```

成功响应：

```json
{
  "token": "af-...",
  "token_type": "Bearer",
  "expires_in": 28800,
  "username": "admin",
  "redirect": "/"
}
```

失败响应统一返回“账号或密码不正确”，不会暴露具体是账号错误还是密码错误。连续 3 次失败后，同一账号与来源 IP 会临时锁定 15 分钟并返回 `429 login_locked`。

登录审计记录保存到：

```text
data/server/login_audit.jsonl
```

生产环境必须启用 HTTPS/TLS，避免认证令牌和密码哈希在明文 HTTP 中传输。

## 状态与配置

### GET /health

用途：健康检查。

### GET /status

用途：查看服务运行状态、事件计数、运行时间等信息。

### GET /config

用途：查看当前加载配置。

## 主机管理

### GET /hosts

用途：查看所有主机信息、在线状态和资源占用摘要。

### POST /hosts

用途：新增主机。

必填字段：

```json
{
  "name": "client-01",
  "ip_address": "192.168.1.10",
  "hardware": "cpu_threads=8",
  "os_version": "Windows 11",
  "permissions": ["collect_status", "echo"]
}
```

### PUT /hosts?id=<host_id>

用途：编辑主机信息。

### DELETE /hosts?id=<host_id>

用途：删除主机记录。

### POST /hosts/heartbeat

用途：Agent 上报心跳和资源摘要。服务端配置了 `manager.enrollment_key` 时，请求体必须携带相同的 `enrollment_key`，否则返回 `401 invalid_enrollment_key`，主机不会加入监管列表。

### POST /hosts/register

用途：Agent 首次注册到监管系统。当前实现与 `/hosts/heartbeat` 使用同一套保存逻辑：密钥验证通过后新增或更新主机信息，并分配客户端上报的权限列表。

```json
{
  "host_id": "test-agent-001",
  "name": "client-01",
  "ip_address": "192.168.1.10",
  "hardware": "cpu_threads=8",
  "os_version": "Windows 11",
  "network_status": "online",
  "enrollment_key": "<你的注册密钥>",
  "cpu_usage_percent": 25,
  "memory_usage_percent": 63,
  "permissions": ["collect_status", "echo"]
}
```

## 指标与审计摘要

### POST /agent/metrics

用途：Agent 上报 CPU、内存、磁盘、网络指标。服务端按主机保存到 `data/host_metrics/<host_id>.jsonl`。

服务端会读取 `/status/thresholds` 中的阈值策略；指标超过阈值时，会自动写入 `data/alerts/<host_id>.jsonl`。

### GET /status/thresholds

用途：查看主机状态阈值策略，包括 CPU、内存、磁盘和网络流量告警阈值。

### PUT /status/thresholds

用途：更新主机状态阈值策略。请求体为 JSON 对象。

### POST /agent/audit-summaries

用途：Agent 批量上报本地审计批次摘要。服务端保存到 `data/audit_summaries/<host_id>.jsonl`。

### POST /agent/operation-logs

用途：Agent 上传结构化操作日志。服务端保存到 `data/operation_logs/<host_id>.jsonl`，并按违规规则实时分析。

```json
{
  "host_id": "test-agent-001",
  "timestamp": "2026-07-02T10:00:00Z",
  "operation_type": "execute",
  "actor": "user01",
  "object": "cmd.exe",
  "command": "whoami",
  "status": "success",
  "message": "执行命令"
}
```

也支持批量格式：

```json
{
  "host_id": "test-agent-001",
  "logs": [
    { "timestamp": "2026-07-02T10:00:00Z", "operation_type": "file", "message": "read password.txt" }
  ]
}
```

### GET /logs/query?host_id=<host_id>&operation_type=<type>&from=<iso>&to=<iso>&limit=<n>

用途：按主机 ID、操作类型、时间范围查询结构化操作日志。

### GET /logs/analytics?host_id=<host_id>&from=<iso>&to=<iso>&limit=<n>

用途：汇总结构化操作日志和违规告警，返回日志总数、告警总数、操作类型分布、告警级别分布和主机记录分布，用于前端可视化分析。

### GET /hosts/history?host_id=<host_id>&kind=<metrics|audit|commands|logs|alerts>

用途：查询主机历史指标、审计摘要、命令结果、操作日志或告警记录。

## 违规检测与告警

### GET /violation/rules

用途：查看服务端违规操作规则库。首次访问会自动生成默认规则文件 `data/policies/violation_rules.json`。

### PUT /violation/rules

用途：动态更新违规规则。请求体必须包含 `rules` 数组。

### GET /alerts?host_id=<host_id>&limit=<n>

用途：查询系统内告警。告警来源包括指标阈值检测和操作日志违规规则检测。

### GET /rbac/policy

用途：查看当前 RBAC 策略说明。当前版本使用 Bearer Token 完成接口认证，认证通过后内置为 `admin` 角色；生产环境可扩展为用户表、角色绑定和细粒度接口授权。

## 跨操作员合谋协同检测（v1.1.0）

以下接口均需登录 Bearer Token，数据存储于 `data/server/collusion/` 与 `data/server/policies/collusion_*.json`。

### GET /collusion/overview

用途：返回引擎开关、双窗口时长、风险阈值、规则/资产组数量、画像覆盖、各级别事件计数与待复核数。

### GET /collusion/events?level=<HIGH|MID|LOW>&status=<处置状态>&limit=<n>

用途：按级别和处置状态查询风险事件（新事件在前，默认 100 条）。每条事件含评分、规则因子、画像因子、命中规则、涉事操作员、判定依据、处置对象和证据时间线。

### GET /collusion/events/detail?id=<event_id>

用途：返回单个风险事件完整 JSON；不存在返回 404。

### GET /collusion/events/export?id=<event_id>

用途：导出证据链 JSON（响应内容与 detail 相同，供审计归档下载）。

### POST /collusion/events/dispose

用途：处置风险事件。状态仅限 `待复核`、`确认合谋攻击`、`合法运维（误报）`、`待进一步调查`，非法状态返回 422。处置全程追加写入 `data/server/collusion/audit.jsonl`。

```json
{
  "event_id": "ce-xxxxxxxxxxxxxxxx",
  "status": "合法运维（误报）",
  "disposer": "admin",
  "note": "变更窗口内已报备操作"
}
```

### GET/PUT /collusion/config

读取 / 保存检测引擎配置（窗口、阈值、资产组、白名单、降噪等）。PUT 保存后约 2 秒热生效；窗口越界自动钳制，`asset_groups` 为空时返回 422。

### GET/PUT /collusion/rules

读取 / 保存规则库（PUT 体需含 `rules` 数组）。规则字段：`rule_id`、`name`、`enabled`、`asset_group`、`min_operator_cnt`、`base_score`、`op_sequence`（有序子序列，每步 `any_of` 关键词任一命中即可）。

### GET/PUT /collusion/workorders

读取 / 保存工单注册表，用于工单外部核验（存在性、状态、允许操作员、有效期四要素）。

### POST /collusion/emergency

用途：开启/解除应急运维模式。请求体：

```json
{ "enabled": true, "duration_minutes": 120, "actor": "admin" }
```

生效期间新评估事件风险等级自动降一级。

### GET /collusion/report?days=<n>

用途：生成近 N 天（1~180，默认 7）合谋行为分析报表，含各级别事件数、规则命中分布、按天趋势、确认攻击数、误报数与待复核数。

### POST /collusion/ingest

用途：接入设计文档原生格式审计事件（支持 `{"events":[...]}` 批量或单对象），供外部系统直连与演练。仅接收执行成功（`return_code=0` 且非失败 outcome）的事件。

## 远程控制

### POST /remote/control

用途：向指定主机下发受控命令。

```json
{
  "target_host_id": "test-agent-001",
  "command_type": "collect_status",
  "payload": "{}"
}
```

说明：

- 命令按 `target_host_id` 写入独立队列。
- 队列使用 AES-256-GCM 加密保存。
- Agent 只执行白名单命令，不执行任意 shell 字符串。

### GET /hosts/commands?host_id=<host_id>

用途：Agent 拉取自己的待执行命令。

### POST /hosts/command-results

用途：Agent 回传命令执行结果，字段包括成功/失败、输出、错误信息和执行耗时。

## 校验规则

### GET /validation/rules

用途：获取前后端共享的校验规则说明。

## 返回码

| 状态码 | 含义 |
| --- | --- |
| 200 | 请求成功 |
| 201 | 创建成功 |
| 401 | 缺少或错误的 Token |
| 404 | 资源不存在 |
| 422 | 字段校验失败 |
| 500 | 服务端处理失败 |
