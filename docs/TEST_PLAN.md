# AuditForwarder 测试计划

## 测试目标

验证系统在本地和多主机场景下能够稳定完成事件采集、规则检测、批次生成、远端上报、命令下发、结果回传和前端管理。

## 单元测试

| 范围 | 验证点 |
| --- | --- |
| 配置解析 | YAML/JSON、内联列表、注释、带引号 URL、文件后缀识别 |
| 事件模型 | JSON 输出合法、字段完整、哈希稳定 |
| 规则引擎 | 规则加载、列表字段解析、阈值窗口、响应动作 |
| Chain | 批次大小、Merkle Root、签名、批次文件格式 |
| 校验模块 | 必填、格式、长度、范围、错误返回 |
| Remote Client | 指标 JSON、命令白名单、结果 JSON |

## 集成测试

1. 启动 `auditforwarderd`。
2. 使用 Token 访问 `/status`、`/config`、`/hosts`。
3. 等待 Agent 上报 `/hosts/heartbeat` 和 `/agent/metrics`。
4. 通过 `/hosts/history?kind=metrics` 验证指标落盘。
5. 调用 `/remote/control` 下发 `collect_status`。
6. 等待 Agent 拉取命令并回传结果。
7. 通过 `/hosts/history?kind=commands` 验证结果落盘。
8. 生成审计批次后验证 `/agent/audit-summaries` 历史记录。
9. 调用 `/status/thresholds` 验证服务端阈值策略可读取和更新。
10. 向 `/agent/operation-logs` 上传结构化操作日志，验证 `/logs/query` 可按主机和操作类型查询。
11. 上传超阈值指标和命中规则的操作日志，验证 `/alerts` 生成对应告警。
12. 调用 `/rbac/policy` 验证角色权限策略可读取。

## 系统测试

| 场景 | 预期结果 |
| --- | --- |
| 无 Token 访问受保护接口 | 返回 401 |
| 非法字段提交 | 返回 422 和字段级错误 |
| Agent 正常运行 | 主机状态在线，资源指标持续更新 |
| Agent 停止超过 90 秒 | 主机状态离线 |
| 下发允许命令 | 命令成功执行并回传结果 |
| 下发未授权命令 | Agent 拒绝执行并记录失败结果 |
| 服务重启 | `data/hosts.json` 和历史 JSONL 数据仍存在 |
| 批次生成 | 批次 JSON 可解析，事件分隔正确 |
| 指标超过阈值 | 自动生成 `metric_threshold` 告警 |
| 操作日志命中违规规则 | 自动生成 `violation_rule` 告警 |
| 日志检索 | 支持按 `host_id`、`operation_type`、时间范围和数量上限查询 |
| 主机数量达到上限 | 新主机注册返回 409，已注册主机心跳不受影响 |

## 安全测试

- 验证生产配置开启 `remote.require_tls=true` 后拒绝 HTTP 地址。
- 验证 TLS 最低版本为 TLS 1.2。
- 验证命令队列文件为 AES-256-GCM 加密内容。
- 验证主机权限不包含某命令时无法下发或无法执行。
- 验证日志输出不会因换行、制表符导致折行。
- 验证 `/rbac/policy` 中角色权限定义符合管理、运维和审计分工。
- 验证操作日志和告警只允许携带合法 `host_id`，非法字段返回 422。

## 性能与稳定性测试

- 连续运行 24 小时，观察内存、句柄和线程数量。
- 批量生成审计事件，验证批次写入和摘要上报不会阻塞采集。
- 断开服务器后恢复连接，验证 Agent 可继续上报。
- 多客户端并发心跳，验证 `/hosts` 和历史查询稳定。
- 按 `manager.max_host_count` 规划压力测试规模，至少覆盖配置值对应的并发主机数。
- 高频上传 `/agent/metrics` 和 `/agent/operation-logs`，验证 JSONL 保留策略不会导致内存持续增长。

## 本地验证命令

```powershell
$env:MSYS2_ROOT = "<MSYS2安装目录>"
$env:PATH = "$env:MSYS2_ROOT\ucrt64\bin;$env:MSYS2_ROOT\usr\bin;$env:PATH"
make -C build -j4
ctest --test-dir build --output-on-failure
node --check server\web\assets\app.js
.\build\auditforwarderd.exe -c config\agent_windows.yaml -d data -L info
```

## 当前已执行验证

- 构建通过。
- 规则文件完整加载 10 条规则。
- Agent 心跳和资源指标写入 `data/host_metrics/test-agent-001.jsonl`。
- `/remote/control` 下发 `collect_status` 成功。
- Agent 拉取并执行命令，结果写入 `data/command_results/test-agent-001.jsonl`。
- `/status/thresholds` 可读取默认 CPU/内存/磁盘/网络阈值。
- `/agent/metrics` 接收超阈值 CPU 指标后生成 `metric_threshold` 告警。
- `/agent/operation-logs` 接收危险命令日志后生成 `violation_rule` 告警。
- `/logs/query`、`/alerts`、`/hosts/history?kind=logs|alerts` 查询成功。
- `node --check server\web\assets\app.js` 通过。

## 已知非阻塞项

- Windows ETW Security 日志订阅需要管理员权限，普通权限下会出现 `EvtSubscribe` 失败。
- 当前 CTest 项目返回成功，但测试用例数量较少，后续应补充配置解析和远端客户端单元测试。
