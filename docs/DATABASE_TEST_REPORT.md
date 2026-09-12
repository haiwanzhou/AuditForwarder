# AuditForwarder 数据库功能验证测试报告

测试时间：2026-07-03  
测试环境：Windows，本地工作目录 `<项目目录>`  
构建目录：`build_db_verify`

## 1. 测试目标

本次测试验证服务端数据库相关交付物和运行链路，包括：

- 数据库模型、校验规则和 CRUD 仓储接口是否可编译、可执行。
- 管理员、主机、主机日志三类核心数据是否支持创建、读取、更新和删除。
- 服务端应用是否能启动并完成登录、状态查询、主机管理、日志上传和日志查询。
- PostgreSQL 脚本是否覆盖关系型表结构、主键、外键、索引和约束设计。

## 2. 环境检查

| 检查项 | 结果 | 说明 |
| --- | --- | --- |
| CMake 配置 | 通过 | `cmake -S . -B build_db_verify -DBUILD_TESTING=ON` |
| 项目编译 | 通过 | 生成 `auditforwarder-server.exe`、`auditforwarder-client.exe`、`auditforwarderd.exe` 和 `auditforwarder_tests.exe` |
| PostgreSQL 客户端 `psql` | 未安装 | 当前环境无法执行真实 PostgreSQL 建库和连接测试 |
| PostgreSQL 健康检查工具 `pg_isready` | 未安装 | 当前环境无法检测本机 PostgreSQL 服务状态 |

## 3. 自动化测试结果

执行命令：

```powershell
cmake -S . -B build_db_verify -DBUILD_TESTING=ON
cmake --build build_db_verify --config Release
ctest --test-dir build_db_verify --output-on-failure
```

结果：

```text
1/1 Test #1: auditforwarder_tests ............. Passed
100% tests passed, 0 tests failed out of 1
```

数据库相关单元测试覆盖：

| 功能 | 结果 | 说明 |
| --- | --- | --- |
| 管理员创建 | 通过 | `InMemoryDatabaseStore::create_admin` 可创建合法管理员 |
| 管理员重复写入拦截 | 通过 | 重复 `user_id` 返回错误 |
| 管理员按用户名读取 | 通过 | 用户名大小写不敏感查询正常 |
| 密码安全校验 | 通过 | 明文样式密码被拒绝，Argon2id 哈希样式通过 |
| 主机写入 | 通过 | `upsert_host` 可保存主机 ID、名称、IP、端口、系统和硬件 JSON |
| 主机日志写入 | 通过 | 日志必须关联已存在主机 |
| 主机日志查询 | 通过 | 可按 `host_id` 和 `log_type` 查询 |
| 主机日志状态更新 | 通过 | `new` 可更新为 `parsed` |

## 4. 服务端运行时验证

启动命令：

```powershell
.\build_db_verify\auditforwarder-server.exe -c config\server_windows.yaml
```

运行时接口测试结果：

| 测试项 | 接口 | 结果 |
| --- | --- | --- |
| 管理员登录 | `POST /auth/login` | 通过，返回 Bearer Token |
| 服务状态查询 | `GET /status` | 通过，`running=true` |
| 主机新增 | `POST /hosts` | 通过，临时主机 `db-verify-host-001` 写入成功 |
| 主机读取 | `GET /hosts` | 通过，可读取新增主机 |
| 主机更新 | `PUT /hosts?id=db-verify-host-001` | 通过，名称和权限列表更新成功 |
| 操作日志上传 | `POST /agent/operation-logs` | 通过，`accepted_count=1` |
| 操作日志查询 | `GET /logs/query` | 通过，查询到 1 条验证日志 |
| 主机删除 | `DELETE /hosts?id=db-verify-host-001` | 通过，删除后主机列表不再包含该 ID |

清理结果：

- 临时主机 `db-verify-host-001` 已从 `data/server/hosts.json` 删除。
- 临时日志文件 `data/server/operation_logs/db-verify-host-001.jsonl` 已删除。

## 5. PostgreSQL 脚本静态检查

已确认 `scripts/database/postgresql/001_schema.sql` 包含以下核心设计：

| 数据类型 | 表 | 关键设计 |
| --- | --- | --- |
| 管理员用户 | `af_admin_users` | UUID 主键、用户名唯一索引、密码哈希字段、账号状态约束、角色外键 |
| 主机信息 | `af_hosts` | `host_id` 主键、IP、端口、系统、硬件 JSON、在线状态、更新时间触发器 |
| 主机上传日志 | `af_host_logs` | `log_id` 主键、`host_id` 外键、日志类型、内容、生成/上传时间、状态约束 |
| 扩展数据 | `af_host_metrics`、`af_operation_logs`、`af_alerts` 等 | 外键、时间索引、JSONB GIN 索引 |

当前环境未安装 `psql`，因此未能实际执行：

```powershell
psql -U auditforwarder -d auditforwarder -f scripts\database\postgresql\001_schema.sql
psql -U auditforwarder -d auditforwarder -f scripts\database\postgresql\002_seed.sql
```

## 6. 发现的问题

| 编号 | 问题 | 影响 | 建议 |
| --- | --- | --- | --- |
| DB-001 | 当前环境没有 PostgreSQL 客户端和可连接数据库实例 | 无法验证真实数据库连接、建表执行、事务提交和 SQL 查询性能 | 安装 PostgreSQL 15+ 后执行 `001_schema.sql` 和 `002_seed.sql`，再补充真实数据库集成测试 |
| DB-002 | 当前服务端 HTTP 接口仍使用 JSON/JSONL 文件持久化 | 运行时 API 验证不能代表 PostgreSQL 已接入生产链路 | 下一步应接入 libpq 或数据库驱动，将 `/hosts`、`/agent/operation-logs` 等接口切换到 `DatabaseStore` |
| DB-003 | HTTP 响应中中文测试主机名在 PowerShell 输出里显示为问号 | 影响测试输出可读性，不影响接口功能 | 后续用 UTF-8 控制台或文件输出方式复测中文显示 |

## 7. 性能与稳定性结论

- 本次完整构建和单元测试通过，数据库模型与 CRUD 仓储接口稳定执行。
- 单元测试总耗时约 0.90 秒，当前内存仓储 CRUD 在测试规模下无明显性能问题。
- 服务端运行时核心接口均能完成请求响应，临时数据可写入、查询、更新和删除。
- 尚未完成真实 PostgreSQL 性能验证；需要数据库实例后补测连接池、参数化 SQL、索引查询、批量日志写入和事务回滚。

## 8. 结论

数据库设计交付物、C++ 数据模型、校验规则和基础 CRUD 行为已经通过本地自动化验证。服务端应用也能正常启动并完成核心 HTTP 数据交互。

当前最大缺口是 PostgreSQL 尚未接入运行时服务端，且本机缺少数据库客户端，无法完成真实数据库连接和 SQL 执行验证。建议下一阶段优先完成 PostgreSQL 驱动接入与集成测试环境搭建。
