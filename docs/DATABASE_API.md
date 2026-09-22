# AuditForwarder 数据库操作 API 与示例

本文档说明服务端关系型数据库与现有 HTTP API 的对应关系，并给出 SQL 与 C++ 示例代码。当前 HTTP 接口路径保持不变，数据库表结构由 `scripts/database/postgresql/001_schema.sql` 定义。

项目提供 C++ 数据访问抽象：

- `include/auditforwarder/database.h`：管理员、主机、主机日志模型，校验规则，CRUD 仓储接口。
- `shared/src/database/database.cpp`：内存仓储实现和 PostgreSQL 参数化 SQL 模板。
- `af::db::Validator`：统一校验用户名、密码哈希、主机 ID、端口、JSON 扩展字段和日志内容。

## 1. 连接配置建议

生产环境建议使用专用数据库账号：

```sql
CREATE USER auditforwarder WITH PASSWORD '请替换为强密码';
CREATE DATABASE auditforwarder OWNER auditforwarder;
GRANT ALL PRIVILEGES ON DATABASE auditforwarder TO auditforwarder;
```

服务端配置建议：

```yaml
database:
  enabled: true
  driver: postgresql
  host: 127.0.0.1
  port: 5432
  name: auditforwarder
  user: auditforwarder
  password: "请使用环境变量或安全密钥管理系统注入"
  pool_size: 8
  connect_timeout_sec: 5
  statement_timeout_ms: 5000
```

安全建议：

- 数据库密码不要提交到 Git。
- 服务端应使用参数化查询，禁止拼接 SQL。
- 管理员密码只保存不可逆哈希，推荐 Argon2id。
- 敏感操作必须写入 `af_admin_audit_logs`。

## 2. 主机信息管理 API

### 2.1 新增或更新主机

对应 HTTP：

```http
POST /hosts
POST /hosts/heartbeat
POST /hosts/register
```

SQL：

```sql
INSERT INTO af_hosts (
    host_id,
    ip_address,
    port,
    host_name,
    os_type,
    os_version,
    hardware_info,
    network_status,
    registered_at,
    last_seen_at,
    cpu_usage_percent,
    memory_usage_percent,
    permissions,
    note
) VALUES (
    $1, $2, $3, $4, $5, $6, $7::jsonb, $8, now(), now(), $9, $10, $11::jsonb, $12
)
ON CONFLICT (host_id) DO UPDATE
SET ip_address = EXCLUDED.ip_address,
    port = EXCLUDED.port,
    host_name = EXCLUDED.host_name,
    os_type = EXCLUDED.os_type,
    os_version = EXCLUDED.os_version,
    hardware_info = EXCLUDED.hardware_info,
    network_status = EXCLUDED.network_status,
    last_seen_at = now(),
    cpu_usage_percent = EXCLUDED.cpu_usage_percent,
    memory_usage_percent = EXCLUDED.memory_usage_percent,
    permissions = EXCLUDED.permissions,
    note = EXCLUDED.note;
```

### 2.2 查询主机列表

对应 HTTP：

```http
GET /hosts
```

SQL：

```sql
SELECT
    host_id,
    host_name,
    ip_address::text AS ip_address,
    port,
    os_type,
    os_version,
    hardware_info,
    network_status,
    registered_at,
    last_seen_at,
    cpu_usage_percent,
    memory_usage_percent,
    permissions,
    note
FROM af_hosts
ORDER BY last_seen_at DESC NULLS LAST, created_at DESC
LIMIT $1 OFFSET $2;
```

### 2.3 修改主机

对应 HTTP：

```http
PUT /hosts?id=<host_id>
```

SQL：

```sql
UPDATE af_hosts
SET ip_address = COALESCE($2, ip_address),
    host_name = COALESCE($3, host_name),
    port = COALESCE($4, port),
    os_type = COALESCE($5, os_type),
    os_version = COALESCE($6, os_version),
    hardware_info = COALESCE($7::jsonb, hardware_info),
    network_status = COALESCE($8, network_status),
    permissions = COALESCE($9::jsonb, permissions),
    note = COALESCE($10, note)
WHERE host_id = $1;
```

### 2.4 写入主机上传日志

对应建议 HTTP：

```http
POST /agent/logs
```

SQL：

```sql
INSERT INTO af_host_logs (
    host_id,
    log_type,
    log_content,
    generated_at,
    uploaded_at,
    log_status,
    metadata
) VALUES (
    $1, $2, $3, $4, now(), $5, $6::jsonb
)
RETURNING log_id;
```

查询主机上传日志：

```sql
SELECT
    log_id,
    host_id,
    log_type,
    log_content,
    generated_at,
    uploaded_at,
    log_status,
    metadata
FROM af_host_logs
WHERE ($1::varchar IS NULL OR host_id = $1)
  AND ($2::varchar IS NULL OR log_type = $2)
  AND ($3::timestamptz IS NULL OR generated_at >= $3)
  AND ($4::timestamptz IS NULL OR generated_at <= $4)
  AND ($5::varchar IS NULL OR log_status = $5)
ORDER BY generated_at DESC, log_id DESC
LIMIT $6 OFFSET $7;
```

### 2.5 删除主机

对应 HTTP：

```http
DELETE /hosts?id=<host_id>
```

建议优先实现软删除。如果必须物理删除，应先归档关联日志。

```sql
UPDATE af_hosts
SET network_status = 'offline',
    note = concat(note, E'\n已从监管列表移除：', now())
WHERE host_id = $1;
```

## 3. 操作日志管理 API

### 3.1 记录操作日志

对应 HTTP：

```http
POST /agent/operation-logs
```

SQL：

```sql
INSERT INTO af_operation_logs (
    host_id,
    user_id,
    actor,
    operation_type,
    operation_time,
    operation_detail,
    result_status,
    error_message
) VALUES (
    $1, $2, $3, $4, $5, $6::jsonb, $7, $8
);
```

### 3.2 多维度查询日志

对应 HTTP：

```http
GET /logs/query?host_id=<host_id>&operation_type=<type>&from=<iso>&to=<iso>&limit=<n>
```

SQL：

```sql
SELECT
    log_id,
    host_id,
    user_id,
    actor,
    operation_type,
    operation_time,
    operation_detail,
    result_status,
    error_message
FROM af_operation_logs
WHERE ($1::varchar IS NULL OR host_id = $1)
  AND ($2::uuid IS NULL OR user_id = $2)
  AND ($3::varchar IS NULL OR operation_type = $3)
  AND ($4::timestamptz IS NULL OR operation_time >= $4)
  AND ($5::timestamptz IS NULL OR operation_time <= $5)
ORDER BY operation_time DESC
LIMIT $6;
```

### 3.3 导出日志

建议使用 CSV 流式导出：

```sql
COPY (
    SELECT log_id, host_id, actor, operation_type, operation_time, result_status, error_message
    FROM af_operation_logs
    WHERE operation_time >= $1 AND operation_time <= $2
    ORDER BY operation_time DESC
) TO STDOUT WITH CSV HEADER;
```

## 4. 管理员账号 API

### 4.1 注册管理员

对应建议 HTTP：

```http
POST /admins/register
```

服务层要求：

- 校验当前用户具备 `admins:manage` 权限。
- 使用 Argon2id 或 bcrypt 生成密码哈希。
- 写入 `af_admin_audit_logs`。

SQL：

```sql
INSERT INTO af_admin_users (
    username,
    password_hash,
    password_algorithm,
    role_id,
    permission_level,
    account_status
) VALUES (
    $1,
    $2,
    'argon2id',
    $3,
    $4,
    'active'
)
RETURNING user_id, username, role_id, permission_level, account_status, created_at;
```

### 4.2 登录

对应建议 HTTP：

```http
POST /admins/login
```

SQL：

```sql
SELECT
    u.user_id,
    u.username,
    u.password_hash,
    u.password_algorithm,
    u.permission_level,
    u.account_status,
    r.role_code,
    r.permissions
FROM af_admin_users u
JOIN af_admin_roles r ON r.role_id = u.role_id
WHERE lower(u.username) = lower($1);
```

服务层验证：

- 如果账号不是 `active`，拒绝登录。
- 使用同一算法校验输入密码与 `password_hash`。
- 校验成功后更新 `last_login_at`。
- 登录成功或失败均写入 `af_admin_audit_logs`。

### 4.3 修改密码

对应建议 HTTP：

```http
PUT /admins/<user_id>/password
```

SQL：

```sql
UPDATE af_admin_users
SET password_hash = $2,
    password_algorithm = 'argon2id'
WHERE user_id = $1
  AND account_status = 'active';
```

### 4.4 维护账号状态

对应建议 HTTP：

```http
PUT /admins/<user_id>/status
```

SQL：

```sql
UPDATE af_admin_users
SET account_status = $2
WHERE user_id = $1;
```

## 5. C++ 参数化查询示例

以下示例使用 `libpq` 风格展示参数化查询的核心做法。实际集成时可封装为 `DatabaseClient`，并在服务端路由中复用。

```cpp
#include <libpq-fe.h>
#include <stdexcept>
#include <string>

void upsert_host(PGconn* conn,
                 const std::string& host_id,
                 const std::string& ip,
                 const std::string& name,
                 const std::string& os_type,
                 const std::string& os_version) {
    const char* sql =
        "INSERT INTO af_hosts "
        "(host_id, ip_address, host_name, os_type, os_version, network_status, registered_at, last_seen_at) "
        "VALUES ($1, $2::inet, $3, $4, $5, 'online', now(), now()) "
        "ON CONFLICT (host_id) DO UPDATE SET "
        "ip_address = EXCLUDED.ip_address, "
        "host_name = EXCLUDED.host_name, "
        "os_type = EXCLUDED.os_type, "
        "os_version = EXCLUDED.os_version, "
        "network_status = 'online', "
        "last_seen_at = now()";

    const char* values[] = {
        host_id.c_str(),
        ip.c_str(),
        name.c_str(),
        os_type.c_str(),
        os_version.c_str()
    };

    PGresult* result = PQexecParams(
        conn,
        sql,
        5,
        nullptr,
        values,
        nullptr,
        nullptr,
        0
    );

    if (PQresultStatus(result) != PGRES_COMMAND_OK) {
        std::string error = PQerrorMessage(conn);
        PQclear(result);
        throw std::runtime_error("主机写入失败：" + error);
    }
    PQclear(result);
}
```

关键点：

- 使用 `$1`、`$2` 这类参数占位符，避免 SQL 注入。
- 不拼接用户输入到 SQL 字符串。
- 每个数据库操作返回明确错误，服务端再转换成统一 JSON 错误响应。

## 6. API 返回示例

主机列表返回：

```json
{
  "hosts": [
    {
      "id": "test-agent-001",
      "name": "本地测试客户端",
      "ip_address": "127.0.0.1",
      "os_type": "Windows",
      "os_version": "Windows 10/11",
      "network_status": "online",
      "last_seen": "2026-07-03T12:00:00Z",
      "cpu_usage_percent": 12.5,
      "memory_usage_percent": 68.2,
      "permissions": ["collect_status", "echo"]
    }
  ]
}
```

日志查询返回：

```json
{
  "logs": [
    {
      "log_id": 1001,
      "host_id": "test-agent-001",
      "actor": "user01",
      "operation_type": "execute",
      "operation_time": "2026-07-03T12:01:02Z",
      "result_status": "success",
      "operation_detail": {
        "command": "whoami"
      }
    }
  ]
}
```
