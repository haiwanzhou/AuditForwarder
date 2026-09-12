-- AuditForwarder PostgreSQL 基础数据初始化脚本
-- 执行前请先执行 001_schema.sql。
-- 生产环境上线前必须替换默认管理员密码哈希。

BEGIN;

INSERT INTO af_admin_roles (role_code, role_name, permission_level, permissions)
VALUES
    ('admin', '系统管理员', 100, '[
        "hosts:read", "hosts:write", "hosts:delete",
        "logs:read", "logs:export",
        "commands:send",
        "admins:manage",
        "audit:read",
        "alerts:read", "alerts:write"
    ]'::jsonb),
    ('operator', '运维操作员', 60, '[
        "hosts:read", "hosts:write",
        "logs:read",
        "commands:send",
        "alerts:read"
    ]'::jsonb),
    ('auditor', '审计员', 40, '[
        "hosts:read",
        "logs:read", "logs:export",
        "audit:read",
        "alerts:read"
    ]'::jsonb)
ON CONFLICT (role_code) DO UPDATE
SET role_name = EXCLUDED.role_name,
    permission_level = EXCLUDED.permission_level,
    permissions = EXCLUDED.permissions;

-- 默认管理员账号：
-- 用户名：admin
-- 密码哈希为示例占位值，生产环境必须由服务端使用 Argon2id 重新生成。
-- 推荐流程：创建数据库后立即调用“修改密码”接口写入真实 password_hash。
INSERT INTO af_admin_users (
    username,
    password_hash,
    password_algorithm,
    role_id,
    permission_level,
    account_status
)
SELECT
    'admin',
    '$argon2id$v=19$m=65536,t=3,p=4$replace_this_demo_salt$replace_this_demo_hash',
    'argon2id',
    role_id,
    100,
    'disabled'
FROM af_admin_roles
WHERE role_code = 'admin'
  AND NOT EXISTS (
      SELECT 1 FROM af_admin_users WHERE lower(username) = lower('admin')
  );

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
)
VALUES (
    'test-agent-001',
    '127.0.0.1',
    8443,
    '本地测试客户端',
    'Windows',
    'Windows 10/11',
    '{"cpu_threads": 28, "memory": "16GB"}'::jsonb,
    'offline',
    now(),
    now(),
    0,
    0,
    '["collect_status", "echo"]'::jsonb,
    '开发环境默认测试主机，可按需删除。'
)
ON CONFLICT (host_id) DO UPDATE
SET host_name = EXCLUDED.host_name,
    port = EXCLUDED.port,
    os_type = EXCLUDED.os_type,
    os_version = EXCLUDED.os_version,
    hardware_info = EXCLUDED.hardware_info,
    permissions = EXCLUDED.permissions,
    note = EXCLUDED.note;

INSERT INTO af_host_logs (
    host_id,
    log_type,
    log_content,
    generated_at,
    uploaded_at,
    log_status,
    metadata
)
VALUES (
    'test-agent-001',
    'system',
    '数据库初始化验证日志',
    now(),
    now(),
    'new',
    '{"source": "seed"}'::jsonb
);

INSERT INTO af_admin_audit_logs (
    username,
    action_type,
    target_type,
    target_id,
    result_status,
    detail
)
VALUES (
    'system',
    'database_seed',
    'database',
    'auditforwarder',
    'success',
    '{"message": "初始化默认角色、占位管理员账号和测试主机"}'::jsonb
);

COMMIT;
