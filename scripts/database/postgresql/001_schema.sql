-- AuditForwarder PostgreSQL 数据库结构脚本
-- 适用版本：PostgreSQL 15+
-- 执行示例：
--   psql -U auditforwarder -d auditforwarder -f scripts/database/postgresql/001_schema.sql

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS af_admin_roles (
    role_id smallserial PRIMARY KEY,
    role_code varchar(64) NOT NULL UNIQUE,
    role_name varchar(128) NOT NULL,
    permission_level integer NOT NULL DEFAULT 0 CHECK (permission_level BETWEEN 0 AND 100),
    permissions jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS af_admin_users (
    user_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    username varchar(64) NOT NULL,
    password_hash text NOT NULL,
    password_algorithm varchar(32) NOT NULL DEFAULT 'argon2id',
    role_id smallint NOT NULL REFERENCES af_admin_roles(role_id) ON UPDATE CASCADE ON DELETE RESTRICT,
    permission_level integer NOT NULL DEFAULT 0 CHECK (permission_level BETWEEN 0 AND 100),
    account_status varchar(16) NOT NULL DEFAULT 'active'
        CHECK (account_status IN ('active', 'disabled', 'locked')),
    created_at timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT af_admin_users_username_not_blank CHECK (length(trim(username)) >= 3)
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_af_admin_users_username_lower
    ON af_admin_users (lower(username));

CREATE TABLE IF NOT EXISTS af_hosts (
    host_id varchar(80) PRIMARY KEY,
    ip_address inet,
    port integer NOT NULL DEFAULT 0 CHECK (port BETWEEN 0 AND 65535),
    host_name varchar(128) NOT NULL,
    os_type varchar(64) NOT NULL DEFAULT 'unknown',
    os_version varchar(256) NOT NULL DEFAULT 'unknown',
    hardware_info jsonb NOT NULL DEFAULT '{}'::jsonb,
    network_status varchar(16) NOT NULL DEFAULT 'unknown'
        CHECK (network_status IN ('online', 'offline', 'unknown')),
    registered_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz,
    cpu_usage_percent numeric(5,2) CHECK (cpu_usage_percent IS NULL OR cpu_usage_percent BETWEEN 0 AND 100),
    memory_usage_percent numeric(5,2) CHECK (memory_usage_percent IS NULL OR memory_usage_percent BETWEEN 0 AND 100),
    permissions jsonb NOT NULL DEFAULT '[]'::jsonb,
    note text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT af_hosts_id_format CHECK (host_id ~ '^[A-Za-z0-9_-]{3,80}$')
);

CREATE INDEX IF NOT EXISTS idx_af_hosts_status_seen
    ON af_hosts (network_status, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS idx_af_hosts_ip
    ON af_hosts (ip_address);

CREATE INDEX IF NOT EXISTS idx_af_hosts_permissions_gin
    ON af_hosts USING gin (permissions);

CREATE TABLE IF NOT EXISTS af_host_logs (
    log_id bigserial PRIMARY KEY,
    host_id varchar(80) NOT NULL REFERENCES af_hosts(host_id) ON UPDATE CASCADE ON DELETE RESTRICT,
    log_type varchar(64) NOT NULL,
    log_content text NOT NULL,
    generated_at timestamptz NOT NULL,
    uploaded_at timestamptz NOT NULL DEFAULT now(),
    log_status varchar(16) NOT NULL DEFAULT 'new'
        CHECK (log_status IN ('new', 'parsed', 'alerted', 'archived')),
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT af_host_logs_type_not_blank CHECK (length(trim(log_type)) > 0),
    CONSTRAINT af_host_logs_content_not_blank CHECK (length(log_content) > 0)
);

CREATE INDEX IF NOT EXISTS idx_af_host_logs_host_time
    ON af_host_logs (host_id, generated_at DESC);

CREATE INDEX IF NOT EXISTS idx_af_host_logs_type_time
    ON af_host_logs (log_type, generated_at DESC);

CREATE INDEX IF NOT EXISTS idx_af_host_logs_status_time
    ON af_host_logs (log_status, generated_at DESC);

CREATE INDEX IF NOT EXISTS idx_af_host_logs_metadata_gin
    ON af_host_logs USING gin (metadata);

CREATE TABLE IF NOT EXISTS af_host_metrics (
    metric_id bigserial PRIMARY KEY,
    host_id varchar(80) NOT NULL REFERENCES af_hosts(host_id) ON UPDATE CASCADE ON DELETE RESTRICT,
    metric_time timestamptz NOT NULL DEFAULT now(),
    cpu_usage_percent numeric(5,2) CHECK (cpu_usage_percent IS NULL OR cpu_usage_percent BETWEEN 0 AND 100),
    memory_total_bytes bigint CHECK (memory_total_bytes IS NULL OR memory_total_bytes >= 0),
    memory_used_bytes bigint CHECK (memory_used_bytes IS NULL OR memory_used_bytes >= 0),
    memory_usage_percent numeric(5,2) CHECK (memory_usage_percent IS NULL OR memory_usage_percent BETWEEN 0 AND 100),
    disk_total_bytes bigint CHECK (disk_total_bytes IS NULL OR disk_total_bytes >= 0),
    disk_free_bytes bigint CHECK (disk_free_bytes IS NULL OR disk_free_bytes >= 0),
    disk_usage_percent numeric(5,2) CHECK (disk_usage_percent IS NULL OR disk_usage_percent BETWEEN 0 AND 100),
    network_rx_bytes bigint CHECK (network_rx_bytes IS NULL OR network_rx_bytes >= 0),
    network_tx_bytes bigint CHECK (network_tx_bytes IS NULL OR network_tx_bytes >= 0),
    raw_payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_af_host_metrics_host_time
    ON af_host_metrics (host_id, metric_time DESC);

CREATE TABLE IF NOT EXISTS af_audit_summaries (
    summary_id bigserial PRIMARY KEY,
    host_id varchar(80) NOT NULL REFERENCES af_hosts(host_id) ON UPDATE CASCADE ON DELETE RESTRICT,
    batch_id varchar(32) NOT NULL,
    event_count integer NOT NULL DEFAULT 0 CHECK (event_count >= 0),
    merkle_root varchar(128),
    signature_present boolean NOT NULL DEFAULT false,
    summary_time timestamptz NOT NULL DEFAULT now(),
    activities jsonb NOT NULL DEFAULT '[]'::jsonb,
    raw_payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ux_af_audit_summaries_host_batch UNIQUE (host_id, batch_id)
);

CREATE INDEX IF NOT EXISTS idx_af_audit_summaries_host_time
    ON af_audit_summaries (host_id, summary_time DESC);

CREATE TABLE IF NOT EXISTS af_operation_logs (
    log_id bigserial PRIMARY KEY,
    host_id varchar(80) NOT NULL REFERENCES af_hosts(host_id) ON UPDATE CASCADE ON DELETE RESTRICT,
    user_id uuid REFERENCES af_admin_users(user_id) ON UPDATE CASCADE ON DELETE SET NULL,
    actor varchar(128) NOT NULL DEFAULT '',
    operation_type varchar(64) NOT NULL,
    operation_time timestamptz NOT NULL DEFAULT now(),
    operation_detail jsonb NOT NULL DEFAULT '{}'::jsonb,
    result_status varchar(16) NOT NULL DEFAULT 'unknown'
        CHECK (result_status IN ('success', 'failure', 'unknown')),
    error_message text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT af_operation_logs_type_not_blank CHECK (length(trim(operation_type)) > 0)
);

CREATE INDEX IF NOT EXISTS idx_af_operation_logs_host_time
    ON af_operation_logs (host_id, operation_time DESC);

CREATE INDEX IF NOT EXISTS idx_af_operation_logs_user_time
    ON af_operation_logs (user_id, operation_time DESC);

CREATE INDEX IF NOT EXISTS idx_af_operation_logs_type_time
    ON af_operation_logs (operation_type, operation_time DESC);

CREATE INDEX IF NOT EXISTS idx_af_operation_logs_status_time
    ON af_operation_logs (result_status, operation_time DESC);

CREATE INDEX IF NOT EXISTS idx_af_operation_logs_detail_gin
    ON af_operation_logs USING gin (operation_detail);

CREATE TABLE IF NOT EXISTS af_command_queue (
    command_id varchar(80) PRIMARY KEY,
    host_id varchar(80) NOT NULL REFERENCES af_hosts(host_id) ON UPDATE CASCADE ON DELETE RESTRICT,
    created_by uuid REFERENCES af_admin_users(user_id) ON UPDATE CASCADE ON DELETE SET NULL,
    command_type varchar(64) NOT NULL,
    encrypted_payload text NOT NULL DEFAULT '',
    encryption_algorithm varchar(32) NOT NULL DEFAULT 'AES-256-GCM',
    command_status varchar(16) NOT NULL DEFAULT 'pending'
        CHECK (command_status IN ('pending', 'delivered', 'completed', 'failed', 'expired')),
    created_at timestamptz NOT NULL DEFAULT now(),
    delivered_at timestamptz,
    expires_at timestamptz NOT NULL DEFAULT (now() + interval '10 minutes'),
    CONSTRAINT af_command_queue_type_not_blank CHECK (length(trim(command_type)) > 0)
);

CREATE INDEX IF NOT EXISTS idx_af_command_queue_host_status_created
    ON af_command_queue (host_id, command_status, created_at);

CREATE TABLE IF NOT EXISTS af_command_results (
    result_id bigserial PRIMARY KEY,
    command_id varchar(80) NOT NULL REFERENCES af_command_queue(command_id) ON UPDATE CASCADE ON DELETE RESTRICT,
    host_id varchar(80) NOT NULL REFERENCES af_hosts(host_id) ON UPDATE CASCADE ON DELETE RESTRICT,
    command_type varchar(64) NOT NULL,
    success boolean NOT NULL DEFAULT false,
    output_text text NOT NULL DEFAULT '',
    error_message text NOT NULL DEFAULT '',
    duration_ms integer CHECK (duration_ms IS NULL OR duration_ms >= 0),
    completed_at timestamptz NOT NULL DEFAULT now(),
    raw_payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_af_command_results_host_completed
    ON af_command_results (host_id, completed_at DESC);

CREATE TABLE IF NOT EXISTS af_alerts (
    alert_id bigserial PRIMARY KEY,
    host_id varchar(80) REFERENCES af_hosts(host_id) ON UPDATE CASCADE ON DELETE SET NULL,
    source_type varchar(32) NOT NULL,
    severity varchar(16) NOT NULL DEFAULT 'warning'
        CHECK (severity IN ('info', 'warning', 'critical')),
    alert_code varchar(80) NOT NULL,
    alert_message text NOT NULL,
    alert_detail jsonb NOT NULL DEFAULT '{}'::jsonb,
    alert_status varchar(16) NOT NULL DEFAULT 'open'
        CHECK (alert_status IN ('open', 'acknowledged', 'closed')),
    created_at timestamptz NOT NULL DEFAULT now(),
    closed_at timestamptz
);

CREATE INDEX IF NOT EXISTS idx_af_alerts_host_created
    ON af_alerts (host_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_af_alerts_severity_status
    ON af_alerts (severity, alert_status, created_at DESC);

CREATE TABLE IF NOT EXISTS af_admin_audit_logs (
    audit_id bigserial PRIMARY KEY,
    user_id uuid REFERENCES af_admin_users(user_id) ON UPDATE CASCADE ON DELETE SET NULL,
    username varchar(64) NOT NULL DEFAULT '',
    action_type varchar(64) NOT NULL,
    target_type varchar(64) NOT NULL DEFAULT '',
    target_id varchar(128) NOT NULL DEFAULT '',
    client_ip inet,
    result_status varchar(16) NOT NULL DEFAULT 'unknown'
        CHECK (result_status IN ('success', 'failure', 'unknown')),
    detail jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_af_admin_audit_logs_user_time
    ON af_admin_audit_logs (user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_af_admin_audit_logs_action_time
    ON af_admin_audit_logs (action_type, created_at DESC);

CREATE OR REPLACE FUNCTION af_touch_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_af_hosts_touch_updated_at ON af_hosts;
CREATE TRIGGER trg_af_hosts_touch_updated_at
BEFORE UPDATE ON af_hosts
FOR EACH ROW EXECUTE FUNCTION af_touch_updated_at();

DROP TRIGGER IF EXISTS trg_af_admin_users_touch_updated_at ON af_admin_users;
CREATE TRIGGER trg_af_admin_users_touch_updated_at
BEFORE UPDATE ON af_admin_users
FOR EACH ROW EXECUTE FUNCTION af_touch_updated_at();

CREATE OR REPLACE VIEW af_online_hosts AS
SELECT
    host_id,
    host_name,
    ip_address,
    port,
    os_type,
    os_version,
    network_status,
    last_seen_at,
    cpu_usage_percent,
    memory_usage_percent
FROM af_hosts
WHERE network_status = 'online'
  AND last_seen_at >= now() - interval '90 seconds';

COMMIT;
