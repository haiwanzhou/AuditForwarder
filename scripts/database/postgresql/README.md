# AuditForwarder PostgreSQL 脚本使用说明

本目录提供服务端关系型数据库的创建、初始化和备份恢复脚本。

## 1. 创建数据库和账号

请先使用 PostgreSQL 管理员账号执行：

```sql
CREATE USER auditforwarder WITH PASSWORD '请替换为强密码';
CREATE DATABASE auditforwarder OWNER auditforwarder;
GRANT ALL PRIVILEGES ON DATABASE auditforwarder TO auditforwarder;
```

## 2. 创建表结构

```powershell
psql -U auditforwarder -d auditforwarder -f scripts\database\postgresql\001_schema.sql
```

该脚本会创建：

- 主机信息表
- 主机上传日志表
- 操作日志表
- 管理员账号表
- 角色权限表
- 主机指标表
- 审计摘要表
- 命令队列表
- 命令结果表
- 告警表
- 管理员审计日志表

## 3. 初始化基础数据

```powershell
psql -U auditforwarder -d auditforwarder -f scripts\database\postgresql\002_seed.sql
```

初始化内容：

- `admin`、`operator`、`auditor` 三类角色。
- 禁用状态的占位管理员账号 `admin`。
- 开发测试主机 `test-agent-001`。

注意：默认管理员账号是禁用状态，密码哈希也是占位值。生产环境必须通过服务端改密流程写入真实 Argon2id 哈希后再启用账号。

## 4. 备份数据库

```powershell
powershell -ExecutionPolicy Bypass -File scripts\database\postgresql\backup_restore.ps1 `
  -Mode backup `
  -Database auditforwarder `
  -User auditforwarder `
  -BackupDir .\backups `
  -RetentionDays 30
```

## 5. 恢复数据库

```powershell
powershell -ExecutionPolicy Bypass -File scripts\database\postgresql\backup_restore.ps1 `
  -Mode restore `
  -Database auditforwarder `
  -User auditforwarder `
  -BackupFile .\backups\auditforwarder_20260703_120000.sql
```

恢复前请确认目标数据库和备份文件正确。生产环境建议先恢复到临时数据库验证，再切换业务。
