# AuditForwarder PostgreSQL 备份与恢复脚本
#
# 备份示例：
#   powershell -ExecutionPolicy Bypass -File scripts/database/postgresql/backup_restore.ps1 -Mode backup -Database auditforwarder -User auditforwarder
#
# 恢复示例：
#   powershell -ExecutionPolicy Bypass -File scripts/database/postgresql/backup_restore.ps1 -Mode restore -Database auditforwarder -User auditforwarder -BackupFile .\backups\auditforwarder_20260703_120000.sql

param(
    [ValidateSet("backup", "restore")]
    [string]$Mode = "backup",

    [string]$HostName = "127.0.0.1",
    [int]$Port = 5432,
    [string]$Database = "auditforwarder",
    [string]$User = "auditforwarder",
    [string]$BackupDir = ".\backups",
    [string]$BackupFile = "",
    [int]$RetentionDays = 30
)

$ErrorActionPreference = "Stop"

function Require-Command {
    param([string]$Name)
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if (-not $cmd) {
        throw "未找到命令：$Name。请确认 PostgreSQL bin 目录已加入 PATH。"
    }
}

Require-Command "pg_dump"
Require-Command "psql"

if ($Mode -eq "backup") {
    if (-not (Test-Path $BackupDir)) {
        New-Item -ItemType Directory -Path $BackupDir | Out-Null
    }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $target = Join-Path $BackupDir "auditforwarder_$timestamp.sql"

    Write-Host "[备份] 正在导出数据库 $Database 到 $target"
    pg_dump `
        --host $HostName `
        --port $Port `
        --username $User `
        --format plain `
        --no-owner `
        --no-privileges `
        --file $target `
        $Database

    $deadline = (Get-Date).AddDays(-$RetentionDays)
    Get-ChildItem -Path $BackupDir -Filter "auditforwarder_*.sql" |
        Where-Object { $_.LastWriteTime -lt $deadline } |
        Remove-Item -Force

    Write-Host "[备份] 完成：$target"
    Write-Host "[备份] 已清理超过 $RetentionDays 天的旧备份。"
    exit 0
}

if ($Mode -eq "restore") {
    if ([string]::IsNullOrWhiteSpace($BackupFile)) {
        throw "恢复模式必须指定 -BackupFile。"
    }
    if (-not (Test-Path $BackupFile)) {
        throw "备份文件不存在：$BackupFile"
    }

    Write-Host "[恢复] 即将把 $BackupFile 恢复到数据库 $Database"
    Write-Host "[恢复] 该操作会执行 SQL 文件中的所有语句，请确认目标数据库和备份文件正确。"

    psql `
        --host $HostName `
        --port $Port `
        --username $User `
        --dbname $Database `
        --file $BackupFile

    Write-Host "[恢复] 完成。"
}
