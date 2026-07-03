# AuditForwarder - Windows PowerShell 安装脚本
# 请以管理员身份运行：
#   powershell -ExecutionPolicy Bypass -File install_windows.ps1

[CmdletBinding()]
param(
    [string]$InstallDir = "C:\Program Files\AuditForwarder",
    [string]$ConfigDir  = "C:\ProgramData\AuditForwarder",
    [string]$DataDir    = "C:\ProgramData\AuditForwarder\data",
    [string]$LogDir     = "C:\ProgramData\AuditForwarder\log",
    [string]$SourceDir  = "$PSScriptRoot\..\build\Release",
    [switch]$Start,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$ServiceName = "AuditForwarder"
$ExeName     = "auditforwarderd.exe"

function Require-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "此脚本必须以管理员身份运行。"
    }
}

function Stop-Service {
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Write-Host "[停止] 正在停止服务 $ServiceName..."
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    }
}

function Remove-Service {
    Stop-Service
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Write-Host "[卸载] 正在删除服务..."
        sc.exe delete $ServiceName | Out-Null
    }
}

function Install-Binary {
    $src = Join-Path $SourceDir $ExeName
    if (-not (Test-Path $src)) { throw "未找到程序文件：$src" }
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Copy-Item $src "$InstallDir\$ExeName" -Force
}

function Install-Config {
    New-Item -ItemType Directory -Force -Path $ConfigDir, $ConfigDir\keys, $ConfigDir\tls, $DataDir\batches, $LogDir | Out-Null
    $cfgSrc = Join-Path $PSScriptRoot "..\config\agent.yaml"
    $rulesSrc = Join-Path $PSScriptRoot "..\config\rules.yaml"
    if (-not (Test-Path "$ConfigDir\agent.yaml")) { Copy-Item $cfgSrc $ConfigDir\agent.yaml }
    if (-not (Test-Path "$ConfigDir\rules.yaml")) { Copy-Item $rulesSrc $ConfigDir\rules.yaml }
}

function Generate-Keys {
    $keyPath = "$ConfigDir\keys\agent.pem"
    if (-not (Test-Path $keyPath)) {
        Write-Host "[密钥] 正在生成 Ed25519 签名密钥..."
        New-Item -ItemType Directory -Force -Path (Split-Path $keyPath) | Out-Null
        openssl genpkey -algorithm ed25519 -out $keyPath 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[密钥] 未找到 openssl，将使用 HMAC 备用方案"
        } else {
            openssl pkey -in $keyPath -pubout -out "$ConfigDir\keys\agent.pub"
        }
    }
}

function New-Service {
    $binPath = "`"$InstallDir\$ExeName`" -c `"$ConfigDir\agent.yaml`" -d $DataDir"
    New-Service -Name $ServiceName -BinaryPathName $binPath `
        -DisplayName "AuditForwarder 安全审计 Agent" `
        -Description "企业级跨平台安全审计 Agent。" `
        -StartupType Automatic | Out-Null
    Write-Host "[服务] 已创建：$ServiceName"
}

function Start-IfRequested {
    if ($Start) {
        Start-Service -Name $ServiceName
        Write-Host "[服务] 已启动：$ServiceName"
    }
}

# ---------------------------------------------------------------------------

if ($Uninstall) {
    Require-Admin
    Remove-Service
    Remove-Item -Recurse -Force $InstallDir -ErrorAction SilentlyContinue
    Write-Host "AuditForwarder 已卸载。数据已保留在 $ConfigDir。"
    exit 0
}

Require-Admin
Install-Binary
Install-Config
Generate-Keys
Stop-Service
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    sc.exe delete $ServiceName | Out-Null
}
New-Service
Start-IfRequested

Write-Host ""
Write-Host "AuditForwarder 安装成功。"
Write-Host "  程序文件：$InstallDir\$ExeName"
Write-Host "  配置文件：$ConfigDir\agent.yaml"
Write-Host "  规则文件：$ConfigDir\rules.yaml"
Write-Host "  数据目录：$DataDir"
Write-Host "  日志目录：$LogDir"
Write-Host ""
Write-Host "  管理服务：Get-Service AuditForwarder"
Write-Host "  查看日志：Get-EventLog -LogName Application -Source AuditForwarder -Newest 50"
