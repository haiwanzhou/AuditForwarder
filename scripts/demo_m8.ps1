# AuditForwarder M8 demo script (PowerShell 5+)
# 1. Generate multi-operator simulation events (auditforwarder-sim)
# 2. Login to the management server and post all events in ONE batch
# 3. Export the incident report (Markdown evidence chain)
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts/demo_m8.ps1 -Server https://127.0.0.1:18443 -Password admin123
#   powershell -ExecutionPolicy Bypass -File scripts/demo_m8.ps1 -Server https://127.0.0.1:18443 -Token <bearer>
#
# Notes:
#   - Events must be posted as ONE batch: per-event ingestion flushes old
#     aggregation windows immediately and multi-step rules cannot match.
#   - Default server login user is "admin"; pass -Username to override.

param(
    [string]$Server = "https://127.0.0.1:18443",
    [string]$Username = "admin",
    [string]$Password = "",
    [string]$Token = "",
    [int]$Days = 7,
    [int]$Operators = 4,
    [int]$NormalEvents = 8,
    [int]$PastMinutes = 120,
    [string]$OutDir = "data/demo_m8"
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($OutDir)) { $OutDir = "data/demo_m8" }
if (-not [System.IO.Path]::IsPathRooted($OutDir)) { $OutDir = Join-Path $root $OutDir }
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

$simExe = Join-Path $root "build\auditforwarder-sim.exe"
if (-not (Test-Path $simExe)) {
    Write-Error "Simulator not found: $simExe (build first: ninja -C build)"
}

# Allow self-signed certificates on the local demo server (PowerShell 5).
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

$baseUrl = $Server.TrimEnd('/')

function Login-Server {
    param([string]$User, [string]$PlainPassword)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($PlainPassword)
    $hash = ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join ""
    $body = @{ username = $User; password_sha256 = $hash } | ConvertTo-Json -Compress
    $resp = Invoke-RestMethod -Uri "$baseUrl/auth/login" -Method Post -Body $body `
        -ContentType "application/json" -TimeoutSec 15
    return $resp.token
}

if ([string]::IsNullOrWhiteSpace($Token)) {
    if ([string]::IsNullOrWhiteSpace($Password)) {
        $secure = Read-Host "Server password for $Username" -AsSecureString
        $Password = [System.Net.NetworkCredential]::new("", $secure).Password
    }
    $Token = Login-Server -User $Username -PlainPassword $Password
    Write-Host "[1/4] Login OK, session token acquired."
} else {
    Write-Host "[1/4] Using provided bearer token."
}

$headers = @{ Authorization = "Bearer $Token" }

# ---- Step 2: generate simulation events ----
$eventsFile = Join-Path $OutDir "sim_events.jsonl"
# Events are generated in the recent past so the asset-group aggregation
# windows expire immediately and multi-step rules can be evaluated right away.
$baseMs = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() - ($PastMinutes * 60 * 1000)
& $simExe --scenario cert_r42 --operators $Operators --normal-events $NormalEvents `
    --base-epoch-ms $baseMs --output $eventsFile
if ($LASTEXITCODE -ne 0) { Write-Error "Simulator failed with exit code $LASTEXITCODE" }

$events = @()
Get-Content -Path $eventsFile -Encoding UTF8 | ForEach-Object {
    if (-not [string]::IsNullOrWhiteSpace($_)) { $events += ($_ | ConvertFrom-Json) }
}
Write-Host "[2/4] Generated $($events.Count) events -> $eventsFile"

# ---- Step 3: post all events in one batch ----
$batch = @{ events = $events } | ConvertTo-Json -Depth 12 -Compress
$ingest = Invoke-RestMethod -Uri "$baseUrl/collusion/ingest" -Method Post -Body $batch `
    -ContentType "application/json" -Headers $headers -TimeoutSec 60
Write-Host "[3/4] Ingest accepted, cleaned events = $($ingest.cleaned_events)"

# ---- Step 4: export incident report ----
$reportPath = Join-Path $OutDir "incident_report.md"
$report = Invoke-RestMethod -Uri "$baseUrl/collusion/incident-report?days=$Days" -Method Get `
    -Headers $headers -TimeoutSec 15
[System.IO.File]::WriteAllText($reportPath, $report, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "[4/4] Incident report saved -> $reportPath"

$overview = Invoke-RestMethod -Uri "$baseUrl/collusion/overview" -Method Get -Headers $headers
Write-Host "Overview JSON:"
$overview | ConvertTo-Json -Depth 6
