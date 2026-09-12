# AuditForwarder 项目使用说明书

版本：v1.0.0  
适用对象：普通使用者、运维人员、安全审计人员、开发学习者  
适用系统：Windows / Linux

---

## 1. 项目概述与目标

AuditForwarder 是一个安全审计事件采集、处理、存证和管理系统。

它的主要目标是：

- 采集系统中的安全相关事件，例如进程、网络、命令、文件、注册表和系统审计日志。
- 对事件进行补充、脱敏、去重和规则检测。
- 将事件写入事件链，生成可验证的证据批次。
- 使用 SHA-256、Merkle Root、HMAC 或数字签名保护数据完整性。
- 提供浏览器管理界面，让非技术用户也能查看运行状态和操作系统。
- 支持主机注册、状态监控、日志接收、日志检索、告警分析和结构化操作记录。
- 支持安全登录页面、会话 Token、登录失败锁定和登录审计记录。
- 提供 PostgreSQL 关系型数据库设计、建表脚本、初始化脚本和备份恢复脚本。

简单流程如下：

```text
系统事件
→ 采集器 Collector
→ 处理器 Processor
→ 检测器 Detector
→ 事件链 Chain
→ 批次文件 data/batches
→ 管理界面 / API / 传输模块
```

当前项目已经拆分为三个可执行程序：

```text
auditforwarderd.exe          兼容的一体化程序
auditforwarder-server.exe    独立服务端管理后台
auditforwarder-client.exe    独立客户端 Agent
```

典型部署关系如下：

```text
客户端主机 auditforwarder-client.exe
  → 心跳注册
  → 指标上报
  → 审计摘要上报
  → 拉取远程命令
  → 回传命令结果

服务端主机 auditforwarder-server.exe
  → 管理页面
  → 主机列表
  → 日志与告警
  → 命令队列
  → 登录认证
```

---

## 2. 功能特性

### 2.1 事件采集

系统支持采集多种类型的审计事件：

- 进程启动、退出
- 命令执行
- 网络连接
- 文件变化
- 注册表变化
- Windows 安全日志事件

注意：Windows 安全日志采集通常需要管理员权限，否则可能出现 `EvtSubscribe` 失败。

### 2.2 事件处理

采集到的事件会进入处理器链，常见处理器包括：

- `Enricher`：补充主机名、Agent ID、用户等信息。
- `PIIMasker`：对敏感信息进行脱敏。
- `Deduper`：过滤短时间内重复的事件。

### 2.3 检测与告警

检测规则位于：

```text
config/rules.yaml
```

系统会根据规则识别可疑行为，并更新告警统计。

### 2.4 证据批次

系统会把事件打包成批次文件，默认保存到：

```text
data/batches
```

每个批次文件是 JSON 格式，包含：

- 批次 ID
- Merkle Root
- 签名或 HMAC
- 事件数量
- 创建时间
- 事件列表

批次容量由配置项控制：

```yaml
chain:
  batch_size: 10
```

如果配置文件未指定该字段，程序会使用内置默认值。

### 2.5 管理界面

系统提供浏览器前端界面：

```text
http://127.0.0.1:8443/
```

当前服务端测试配置已监听：

```text
0.0.0.0:8443
```

因此同一局域网内的其他设备可以使用服务端主机的 IP 访问，例如：

```text
http://10.4.122.141:8443/
```

首次进入页面会显示登录页。交付包不内置默认密码，账号和密码哈希需自行配置：

```text
账号：配置中设置的 manager.login_username（默认 admin）
密码：你为 manager.login_password_sha256 生成哈希时所用的密码
```

界面模块包括：

- 运行概览
- 配置中心
- 证据批次
- 主机管理
- 日志与告警
- 操作记录
- 运维操作
- 登录认证与 Token 会话

### 2.6 登录认证

服务端提供安全登录页面和 `/auth/login` 接口。

安全机制包括：

- 密码输入框以不可见字符显示。
- 前端使用 Web Crypto 计算密码 SHA-256 后提交。
- 服务端与配置中的 `manager.login_username`、`manager.login_password_sha256` 严格匹配。
- 登录成功后签发 Bearer Token。
- 连续 3 次失败后，同一账号与来源 IP 会锁定 15 分钟。
- 登录成功、失败和锁定行为会写入 `data/server/login_audit.jsonl`。

生产环境必须启用 HTTPS/TLS，否则 HTTP 传输层本身不加密。

### 2.7 结构化操作记录

前端会记录用户在页面上的关键操作，包括：

- 执行者身份
- 秒级时间戳
- 操作对象
- 操作类型
- 操作细节
- 成功或失败状态

这些记录保存在浏览器本地，可复制或导出为 JSON。

### 2.8 关系型数据库交付物

项目已经提供 PostgreSQL 关系型数据库设计和脚本，位于：

```text
docs/DATABASE_DESIGN.md
docs/DATABASE_API.md
scripts/database/postgresql/
config/database_postgresql.yaml
```

当前运行链路仍兼容 JSON/JSONL 文件持久化；PostgreSQL 方案用于后续服务端持久化升级。

---

## 3. 系统环境要求

### 3.1 Windows 环境

建议环境：

- Windows 10 或 Windows 11
- MSYS2 UCRT64 或 Visual Studio C++ 构建环境
- CMake
- Make 或 Ninja
- OpenSSL
- Zlib
- PowerShell 5 或更高版本

当前项目在本机常用构建环境：

```text
<MSYS2安装目录>\mingw64\bin
<MSYS2安装目录>\usr\bin
```

### 3.2 Linux 环境

建议环境：

- GCC / G++
- CMake
- OpenSSL 开发库
- Zlib 开发库
- libaudit 开发库

Ubuntu / Debian 示例：

```bash
sudo apt update
sudo apt install -y build-essential cmake pkg-config libssl-dev zlib1g-dev libaudit-dev
```

---

## 4. 安装与构建

### 4.1 获取项目

进入项目目录：

```powershell
cd <项目目录>
```

### 4.2 Windows 构建

如果已经生成过 `build` 目录，可以直接重新构建：

```powershell
$env:MSYS2_ROOT = "<MSYS2安装目录>"
$env:PATH = "$env:MSYS2_ROOT\mingw64\bin;$env:MSYS2_ROOT\usr\bin;$env:PATH"
$env:MSYS2_ROOT\usr\bin\make.exe -C build -j4
```

如果是首次构建，一般流程如下：

```powershell
$env:MSYS2_ROOT = "<MSYS2安装目录>"
$env:PATH = "$env:MSYS2_ROOT\mingw64\bin;$env:MSYS2_ROOT\usr\bin;$env:PATH"
cmake -S . -B build
$env:MSYS2_ROOT\usr\bin\make.exe -C build -j4
```

构建成功后，会生成三个主要程序：

```text
build/auditforwarderd.exe          兼容的一体化程序
build/auditforwarder-server.exe    独立服务端程序
build/auditforwarder-client.exe    独立客户端程序
```

### 4.3 Linux 构建

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

---

## 5. 配置说明

Windows 服务端测试配置文件：

```text
config/server_windows.yaml
```

Windows 客户端测试配置文件：

```text
config/client_windows.yaml
```

通用配置文件：

```text
config/agent.yaml
```

### 5.1 管理服务配置

```yaml
manager:
  enabled: true
  listen: 0.0.0.0:8443
  auth_token: ""
  login_username: "admin"
  login_password_sha256: "<自行生成强密码的SHA-256哈希>"
  enrollment_key: ""
```

字段说明：

- `enabled`：是否启用管理后台。
- `listen`：浏览器和 API 访问地址。
- `auth_token`：固定管理 Token，保留给调试和脚本调用；交付包默认留空，需要时自行配置。
- `login_username`：管理页面登录账号。
- `login_password_sha256`：管理页面登录密码的 SHA-256 哈希；交付包为占位值，必须替换为自己的哈希后才能登录，切勿留空。
- `enrollment_key`：客户端加入监管系统时使用的注册密钥；交付包默认留空（注册不校验密钥），生产环境必须自行配置。

监听地址说明：

```text
127.0.0.1:8443    只允许本机访问
0.0.0.0:8443      允许局域网内其他设备访问
```

当前本机 WLAN 地址为：

```text
10.4.122.141
```

同一局域网内其他设备可以访问：

```text
http://10.4.122.141:8443/
```

如果外部设备打不开，通常需要用管理员 PowerShell 放行防火墙：

```powershell
New-NetFirewallRule -DisplayName "AuditForwarder 8443" -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow
```

### 5.2 数据目录配置

```yaml
agent:
  data_dir: data
```

该目录用于保存：

- 日志文件
- 批次文件
- 传输索引
- 主机状态和上传日志
- 告警与策略文件
- 运行数据

### 5.3 日志配置

```yaml
log:
  level: debug
  file: data/agent.log
  max_bytes: 52428800
```

常见日志级别：

```text
debug
info
warning
error
critical
```

### 5.4 客户端远端连接配置

客户端配置文件：

```text
config/client_windows.yaml
```

关键配置：

```yaml
remote:
  enabled: true
  servers:
    - "http://127.0.0.1:8443"
  host_id: "test-agent-001"
  enrollment_key: ""           # 与服务端保持一致；如需启用请自行配置
  allowed_commands:
    - collect_status
    - echo
```

字段说明：

- `servers`：服务端地址。跨机器部署时应改成服务端实际 IP，例如 `http://10.4.122.141:8443`。
- `host_id`：客户端主机 ID。
- `enrollment_key`：必须和服务端 `manager.enrollment_key` 一致。
- `allowed_commands`：客户端允许执行的远程命令白名单。

### 5.5 传输配置

```yaml
transport:
  servers: []
  mode: batch
  interval_sec: 60
  compress: false
  encrypt_payload: false
```

当前测试环境中 `servers` 为空，表示不上传到远端服务器，只在本地保存和查看。

### 5.6 数据库配置

PostgreSQL 配置示例：

```text
config/database_postgresql.yaml
```

数据库脚本目录：

```text
scripts/database/postgresql/
```

当前版本保留 JSON/JSONL 文件持久化能力；数据库脚本用于服务端关系型存储升级。

---

## 6. 启动与停止

### 6.1 启动服务端

在项目根目录执行：

```powershell
$env:MSYS2_ROOT = "<MSYS2安装目录>"
$env:PATH = "$env:MSYS2_ROOT\mingw64\bin;$env:MSYS2_ROOT\usr\bin;$env:PATH"
.\build\auditforwarder-server.exe -c .\config\server_windows.yaml
```

启动成功后，浏览器打开：

```text
http://127.0.0.1:8443/
```

同一局域网内其他设备访问：

```text
http://10.4.122.141:8443/
```

### 6.2 启动客户端

客户端用于在被监管主机上运行，主动向服务端上报心跳、资源指标和审计摘要，并轮询远程命令。

```powershell
$env:MSYS2_ROOT = "<MSYS2安装目录>"
$env:PATH = "$env:MSYS2_ROOT\mingw64\bin;$env:MSYS2_ROOT\usr\bin;$env:PATH"
.\build\auditforwarder-client.exe -c .\config\client_windows.yaml
```

### 6.3 启动一体化程序

一体化程序兼容旧运行方式，适合本机学习和调试：

```powershell
$env:MSYS2_ROOT = "<MSYS2安装目录>"
$env:PATH = "$env:MSYS2_ROOT\mingw64\bin;$env:MSYS2_ROOT\usr\bin;$env:PATH"
.\build\auditforwarderd.exe -c .\config\agent_windows.yaml -d data -L info
```

### 6.4 停止项目

在运行窗口按：

```text
Ctrl + C
```

如果需要强制停止：

```powershell
Get-Process auditforwarderd,auditforwarder-server,auditforwarder-client -ErrorAction SilentlyContinue | Stop-Process -Force
```

---

## 7. 用户界面操作指南

### 7.1 登录认证

打开页面后，系统会先显示登录表单。

登录账号和密码使用你在 `manager.login_username`、`manager.login_password_sha256` 中自行配置的值（交付包不内置默认密码）。

登录成功后，服务端会签发会话 Token，浏览器会自动保存并进入控制台。

如果连续 3 次登录失败，当前账号和来源 IP 会临时锁定 15 分钟。错误提示不会区分“账号错误”或“密码错误”，避免泄露账号状态。

### 7.2 运行概览

用于查看当前系统状态。

显示内容包括：

- 是否运行中
- 已采集事件数量
- 已上传事件数量
- 失败事件数量
- 告警数量
- 丢弃事件数量
- 上传字节数
- 运行时长

### 7.3 配置中心

用于查看当前配置快照。

可执行操作：

- 查看配置
- 复制配置
- 重新加载配置

注意：重新加载配置属于敏感操作，需要正确 Token。

### 7.4 证据批次

用于查看系统已生成的批次。

每个批次显示：

- 批次 ID
- Merkle Root 摘要
- 数字签名摘要
- 完整 Merkle Root
- 完整数字签名

完整批次文件保存在：

```text
data/batches/{batch_id}.json
```

### 7.5 主机管理

用于注册、维护和监控接入监管系统的客户端主机。

支持能力：

- 手动新增、编辑、删除主机信息。
- 查看主机在线/离线状态、CPU、内存和最后心跳时间。
- 按主机查看资源指标、审计摘要、命令结果、操作日志和告警历史。
- 向指定主机下发白名单远程控制指令。

注意：生产环境中客户端应通过 `/hosts/register` 或 `/hosts/heartbeat` 携带正确 `enrollment_key` 自动注册，避免人工录入错误。

### 7.6 操作记录

用于查看前端生成的结构化操作记录。

记录字段包括：

```text
actor               执行者身份
timestamp           秒级时间戳
object              操作对象
operation_type      操作类型
operation_details   操作细节
status              成功或失败
error_message       失败原因，失败时出现
```

可执行操作：

- 修改执行者身份
- 复制记录
- 导出 JSON
- 清空记录

### 7.7 运维操作

当前支持提交升级包 URL。

示例：

```text
http://127.0.0.1:9000/auditforwarderd.exe
```

注意：当前后端主要记录升级请求，实际生产升级流程需要结合正式发布系统。

### 7.8 设置 Token

正常使用建议通过登录页进入系统。右上角“设置 Token”主要用于本地调试或脚本验证。

调试 Token：

```text
<请填写你在 server 配置中设置的 auth_token>
```

Token 会保存在当前浏览器，用于访问需要认证的接口。

---

## 8. API 使用说明

常用接口：

```text
GET  /              前端页面
POST /auth/login    管理员登录并签发 Token
GET  /status        查看运行状态
GET  /health        健康检查
GET  /config        查看配置
GET  /batches       查看最近批次
POST /config/reload 重新加载配置
POST /upgrade       提交升级请求
GET  /hosts         查看主机列表
POST /hosts/register 注册主机
POST /hosts/heartbeat 上报主机心跳
POST /agent/metrics 上报资源指标
POST /agent/operation-logs 上传结构化操作日志
GET  /logs/query    检索操作日志
GET  /logs/analytics 日志与告警统计分析
GET  /alerts        查看违规告警
```

需要 Token 的接口通常要带上请求头。推荐先调用登录接口获取会话 Token：

```powershell
$body = @{
  username = "admin"
  password_sha256 = "<你的登录密码的SHA-256哈希>"
} | ConvertTo-Json

$login = Invoke-RestMethod `
  -Uri "http://127.0.0.1:8443/auth/login" `
  -Method Post `
  -ContentType "application/json" `
  -Body $body
```

然后把返回的 Token 放入请求头：

```powershell
Invoke-RestMethod `
  -Uri "http://127.0.0.1:8443/config/reload" `
  -Method Post `
  -Headers @{"Authorization"="Bearer $($login.token)"}
```

调试环境也可以使用固定管理 Token（即在配置中自行设置的 `auth_token`）：

```text
Authorization: Bearer <你的auth_token>
```

---

## 9. 数据操作规范

### 9.1 批次文件

批次文件位于：

```text
data/batches
```

操作建议：

- 不要手动修改批次文件内容。
- 如需分析，应复制副本后再处理。
- 保留原始 JSON 文件，避免破坏证据链。
- 批次文件保存原始 JSON 内容，不做派生转换。

### 9.2 日志文件

日志文件位于配置中的 `log.file`。

建议：

- 日志应按时间顺序保存。
- 不要直接删除正在使用的日志文件。
- 导出日志时保留时间戳、级别、模块名和消息内容。

### 9.3 操作记录

前端操作记录保存在浏览器本地。

建议：

- 重要操作后及时导出 JSON。
- 导出文件应和批次文件一起归档。
- 审计场景下不要只依赖浏览器本地记录，应结合后端日志和批次文件验证。

### 9.4 登录审计日志

登录行为审计日志保存到：

```text
data/server/login_audit.jsonl
```

记录内容包括：

- 登录时间
- 用户名
- 来源 IP
- 成功、失败或锁定状态
- 简要说明

### 9.5 数据库存储与备份

PostgreSQL 脚本位于：

```text
scripts/database/postgresql/
```

主要文件：

```text
001_schema.sql          建表脚本
002_seed.sql            基础数据初始化脚本
backup_restore.ps1      备份与恢复脚本
README.md               脚本使用说明
```

生产环境建议每日备份，并定期做恢复演练。

---

## 10. 安全注意事项

### 10.1 登录与 Token 安全

交付包不内置任何默认 Token 或默认密码。`auth_token` 默认留空（本地接口免固定 Token 认证），`login_password_sha256` 为占位值，需自行配置后才能登录。

生产环境不要使用简单 Token，也不要使用弱密码。

建议使用复杂值，例如：

```text
AF-prod-2026-long-random-secret
```

不要把 Token 写在公开文档、聊天记录或截图中。

生产环境应修改 `manager.login_username` 和 `manager.login_password_sha256`（生成方法见《本地测试环境配置说明.md》），并启用 HTTPS/TLS。

### 10.2 管理地址安全

默认监听：

```text
127.0.0.1:8443
```

这表示只允许本机访问。

如果改成：

```text
0.0.0.0:8443
```

则可能允许局域网或外部访问，必须配合更严格的认证和防火墙策略。

当前测试配置已经改为：

```text
0.0.0.0:8443
```

同一局域网访问地址示例：

```text
http://10.4.122.141:8443/
```

如果其他设备无法访问，需要确认 Windows 防火墙是否放行 8443 端口。管理员 PowerShell 示例：

```powershell
New-NetFirewallRule -DisplayName "AuditForwarder 8443" -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow
```

### 10.3 HTTPS/TLS

当前本地调试配置：

```yaml
manager:
  use_tls: false
```

这表示使用 HTTP，适合本机或局域网测试。生产环境必须配置：

```yaml
manager:
  use_tls: true
  tls_cert: "server.crt"
  tls_key: "server.key"
```

否则登录 Token 和请求内容会通过明文 HTTP 传输。

### 10.4 管理员权限

Windows 安全日志采集需要管理员权限。

如果没有管理员权限，可能看到：

```text
collector: etw_win start failed: EvtSubscribe
```

这通常不影响前端页面、普通进程采集和批次查看。

### 10.5 原始证据保护

批次文件、日志文件和操作记录都属于审计材料。

建议：

- 定期备份。
- 限制写权限。
- 使用只读归档保存重要批次。
- 不要用摘要、截图或人工整理内容替代原始 JSON。

---

## 11. 故障排除

### 11.1 浏览器打不开页面

检查项目是否运行：

```powershell
Get-Process auditforwarder-server -ErrorAction SilentlyContinue
```

检查端口：

```powershell
netstat -ano | Select-String "8443"
```

重新启动：

```powershell
$env:MSYS2_ROOT = "<MSYS2安装目录>"
$env:PATH = "$env:MSYS2_ROOT\mingw64\bin;$env:MSYS2_ROOT\usr\bin;$env:PATH"
.\build\auditforwarder-server.exe -c .\config\server_windows.yaml
```

如果本机能打开、其他电脑打不开，请检查：

- 服务端是否监听 `0.0.0.0:8443`。
- 对方是否和服务端在同一局域网。
- Windows 防火墙是否放行 TCP 8443。

### 11.2 构建失败：Permission denied

如果出现：

```text
cannot open output file auditforwarder-server.exe: Permission denied
```

通常是程序正在运行，Windows 无法覆盖 exe。

处理方法：

```powershell
Get-Process auditforwarderd,auditforwarder-server,auditforwarder-client -ErrorAction SilentlyContinue | Stop-Process -Force
$env:MSYS2_ROOT\usr\bin\make.exe -C build -j4
```

### 11.3 接口返回未授权

如果调用接口失败并提示未授权，优先重新登录。

前端操作：

```text
刷新页面
输入你自行配置的登录账号和密码
```

PowerShell 操作（使用你自行配置的 `auth_token`）：

```powershell
-Headers @{"Authorization"="Bearer <你的auth_token>"}
```

如果连续登录失败 3 次，需要等待 15 分钟或重启服务端清空内存锁定状态。

### 11.4 没有生成批次文件

可能原因：

- 事件数量还没有达到批次容量。
- 采集器没有采集到事件。
- 程序没有正常运行。
- 数据目录没有写入权限。

检查目录：

```powershell
Get-ChildItem .\data\batches
```

### 11.5 Windows 安全日志采集失败

错误示例：

```text
EvtSubscribe
failed to subscribe to Security log
```

解决方法：

- 用管理员权限启动 PowerShell。
- 确认当前用户有读取安全日志的权限。
- 测试阶段可以忽略该错误，其他模块仍可运行。

### 11.6 页面显示旧内容

浏览器可能缓存了旧的 CSS 或 JavaScript。

解决方法：

```text
Ctrl + F5
```

强制刷新页面。

---

## 12. 性能与容量说明

### 12.1 批次容量

批次容量由配置决定：

```yaml
chain:
  batch_size: 10
```

触发逻辑：

```text
pending 事件数量 >= batch_size 时自动 flush
```

### 12.2 文件大小

批次文件大小取决于事件数量和事件字段长度。根据当前本地样例，一个 256 条事件的批次文件大约为：

```text
160 KB ~ 475 KB
```

实际大小取决于事件字段长度。

### 12.3 性能影响因素

主要影响因素：

- 事件产生速度
- 批次容量
- Merkle Root 计算
- HMAC 或签名计算
- 磁盘写入速度
- 是否启用远程传输

---

## 13. 版本更新记录

### v1.0.0

基础能力：

- 跨平台审计代理
- Collector / Processor / Detector / Chain / Transport 架构
- 事件链和批次文件
- Merkle Root 和 HMAC / 签名
- 管理 API
- Windows 测试配置

近期增强：

- 新增浏览器管理界面。
- 新增“证据批次”卡片式展示。
- 新增主机管理、状态监控、日志检索和告警查看能力。
- 新增结构化操作记录页面。
- 新增安全登录页面、会话 Token、失败锁定和登录审计日志。
- 新增独立服务端程序 `auditforwarder-server.exe`。
- 新增独立客户端程序 `auditforwarder-client.exe`。
- 新增客户端心跳、资源指标上报、审计摘要上报、命令轮询和结果回传。
- 新增日志可视化分析接口和前端统计卡片。
- 新增 PostgreSQL 数据库设计文档、建表脚本、初始化脚本和备份恢复脚本。
- 服务端测试配置支持 `0.0.0.0:8443`，便于局域网访问。
- 优化批次 JSON 文件格式。
- 批次文件保留原始内容。
- 空服务器配置下不启动无意义的传输线程。

---

## 14. 技术支持与联系方式

当前项目为本地开发和学习项目，建议按以下顺序获取支持：

1. 查看项目文档：

```text
README.md
docs/ARCHITECTURE.md
docs/OPERATIONS.md
docs/PROTOCOL.md
docs/PROJECT_SPEC.md
docs/USER_MANUAL.md
docs/API_REFERENCE.md
docs/DATABASE_DESIGN.md
docs/DATABASE_API.md
```

2. 查看运行日志：

```text
data/server/server.log
data/client/client.log
data/server/login_audit.jsonl
```

3. 查看配置文件：

```text
config/server_windows.yaml
config/client_windows.yaml
config/agent_windows.yaml
config/agent.yaml
config/rules.yaml
config/database_postgresql.yaml
```

4. 联系项目维护人员：

```text
维护人：请在正式交付时填写
邮箱：请在正式交付时填写
Issue 地址：请在正式交付时填写
安全问题联系人：请在正式交付时填写
```

如果用于生产环境，建议补充正式的技术支持邮箱、问题跟踪地址和安全事件响应流程。

---

## 15. 快速使用清单

首次使用可以按下面顺序操作：

```text
1. 构建项目
2. 启动 auditforwarder-server.exe
3. 打开 http://127.0.0.1:8443/
4. 使用你自行配置的登录账号和密码登录
5. 启动 auditforwarder-client.exe
6. 查看主机管理页面，确认 test-agent-001 在线
7. 查看运行概览、日志与告警
8. 下发 collect_status 测试命令
9. 查看命令结果和审计摘要
10. 根据日志、批次文件和登录审计记录进行审计分析
```

常用服务端启动命令：

```powershell
$env:MSYS2_ROOT = "<MSYS2安装目录>"
$env:PATH = "$env:MSYS2_ROOT\mingw64\bin;$env:MSYS2_ROOT\usr\bin;$env:PATH"
.\build\auditforwarder-server.exe -c .\config\server_windows.yaml
```

常用客户端启动命令：

```powershell
$env:MSYS2_ROOT = "<MSYS2安装目录>"
$env:PATH = "$env:MSYS2_ROOT\mingw64\bin;$env:MSYS2_ROOT\usr\bin;$env:PATH"
.\build\auditforwarder-client.exe -c .\config\client_windows.yaml
```
