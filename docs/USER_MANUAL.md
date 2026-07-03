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

当前代码默认批次容量为：

```text
256 条事件 / 批次
```

说明：`config/agent_windows.yaml` 中虽然写有 `chain.batch_size: 10`，但当前代码尚未把该 YAML 配置映射到运行参数中，因此实际运行仍使用默认值 `256`。

### 2.5 管理界面

系统提供浏览器前端界面：

```text
http://127.0.0.1:8443/
```

界面模块包括：

- 运行概览
- 配置中心
- 证据批次
- 主机管理
- 日志与告警
- 操作记录
- 运维操作
- Token 设置

### 2.6 结构化操作记录

前端会记录用户在页面上的关键操作，包括：

- 执行者身份
- 秒级时间戳
- 操作对象
- 操作类型
- 操作细节
- 成功或失败状态

这些记录保存在浏览器本地，可复制或导出为 JSON。

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
C:\msys64\ucrt64\bin
C:\msys64\usr\bin
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
cd C:\Users\30952\Desktop\AuditForwarder
```

### 4.2 Windows 构建

如果已经生成过 `build` 目录，可以直接重新构建：

```powershell
$env:PATH = "C:\msys64\ucrt64\bin;C:\msys64\usr\bin;$env:PATH"
make -C build -j4
```

如果是首次构建，一般流程如下：

```powershell
$env:PATH = "C:\msys64\ucrt64\bin;C:\msys64\usr\bin;$env:PATH"
cmake -S . -B build
make -C build -j4
```

构建成功后，主程序位置为：

```text
build/auditforwarderd.exe
```

### 4.3 Linux 构建

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

---

## 5. 配置说明

Windows 测试配置文件：

```text
config/agent_windows.yaml
```

通用配置文件：

```text
config/agent.yaml
```

### 5.1 管理服务配置

```yaml
manager:
  enabled: true
  listen: 127.0.0.1:8443
  auth_token: "test-token-12345"
```

字段说明：

- `enabled`：是否启用管理后台。
- `listen`：浏览器和 API 访问地址。
- `auth_token`：访问敏感接口时使用的 Token。

### 5.2 数据目录配置

```yaml
agent:
  data_dir: C:\Users\30952\Desktop\AuditForwarder\data
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
  file: C:\Users\30952\Desktop\AuditForwarder\data\agent.log
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

### 5.4 传输配置

```yaml
transport:
  servers: []
  mode: batch
  interval_sec: 60
  compress: false
  encrypt_payload: false
```

当前测试环境中 `servers` 为空，表示不上传到远端服务器，只在本地保存和查看。

---

## 6. 启动与停止

### 6.1 启动项目

在项目根目录执行：

```powershell
$env:PATH = "C:\msys64\ucrt64\bin;C:\msys64\usr\bin;$env:PATH"
.\build\auditforwarderd.exe -c config\agent_windows.yaml -d data -L info
```

启动成功后，浏览器打开：

```text
http://127.0.0.1:8443/
```

### 6.2 停止项目

在运行窗口按：

```text
Ctrl + C
```

如果需要强制停止：

```powershell
Get-Process auditforwarderd -ErrorAction SilentlyContinue | Stop-Process -Force
```

---

## 7. 用户界面操作指南

### 7.1 运行概览

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

### 7.2 配置中心

用于查看当前配置快照。

可执行操作：

- 查看配置
- 复制配置
- 重新加载配置

注意：重新加载配置属于敏感操作，需要正确 Token。

### 7.3 证据批次

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

### 7.4 主机管理

用于注册、维护和监控接入监管系统的客户端主机。

支持能力：

- 手动新增、编辑、删除主机信息。
- 查看主机在线/离线状态、CPU、内存和最后心跳时间。
- 按主机查看资源指标、审计摘要、命令结果、操作日志和告警历史。
- 向指定主机下发白名单远程控制指令。

注意：生产环境中客户端应通过 `/hosts/register` 或 `/hosts/heartbeat` 携带正确 `enrollment_key` 自动注册，避免人工录入错误。

### 7.5 操作记录

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

### 7.6 运维操作

当前支持提交升级包 URL。

示例：

```text
http://127.0.0.1:9000/auditforwarderd.exe
```

注意：当前后端主要记录升级请求，实际生产升级流程需要结合正式发布系统。

### 7.7 设置 Token

点击右上角“设置 Token”，输入：

```text
test-token-12345
```

Token 会保存在当前浏览器，用于访问需要认证的接口。

---

## 8. API 使用说明

常用接口：

```text
GET  /              前端页面
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
GET  /alerts        查看违规告警
```

需要 Token 的接口通常要带上请求头：

```text
Authorization: Bearer test-token-12345
```

PowerShell 示例：

```powershell
Invoke-RestMethod `
  -Uri "http://127.0.0.1:8443/config/reload" `
  -Method Post `
  -Headers @{"Authorization"="Bearer test-token-12345"}
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

---

## 10. 安全注意事项

### 10.1 Token 安全

测试 Token：

```text
test-token-12345
```

生产环境不要使用简单 Token。

建议使用复杂值，例如：

```text
AF-prod-2026-long-random-secret
```

不要把 Token 写在公开文档、聊天记录或截图中。

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

### 10.3 管理员权限

Windows 安全日志采集需要管理员权限。

如果没有管理员权限，可能看到：

```text
collector: etw_win start failed: EvtSubscribe
```

这通常不影响前端页面、普通进程采集和批次查看。

### 10.4 原始证据保护

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
Get-Process auditforwarderd -ErrorAction SilentlyContinue
```

检查端口：

```powershell
netstat -ano | Select-String "8443"
```

重新启动：

```powershell
.\build\auditforwarderd.exe -c config\agent_windows.yaml -d data -L info
```

### 11.2 构建失败：Permission denied

如果出现：

```text
cannot open output file auditforwarderd.exe: Permission denied
```

通常是程序正在运行，Windows 无法覆盖 exe。

处理方法：

```powershell
Get-Process auditforwarderd -ErrorAction SilentlyContinue | Stop-Process -Force
make -C build -j4
```

### 11.3 接口返回未授权

如果调用接口失败并提示未授权，检查 Token。

前端操作：

```text
点击“设置 Token”
输入 config/agent_windows.yaml 中的 manager.auth_token
```

PowerShell 操作：

```powershell
-Headers @{"Authorization"="Bearer test-token-12345"}
```

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

当前实际批次容量：

```text
256 条事件 / 批次
```

触发逻辑：

```text
pending 事件数量 >= batch_size 时自动 flush
```

### 12.2 文件大小

根据当前本地样例，一个 256 条事件的批次文件大约为：

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
```

2. 查看运行日志：

```text
data/agent.log
```

3. 查看配置文件：

```text
config/agent_windows.yaml
config/agent.yaml
config/rules.yaml
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
2. 启动 auditforwarderd.exe
3. 打开 http://127.0.0.1:8443/
4. 设置 Token
5. 查看运行概览
6. 查看配置中心
7. 查看证据批次
8. 设置执行者身份
9. 查看或导出操作记录
10. 根据日志和批次文件进行审计分析
```

常用启动命令：

```powershell
$env:PATH = "C:\msys64\ucrt64\bin;C:\msys64\usr\bin;$env:PATH"
.\build\auditforwarderd.exe -c config\agent_windows.yaml -d data -L info
```
