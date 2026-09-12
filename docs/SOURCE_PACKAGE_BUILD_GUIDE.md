# AuditForwarder 源码包编译说明书

本文档用于指导接收源码压缩包的用户，在 Windows 主机上把 AuditForwarder 源码编译成可执行程序，并启动服务端或客户端。

## 1. 源码包内容

解压后应看到类似目录：

```text
AuditForwarder/
├─ client/                 客户端 Agent 源码
├─ server/                 服务端管理后台和 Web 页面
├─ shared/                 客户端与服务端共享实现
├─ include/                公共头文件
├─ config/                 示例配置文件
├─ docs/                   项目文档
├─ scripts/                安装、数据库和辅助脚本
├─ tests/                  测试代码
├─ CMakeLists.txt          CMake 构建入口
├─ README.md               项目简介
└─ LICENSE                 许可证
```

源码包不包含 `.git/`、`build/`、`data/` 等本机生成目录。

## 2. 环境要求

推荐环境：

```text
Windows 10/11
MSYS2 MinGW64
CMake 3.20+
GCC/G++ 11+
PowerShell 5+
```

项目当前本机验证使用的工具路径：

```text
<MSYS2安装目录>\mingw64\bin
<MSYS2安装目录>\usr\bin
```

## 3. 安装 MSYS2 和构建工具

1. 安装 MSYS2。

   下载地址：

   ```text
   https://www.msys2.org/
   ```

2. 打开 “MSYS2 MSYS” 终端，更新基础环境：

   ```bash
   pacman -Syu
   ```

   如果提示关闭窗口，关闭后重新打开 “MSYS2 MSYS”，再执行：

   ```bash
   pacman -Su
   ```

3. 安装 MinGW64 编译工具、CMake、Make 和 OpenSSL：

   ```bash
   pacman -S --needed mingw-w64-x86_64-toolchain mingw-w64-x86_64-cmake mingw-w64-x86_64-openssl make
   ```

## 4. 解压源码包

建议解压到路径中不含中文和空格的位置，例如：

```text
C:\AuditForwarder
```

如果解压在桌面也可以，但后续命令中的路径要按实际位置调整。

## 5. 配置 PowerShell 环境变量

打开 PowerShell，进入项目目录：

```powershell
cd C:\AuditForwarder
```

把 MSYS2 的运行库和工具加入当前窗口的 `PATH`：

```powershell
$env:MSYS2_ROOT = "<MSYS2安装目录>"
$env:PATH = "$env:MSYS2_ROOT\mingw64\bin;$env:MSYS2_ROOT\usr\bin;$env:PATH"
```

验证工具是否可用：

```powershell
cmake --version
$env:MSYS2_ROOT\usr\bin\make.exe --version
g++ --version
```

## 6. 编译项目

首次编译：

```powershell
cmake -S . -B build -G "Unix Makefiles"
$env:MSYS2_ROOT\usr\bin\make.exe -C build -j4
```

编译成功后会生成：

```text
build/auditforwarderd.exe          一体化兼容程序
build/auditforwarder-server.exe    独立服务端程序
build/auditforwarder-client.exe    独立客户端程序
```

如果电脑 CPU 核心数较少，可以把 `-j4` 改成 `-j2`。

## 7. 启动服务端

服务端用于提供管理页面、API、主机列表、日志与告警、命令队列和登录认证。

```powershell
.\build\auditforwarder-server.exe -c .\config\server_windows.yaml
```

启动成功后，浏览器打开：

```text
http://127.0.0.1:8443/
```

登录账号：

交付包不内置默认密码，`login_password_sha256` 为占位值。首次使用前请按《本地测试环境配置说明.md》第 6 节生成并替换为自己的密码哈希。

## 8. 允许局域网访问服务端

如果希望同一 Wi-Fi 或局域网内的其他设备访问服务端，确认：

```yaml
manager:
  listen: 0.0.0.0:8443
```

然后查看服务端主机 IP：

```powershell
ipconfig
```

假设 IPv4 地址为：

```text
192.168.1.23
```

其他设备访问：

```text
http://192.168.1.23:8443/
```

如果打不开，需要用管理员 PowerShell 放行端口：

```powershell
New-NetFirewallRule -DisplayName "AuditForwarder 8443" -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow
```

## 9. 启动客户端

客户端用于在被监管主机上运行，主动连接服务端，上报心跳、资源指标、审计摘要，并拉取远程命令。

如果客户端和服务端在同一台电脑上，可以直接运行：

```powershell
.\build\auditforwarder-client.exe -c .\config\client_windows.yaml
```

如果客户端运行在另一台电脑，需要修改：

```text
config/client_windows.yaml
```

把服务端地址改成服务端主机 IP：

```yaml
remote:
  servers:
    - "http://192.168.1.23:8443"
```

同时确认客户端注册密钥和服务端一致（交付包默认留空，如需启用请自行配置相同值）：

```yaml
remote:
  enrollment_key: "<自行生成的注册密钥>"
```

```yaml
manager:
  enrollment_key: "<自行生成的注册密钥>"
```

## 10. 验证运行结果

服务端运行后，在浏览器登录管理页面，检查：

```text
运行概览     服务端状态正常
主机管理     客户端主机显示在线
日志与告警   可以加载日志和统计
运维操作     可以下发 collect_status 测试命令
```

也可以用 PowerShell 测试登录和状态接口：

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

Invoke-RestMethod `
  -Uri "http://127.0.0.1:8443/status" `
  -Headers @{"Authorization"="Bearer $($login.token)"}
```

返回内容中 `running` 为 `true` 表示服务端接口正常。

## 11. 常见问题

### 11.1 提示找不到 DLL

原因通常是 PowerShell 没有加载 MSYS2 运行库路径。

重新执行：

```powershell
$env:MSYS2_ROOT = "<MSYS2安装目录>"
$env:PATH = "$env:MSYS2_ROOT\mingw64\bin;$env:MSYS2_ROOT\usr\bin;$env:PATH"
```

然后再启动程序。

### 11.2 CMake 缓存路径错误

如果移动过项目目录，可能出现 CMake 缓存路径不一致。

删除旧构建目录后重新构建：

```powershell
Remove-Item -Recurse -Force build
cmake -S . -B build -G "Unix Makefiles"
$env:MSYS2_ROOT\usr\bin\make.exe -C build -j4
```

### 11.3 服务端页面打不开

先确认服务端进程正在运行：

```powershell
Get-Process auditforwarder-server -ErrorAction SilentlyContinue
```

再确认访问地址：

```text
本机访问：http://127.0.0.1:8443/
局域网访问：http://服务端IP:8443/
```

如果局域网访问失败，检查防火墙和 `manager.listen`。

### 11.4 登录失败

登录账号和密码使用你在 `manager.login_username`、`manager.login_password_sha256` 中自行配置的值。

连续 3 次失败会临时锁定 15 分钟。等待锁定结束，或重启服务端清空内存锁定状态。

### 11.5 Windows 安全日志采集失败

如果看到 `EvtSubscribe` 相关错误，通常是因为没有管理员权限。客户端和服务端通信仍可正常测试；如需订阅 Windows Security 日志，请用管理员权限运行客户端。

## 12. 安全注意事项

默认配置只适合本地测试或学习演示。正式分享或部署前应修改：

```yaml
manager:
  auth_token: "改成复杂 Token"
  enrollment_key: "改成复杂注册密钥"
  login_username: "改成新的管理员账号"
  login_password_sha256: "改成新密码的 SHA-256"
```

生产环境还应启用 HTTPS/TLS：

```yaml
manager:
  use_tls: true
  tls_cert: "server.crt"
  tls_key: "server.key"
```

不要把默认账号、Token、注册密钥暴露到公网环境。
