﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿# AuditForwarder

企业级跨平台安全审计代理系统。

## 主要特性

- 跨平台支持：Linux 和 Windows
- 实时操作监控与日志采集
- SHA-256 哈希链 + Merkle 树可信存证
- 规则引擎异常检测
- HTTPS 传输（压缩 + 加密）
- 自我保护机制（完整性校验、看门狗）
- 远程管理 API
- Agent 主动心跳、资源指标上报、审计摘要上报
- 多主机管理、远程命令下发、命令结果回传
- Web 前端管理界面和字段级输入校验
- 安全登录页面、会话 Token、失败锁定和登录审计
- PostgreSQL 数据库设计、建表脚本、初始化脚本和备份恢复脚本

## 快速开始

### Linux

```bash
sudo apt install -y build-essential cmake pkg-config libssl-dev zlib1g-dev libaudit-dev
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
sudo ./scripts/install_linux.sh --start
```

### Windows

```powershell
vcpkg install openssl zlib
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release -j
powershell -ExecutionPolicy Bypass -File scripts\install_windows.ps1 -Start
```

### 本地服务端与客户端

启动服务端：

```powershell
$env:MSYS2_ROOT = "<MSYS2安装目录>"  # 示例：安装 MSYS2 后填写实际目录
$env:PATH = "$env:MSYS2_ROOT\mingw64\bin;$env:MSYS2_ROOT\usr\bin;$env:PATH"
.\build\auditforwarder-server.exe -c .\config\server_windows.yaml
```

启动客户端：

```powershell
$env:MSYS2_ROOT = "<MSYS2安装目录>"  # 示例：安装 MSYS2 后填写实际目录
$env:PATH = "$env:MSYS2_ROOT\mingw64\bin;$env:MSYS2_ROOT\usr\bin;$env:PATH"
.\build\auditforwarder-client.exe -c .\config\client_windows.yaml
```

服务端页面：

```text
http://127.0.0.1:8443/
```

局域网访问示例：

```text
http://10.4.122.141:8443/
```

本地测试登录：

```text
账号：admin
密码：admin123
```

生产环境请修改默认账号密码并启用 HTTPS/TLS。

## 文档

- [项目运行指南](项目运行指南.md)
- [VS Code 编译运行指南](VSCode编译运行指南.md)
- [本地测试环境配置说明](本地测试环境配置说明.md)
- [项目规格说明](docs/PROJECT_SPEC.md)
- [架构说明](docs/ARCHITECTURE.md)
- [项目结构说明](docs/PROJECT_STRUCTURE.md)
- [API 文档](docs/API_REFERENCE.md)
- [数据库设计](docs/DATABASE_DESIGN.md)
- [数据库 API 与示例](docs/DATABASE_API.md)
- [开发文档](docs/DEVELOPMENT_GUIDE.md)
- [测试计划](docs/TEST_PLAN.md)
- [用户手册](docs/USER_MANUAL.md)
- [运维说明](docs/OPERATIONS.md)

## 许可证

Apache 2.0
