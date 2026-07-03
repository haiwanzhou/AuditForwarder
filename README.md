﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿﻿# AuditForwarder

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

## 文档

- [项目规格说明](docs/PROJECT_SPEC.md)
- [架构说明](docs/ARCHITECTURE.md)
- [项目结构说明](docs/PROJECT_STRUCTURE.md)
- [API 文档](docs/API_REFERENCE.md)
- [开发文档](docs/DEVELOPMENT_GUIDE.md)
- [测试计划](docs/TEST_PLAN.md)
- [用户手册](docs/USER_MANUAL.md)
- [运维说明](docs/OPERATIONS.md)

## 许可证

Apache 2.0
