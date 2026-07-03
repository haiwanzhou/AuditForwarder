# 项目结构说明

本文档说明客户端、服务器端和共享代码的文件边界，便于后续开发、部署和维护。

## 顶层目录

```text
AuditForwarder/
├── client/          # 客户端 Agent 相关代码
├── server/          # 服务端管理接口和 Web 前端
├── shared/          # 客户端与服务端共用实现
├── include/         # 公共头文件接口
├── config/          # 运行配置和规则配置
├── docs/            # 项目文档
├── scripts/         # 安装和运维脚本
├── tests/           # 自动化测试
└── CMakeLists.txt   # 统一构建入口
```

## client

`client/` 存放运行在用户主机上的 Agent 客户端代码。

```text
client/src/core/
```

负责 Agent 生命周期、远端客户端、守护进程、自保护和系统服务入口。

```text
client/src/collector/
```

负责采集 Windows/Linux 系统事件、文件事件、进程事件、网络事件等。

```text
client/src/processor/
```

负责事件补全、脱敏、去重等处理管道。

```text
client/src/transport/
```

负责批次上传、传输重试、加密传输相关逻辑。

```text
client/src/main.cpp
```

兼容程序入口，构建为 `auditforwarderd`。

```text
client/src/client_main.cpp
```

独立客户端入口，构建为 `auditforwarder-client`，默认关闭本机管理后台，只负责采集、心跳、指标上报、命令轮询和结果回传。

## server

`server/` 存放远端管理服务和前端页面。

```text
server/src/manager/
```

负责 HTTP/HTTPS 管理 API、主机管理、指标接收、远控命令队列、命令结果回传和静态页面服务。

```text
server/src/server_main.cpp
```

独立服务端入口，构建为 `auditforwarder-server`，默认关闭本机采集器和远端客户端，只负责监管系统服务端能力。

```text
server/web/
```

负责 Web 管理界面，包括首页、样式和前端脚本。

## shared

`shared/` 存放客户端和服务器端都会使用的公共实现。

```text
shared/src/common/
```

日志、配置、文件系统、线程池、进程工具和事件序列化等基础能力。

```text
shared/src/crypto/
```

SHA-256、HMAC、AES-GCM、Ed25519、事件链和批次存证逻辑。

```text
shared/src/detector/
```

规则引擎实现。当前主要由客户端 Agent 使用，后续服务端做集中分析时也可复用。

## include

`include/auditforwarder/` 是公共头文件接口层。客户端、服务器端和共享模块都通过这里声明类型、接口和配置结构。

## 文件组织原则

- 只在客户端运行的功能放入 `client/`。
- 只在服务端运行的 API、Web 和管理能力放入 `server/`。
- 客户端和服务端都需要的基础能力放入 `shared/`。
- 公共接口声明放入 `include/`，具体实现放入对应端目录。
- 新增文件后必须同步更新 `CMakeLists.txt`。
- 服务端前端资源统一从 `server/web/` 读取和安装。

## 构建与运行影响

目录分离后，构建入口仍是根目录 `CMakeLists.txt`，会生成三个可执行程序：

- `auditforwarderd`：兼容的一体化程序。
- `auditforwarder-client`：用户端 Agent 程序。
- `auditforwarder-server`：监管服务端程序。

开发构建：

```powershell
make -C build -j4
```

独立服务端运行：

```powershell
.\build\auditforwarder-server.exe -c config\server_windows.yaml -d data\server -L info
```

独立客户端运行：

```powershell
.\build\auditforwarder-client.exe -c config\client_windows.yaml -d data\client -L info
```

Web 页面访问方式不变：

```text
http://127.0.0.1:8443/
```
