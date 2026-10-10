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
│   └── database/    # 关系型数据库建表、初始化和备份恢复脚本
├── tests/           # 自动化测试
├── AuditForwarder-Server-Bundle/  # 服务端一键部署包（启动脚本+配置模板）
├── AuditForwarder-Client-Bundle/  # 客户端一键部署包（启动脚本+配置模板+使用说明）
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
client/src/collector/adapters/
```

安全产品适配器（M2 新增）：对接异构安全产品日志源并统一转为 `AuditEvent`。包含三类适配器实现：

- `syslog_adapter.cpp/.h`：UDP 514 监听，按 RFC 3164/5424 解析 Syslog 报文。
- `db_audit_adapter.cpp/.h`：JSON Lines 增量轮询数据库审计日志。
- `bastion_adapter.cpp/.h`：REST API 游标轮询堡垒机操作记录。

适配器在 `client/src/core/agent.cpp` 中按配置注册到采集流水线，产出事件与系统采集器事件走同一条链签名路径。

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
server/src/collusion/
```

跨操作员合谋协同检测模块（v1.1.0 新增）：事件清洗与资产组聚合、双窗口冲刷、规则引擎、行为画像评分、工单核验、风险分级、告警降噪、事件留存与处置报表。通过 manager 中的单行钩子并行接入，不侵入原有审计链路。公共接口声明在 `include/auditforwarder/collusion.h`。

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

SHA-256、HMAC、AES-GCM、Ed25519、事件链和批次存证逻辑。M1 在 `chain.cpp` 中新增 `build_super_batch` / `persist_super_batch` 实现，`flush()` 尾部触发超级批次聚合。

```text
shared/src/detector/
```

规则引擎实现。当前主要由客户端 Agent 使用，后续服务端做集中分析时也可复用。

```text
shared/src/ml/
```

机器学习推理与行为特征工程（M3 新增）：

- `onnx_inference.cpp`：`OnnxModel` 实现，PIMPL 封装 ONNX Runtime，条件编译 `AF_HAVE_ONNXRUNTIME`，无运行时时优雅降级。
- `feature_extractor.cpp`：`FeatureExtractor` 实现，从聚合事件集合 + 行为画像提取固定 20 维 `BehaviorFeatures` 向量。

```text
shared/src/graph/
```

轻量级图算法模块（M4 新增）：

- `behavior_graph.cpp`：`BehaviorGraph` 实现，纯 C++ 无外部依赖，包含度中心性、Louvain 社区检测、三角形计数、Jaccard 相似度四类算法，替代 GNN 行为图谱。

## include

`include/auditforwarder/` 是公共头文件接口层。客户端、服务器端和共享模块都通过这里声明类型、接口和配置结构。M1-M4 新增以下头文件：

- `security_adapter.h`（M2）：`SecurityAdapter` 抽象基类，定义安全产品适配器统一接口。
- `onnx_inference.h`（M3）：`OnnxModel` 类，PIMPL + 条件编译 + 优雅降级。
- `feature_extractor.h`（M3）：`BehaviorFeatures` 20 维结构 + `FeatureExtractor` 类。
- `behavior_graph.h`（M4）：`BehaviorGraph` 类 + `AnalysisResult` 结构，三类节点 `Operator` / `Asset` / `OpType`。

`chain.h` 在 M1 中新增 `SuperBatch` 结构体、`set_super_batch_size` / `last_super_root` / `verify_super_batch` / `recent_super_batches` 等方法；`collusion.h` 在 M3/M4 中扩展 `EngineConfig`（`ml_*` / `graph_*` 字段）、`DetectionResult`（`ml_factor` / `graph_factor` / `ml_notes` / `graph_notes`）、`detect()` 签名（新增 `OnnxModel*` 与 `BehaviorGraph*` 参数）以及 `Engine` 私有成员（`onnx_if_` / `graph_baseline_`）。

## 数据库脚本

`scripts/database/postgresql/` 存放 PostgreSQL 数据库交付物。

```text
scripts/database/postgresql/001_schema.sql
```

创建服务端关系型数据库表、索引、约束、触发器和视图。

```text
scripts/database/postgresql/002_seed.sql
```

初始化默认角色、占位管理员账号和开发测试主机。

```text
scripts/database/postgresql/backup_restore.ps1
```

执行 PostgreSQL 逻辑备份、恢复和旧备份清理。

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
