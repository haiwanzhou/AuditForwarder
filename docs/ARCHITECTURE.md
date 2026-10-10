# AuditForwarder 架构文档

本文档描述代理的内部架构、数据流以及代理所解决的威胁模型。

## 1. 组件

```
+--------------------------+
|        采集器            |   inotify / RDCW / ETW / audit / /proc / WMI / RegNotif
+----+----+----+-----+------+
     |    |    |     |
     v    v    v     v
+--------------------------+
|   处理器管道             |   增强器 -> PII掩码 -> 去重 -> 采样器 -> 聚合器
+----+----+----+-----+
     |    |    |     |
     v    v    v     v
+--------------------------+
|   检测引擎               |   规则引擎 + 行为基线
+----+----+----+-----+
     |    |    |     |
     v    v    v     v
+--------------------------+
|   监管链                 |   每事件哈希链 + 每批次Merkle + 签名 + 超级批次分层聚合
+----+----+----+-----+
     |    |    |     |
     v    v    v     v
+--------------------------+
|   本地存储               |   /var/lib/auditforwarder/batches/*.json
+--------------------------+
     |
     v
+--------------------------+
|   HTTPS传输              |   压缩 + AEAD + 断点续传 + 退避 + 故障转移
+--------------------------+
```

Manager HTTP接口、Self-Protection看门狗和Stats端点是观察/控制管道的正交服务。

### 1.1 安全产品适配器（M2）

采集器层在原有操作系统采集器之外，新增安全产品适配器子系统，统一对接异构安全产品日志源：

```
+----------------------------+
|   安全产品适配器            |   Syslog(UDP 514) / 数据库审计(JSON Lines) / 堡垒机(REST)
+-----+--------+------------+
      |        |
      v        v
+----------------------------+
|   适配器基类 SecurityAdapter |   open()/poll()/close() -> emit(AuditEvent)
+----------------------------+
      |
      v
   进入 Chain 签名流水线
```

- 适配器基类 `SecurityAdapter`（`include/auditforwarder/security_adapter.h`）定义统一的 `open/poll/close` 接口，具体适配器负责拉取/接收原始日志并转为标准 `AuditEvent`。
- 三类适配器：`syslog_adapter`（UDP 514 监听 + RFC 3164/5424 解析）、`db_audit_adapter`（JSON Lines 增量轮询）、`bastion_adapter`（REST API 游标轮询）。
- 适配器在 `Agent::init()` 中按配置注册到采集流水线，产出事件与系统采集器事件走同一条链签名路径。

## 2. 线程模型

| 线程 | 角色 |
|---|---|
| 采集器工作线程 | 每个采集器一个；将事件推入线程安全的MPSC队列 |
| 处理管道 | 单线程，消耗队列并应用所有处理器 + 检测器 + 链 |
| 链刷新器 | 周期性批次边界；调用 `Chain::flush()` 并交给传输层 |
| 传输工作线程 | 消耗出站队列，执行HTTPS上传并支持退避 |
| Manager调度器 | 每个连接一个线程，处理管理HTTP请求 |
| 自我保护循环 | 周期性完整性检查 |
| 统计计数器 | 受锁保护的 `AgentStats`，由每个事件更新 |

## 3. 事件生命周期

```
   原始操作系统事件
   -> Collector::poll() 产生部分填充的 AuditEvent
   -> Agent::submit() 获取每进程增强信息（主机、agent_id、用户、pid）
   -> 管道处理器：增强 -> PII掩码 -> 去重 -> 采样 -> 聚合
   -> 检测引擎：规则匹配？-> 标记严重性，设置rule_id，分发响应
   -> Chain::submit(): 分配全局序列号，设置时间戳，计算哈希，链接前一哈希
   -> 在批次边界：构建Merkle树，签名（Ed25519 / HMAC），持久化到磁盘
   -> Transport::send_batch(): 压缩，AEAD加密，HTTPS POST
   -> 成功时：移除断点续传检查点
   -> 失败时：使用指数退避重新入队
```

## 4. 防篡改证据

- **事件级别**：每个事件都有 `seq`、`ts_micros`、`prev_hash` 和 `hash = SHA256(canonical_form)`。规范化形式是所有字段的稳定、有序连接。
- **批次级别**：所有事件哈希的Merkle树被根化并用Ed25519（或HMAC-SHA-256备选）签名。签名覆盖批次ID、时间戳和Merkle根。
- **超级批次级别（M1）**：每 K 个 EventBatch 的 `merkle_root` 作为叶子构建上层 Merkle 树，生成 `super_root`；通过 `prev_super_root` 链式锚定前一个超级批次，形成跨批次分层聚合结构。超级批次同样用 HMAC/Ed25519 签名并持久化到 `super_batches/<id>.json`，支持 `verify_super_batch` / `verify_super_batch_with_key` 校验。
- **端到端**：篡改任何事件都会使批次签名失效；篡改批次ID或签名会使传输级信封失效；篡改任一批次根会使对应超级批次的分层签名失效。

## 5. 自我保护

- 在启动时和每个 `check_interval_sec` 对磁盘上的二进制文件计算SHA-256。期望的哈希通过配置提供（`self_protect.known_good_hash`）；不匹配会触发 `critical` 审计事件。
- 安装目录被设置为 `chmod 0555`（Linux）或ACL锁定（Windows），防止非管理员写入。
- 看门狗线程确保代理崩溃时自动重启（systemd `Restart=on-failure` / Windows服务恢复）。

## 6. 威胁模型

范围内：

- 操作员级别的本地活动（命令、文件访问、网络、GUI）
- 提权尝试
- 横向移动（网络、进程注入、计划任务、服务）
- 篡改代理本身
- 与中央平台失去连接

范围外（由平台端处理）：

- 网络层DoS、DDoS
- 加密载荷检查（我们只看到元数据）
- 启动/BIOS级攻击（代理在操作系统用户空间启动）

## 7. 性能

代理设计用于高事件量。每事件工作：

| 阶段 | 延迟 |
|---|---|
| 采集器轮询 | 数十微秒（inotify）到毫秒（ETW） |
| SHA-256 | < 1 微秒 |
| 检测（规则） | 典型10规则集 < 5 微秒 |
| 链 | < 2 微秒 |
| AEAD加密 + 压缩（每批次） | 受批次大小限制 |

现代x86_64上的吞吐量目标：

- 持续 10,000 事件/秒
- 峰值 50,000 事件/秒（使用 `keep_ratio` < 1.0 采样器）

## 8. 扩展

- 新采集器：继承 `af::Collector`，添加到 `platform_*.h` 中的 `create_*_collectors` 辅助函数。
- 新处理器：继承 `af::Processor`，在 `Agent::init()` 中注册。
- 新检测规则：追加到 `rules.yaml`。
- 新传输：继承 `af::Transport`，在 `Agent::init()` 中替换。

## 9. 服务端合谋检测引擎（v1.1.0）

跨操作员合谋协同行为检测是**服务端侧**独立子系统（接口见 `include/auditforwarder/collusion.h`，实现见 `server/src/collusion/collusion.cpp`），与上述客户端管道并行、互不阻塞：

- 接入：审计日志落盘后由服务端复制给合谋引擎，同时提供 `POST /collusion/ingest` 直连接口（设计文档原生格式）。
- 评估：15 分钟短窗 / 4 小时长窗双窗口聚合；窗口到期冲刷，按 R-001~R-005 规则匹配 + 行为画像因子评分（HIGH ≥ 80、MID ≥ 40）；同一聚合 key 5 分钟降噪；有效工单 −40；白名单协同组仅留 0 分线索；应急模式自动降级。
- 输出：风险事件写入 `data/server/collusion/events.jsonl`（中高 180 天、低 90 天留存），HIGH/MID 事件同时以 `source=collusion` 进入统一告警。
- 配置热更新：`data/server/policies/collusion_{config,rules,workorders}.json` 由 Web「合谋检测」页管理，约 2 秒生效。

## 10. 分层 Merkle 树 / 超级批次（M1）

监管链在原有「每事件哈希链 + 每批次 Merkle 树 + 签名」基础上，新增跨批次分层聚合结构（接口见 `include/auditforwarder/chain.h`，实现见 `shared/src/crypto/chain.cpp`）：

- **超级批次（SuperBatch）**：每 K 个 EventBatch 的 `merkle_root` 作为叶子，构建上层 Merkle 树生成 `super_root`；K 由 `ChainConfig::super_batch_k` 控制（默认 8，0 = 禁用）。
- **链式锚定**：每个超级批次记录 `prev_super_root` 指向前一个超级批次根，形成跨批次的链式证据结构，任何中间批次被篡改都会破坏后续超级批次的根。
- **触发时机**：`Chain::flush()` 在尾部检查累计已签名批次是否达到 K 个，达到则调用 `build_super_batch` / `persist_super_batch` 聚合并持久化到 `data_dir/super_batches/<id>.json`。
- **客户端接入**：`Agent` 启动时调用 `Chain::set_super_batch_size(k)` 配置容量。
- **校验**：提供 `verify_super_batch`（HMAC）与 `verify_super_batch_with_key`（Ed25519 公钥）静态方法，用于服务端或审计方验证分层结构与签名一致性。

## 11. ONNX Runtime 推理与行为特征工程（M3）

合谋检测引擎在规则因子 + 画像因子之外，新增 ML 异常检测线索（接口见 `include/auditforwarder/onnx_inference.h` 与 `include/auditforwarder/feature_extractor.h`，实现见 `shared/src/ml/`）：

- **行为特征工程**：`FeatureExtractor` 从聚合事件集合（`AggSet.events`）+ 行为画像（`ProfileSnapshot`）提取固定 20 维 `BehaviorFeatures` 向量，涵盖操作间隔、类型熵、突发占比、跨资产/跨域比例、协作熟悉度、深夜/周末占比等维度，顺序与预训练模型输入对齐。
- **ONNX 推理封装**：`OnnxModel` 采用 PIMPL 隔离 ONNX Runtime C++ API，支持 `load` / `is_loaded` / `infer` 三段式调用；通过条件编译宏 `AF_HAVE_ONNXRUNTIME` 实现有运行时则真实推理、无运行时则优雅降级（`is_loaded()=false`、`infer()` 返回空向量）。
- **引擎集成**：`Engine` 持有 `onnx_if_` 成员；`detect()` 在规则与画像评估后追加 ML 推理段：提取特征 → ONNX 推理得到异常分数 → 超过 `ml_high_threshold` 时计入 `ml_factor`（上限 30，线索性质，不直接触发 HIGH）。
- **模型文件**：预训练模型 `models/isolation_forest.onnx`（输入 [1,20] → 输出 [1] 异常分数）。

## 12. 轻量级图算法替代 GNN（M4）

合谋检测引擎在 ML 线索之外，新增纯 C++ 图算法线索模块（接口见 `include/auditforwarder/behavior_graph.h`，实现见 `shared/src/graph/behavior_graph.cpp`）：

- **异构图构建**：`BehaviorGraph` 以邻接表存储三类节点（`Operator` / `Asset` / `OpType`），从聚合事件集合构建「操作员 → 资产」「操作员 → 操作类型」加权有向边，无外部依赖。
- **四类图算法**：
  - 度中心性异常：操作员节点度数超过均值 +2σ → `degree_anomaly`。
  - Louvain 社区检测（贪心模块度最大化）：陌生社区（仅含 1~2 个操作员且与基线不重合）→ `community_anomaly`。
  - 三角形计数：操作员节点三角形数超过均值 +2σ → `triangle_anomaly`。
  - Jaccard 边集相似度：与历史基线图相似度 < 0.3 → `similarity_anomaly`。
- **引擎集成**：`Engine` 持有 `graph_baseline_` 历史基线图成员；`detect()` 在 ML 推理后追加图分析段：构建当前行为图 → 与基线对比 → 各异常分量累加为 `graph_factor`（上限 25，线索性质，不直接触发 HIGH）。
- **设计取舍**：以经典图算法替代 GNN/DGL/PyG 等重量级框架，保证服务端零额外依赖、可独立单元测试。
