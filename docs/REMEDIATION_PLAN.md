# AuditForwarder 补救方案设计

> 基于《可行性研究报告核验报告》识别的 4 条补救措施，本文档为每条措施提供完整的工程设计方案，包括当前状态分析、目标架构、具体代码变更点、验证标准和实施顺序。

---

## 一、核验偏差与补救措施总览

| 编号 | 偏差项 | 差异程度 | 对应措施 | 优先级 |
|------|--------|----------|----------|--------|
| M1 | 分层 Merkle 树 → 实际为批量哈希链 | 轻微 | 措施1：重构 chain.cpp 实现跨批次分层 Merkle 树 | P2 |
| M2 | 安全产品适配器缺失（报告要求 ≥3 类，当前 0 类） | 重大 | 措施2：补充 Syslog/API 适配器 | P1 |
| M3 | LSTM 序列检测缺失 | 重大 | 措施3：集成 ONNX Runtime 加载预训练模型 | P1 |
| M4 | GNN 行为图谱缺失 | 重大 | 措施4：补充轻量级图算法模块 | P1 |

**实施顺序**：M1（独立、无依赖）→ M2（采集层、独立）→ M3（检测层、依赖采集数据）→ M4（检测层、依赖 M3 特征工程）

---

## 二、措施1：重构 chain.cpp 实现跨批次分层 Merkle 树

### 2.1 当前状态

- [chain.cpp](file:///c:/Users/30952/Desktop/AuditForwarder_ovo1102/shared/src/crypto/chain.cpp) 第 88-95 行：每个批次内部已构建 `MerkleTree`（叶子 = 事件哈希），生成 `b.merkle_root`
- 批次之间仅通过 `last_event_hash_` 链式连接（第 69 行 `ev.prev_hash = last_event_hash_`），**无跨批次聚合根**
- [chain.h](file:///c:/Users/30952/Desktop/AuditForwarder_ovo1102/include/auditforwarder/chain.h) 无 SuperBatch / 聚合根相关接口

**结论**：批内 Merkle 树已具备，缺失的是跨批次的分层聚合结构。

### 2.2 目标架构

```
事件层:   ev0  ev1  ev2 ... evN     ← 单个事件哈希
           \    /\    /\    /
批次层:     Batch-A  Batch-B  ...    ← 每批 N 个事件 → MerkleTree → batch_root
              \      |      /
超级批次层:     SuperBatch-S1         ← 每 K 个 batch_root → MerkleTree → super_root
                   |
全局根层:       global_anchor         ← 最新 super_root 链式锚定
```

- **超级批次（SuperBatch）**：每 K 个 EventBatch 的 merkle_root 作为叶子，构建上层 Merkle 树，生成 `super_root`
- **全局锚定**：最新 super_root 通过 `prev_super_root` 链式连接，形成可验证的时序锚链
- **向后兼容**：单批次验证（`verify_batch`）不受影响，分层验证为新增能力

### 2.3 具体设计

#### 2.3.1 数据结构

```cpp
// chain.h 新增
struct SuperBatch {
    std::string id;                          // 超级批次 ID
    std::vector<std::string> batch_ids;      // 包含的批次 ID 列表
    std::vector<std::string> batch_roots;    // 各批次 merkle_root 列表
    std::string super_root;                  // 超级批次 Merkle 根
    std::string prev_super_root;             // 前一个超级批次根（链式锚定）
    u64 created_at_us;                       // 创建时间（微秒）
    std::string signature;                  // 签名
};
```

#### 2.3.2 Chain 类变更

```cpp
// chain.h 新增成员与接口
class Chain {
public:
    // ... 现有接口不变 ...

    // 新增：设置超级批次容量（多少个 EventBatch 组成一个 SuperBatch）
    void set_super_batch_size(std::size_t k);  // 默认 k=8

    // 新增：获取当前超级批次根
    std::string last_super_root() const;

    // 新增：验证超级批次签名与 Merkle 结构
    static bool verify_super_batch(const SuperBatch& sb, const std::string& hmac_key);
    static bool verify_super_batch_with_key(const SuperBatch& sb, const crypto::KeyPair& kp);

    // 新增：读取最近 N 个超级批次
    Result<std::vector<SuperBatch>> recent_super_batches(std::size_t n = 10) const;

private:
    // 新增
    void persist_super_batch(const SuperBatch& sb);
    SuperBatch build_super_batch(std::vector<std::string>&& batch_ids,
                                  std::vector<std::string>&& batch_roots);

    std::size_t super_batch_k_ { 8 };        // 每 K 个批次组成一个超级批次
    std::vector<std::string> pending_batch_ids_;      // 待聚合的批次 ID
    std::vector<std::string> pending_batch_roots_;    // 待聚合的批次 root
    std::string last_super_root_;           // 最近超级批次根（链式锚定）
};
```

#### 2.3.3 关键实现逻辑

- `flush()` 成功构建 EventBatch 后，将 `b.id` 和 `b.merkle_root` 追加到 `pending_batch_ids_` / `pending_batch_roots_`
- 当 `pending_batch_roots_.size() >= super_batch_k_` 时，触发 `build_super_batch()`
- `build_super_batch()` 将 batch_roots 转为 `ByteBuffer` 叶子 → 复用 `crypto::MerkleTree` → 生成 `super_root`
- 签名 payload = `sb.id + "|" + created_at_us + "|" + sb.super_root + "|" + sb.prev_super_root`（微秒粒度，与现有批次签名一致）
- 持久化到 `data_dir/super_batches/<sb_id>.json`

#### 2.3.4 代码变更点

| 文件 | 变更类型 | 内容 |
|------|----------|------|
| [chain.h](file:///c:/Users/30952/Desktop/AuditForwarder_ovo1102/include/auditforwarder/chain.h) | 新增 | SuperBatch 结构体；Chain 类新增 4 个公开方法 + 3 个私有方法 + 4 个成员变量 |
| [chain.cpp](file:///c:/Users/30952/Desktop/AuditForwarder_ovo1102/shared/src/crypto/chain.cpp) | 新增 | build_super_batch / persist_super_batch / verify_super_batch 实现；flush() 尾部追加聚合触发 |
| [agent.cpp](file:///c:/Users/30952/Desktop/AuditForwarder_ovo1102/client/src/core/agent.cpp) | 修改 | 启动时调用 `chain_.set_super_batch_size(k)`（从配置读取） |
| 测试 | 新增 | tests/unit/test_super_batch.cpp：验证超级批次构建、Merkle proof、签名验签、链式锚定连续性 |

### 2.4 验证标准

1. 构造 8 个批次 × 256 事件，调用 `flush()` 后自动生成 1 个 SuperBatch
2. `verify_super_batch()` 对正确签名返回 true，篡改任一 batch_root 后返回 false
3. `prev_super_root` 链式连续，断裂时验证失败
4. 现有 175 项单元测试全部通过（无回归）
5. `recent_super_batches(5)` 正确返回最近 5 个超级批次的元数据

---

## 三、措施2：补充 Syslog/API 适配器

### 3.1 当前状态

- [collector_base.h](file:///c:/Users/30952/Desktop/AuditForwarder_ovo1102/include/auditforwarder/collector_base.h) 定义了 `FileWatchSource` 虚拟接口（open/close/poll）和 `make_file_watch_source()` 工厂
- 现有采集器仅覆盖：Linux auditd 日志（collectors_linux.cpp）、Windows 事件日志（collectors_win.cpp）、文件监控
- **无 Syslog 监听、无数据库审计 API 轮询、无堡垒机 API 对接**
- 报告要求 ≥3 类安全产品适配器，当前 0 类

### 3.2 目标架构

```
安全产品日志源
├── 1. Syslog 适配器      ← UDP 514 监听，解析 RFC 3164/5424
├── 2. 数据库审计适配器    ← 轮询 MySQL/PostgreSQL audit plugin API
└── 3. 堡垒机 API 适配器  ← REST API 拉取会话/命令日志
         ↓
    统一 AuditEvent 格式
         ↓
    Chain.submit() → Merkle 树 → 签名 → 传输
```

### 3.3 具体设计

#### 3.3.1 统一适配器接口

复用 `FileWatchSource` 模式，新建 `SecurityAdapter` 基类：

```cpp
// include/auditforwarder/security_adapter.h（新建）
class SecurityAdapter {
public:
    virtual ~SecurityAdapter() = default;
    virtual Result<void> open(const std::string& config_json) = 0;
    virtual void         close() = 0;
    // 轮询：返回拉取到的 AuditEvent 数量，通过回调逐条产出
    virtual int poll(std::function<void(const AuditEvent&)> emit) = 0;
    virtual std::string name() const = 0;       // 适配器名称
    virtual std::string source_type() const = 0; // "syslog" | "db_audit" | "bastion"
};
```

#### 3.3.2 三个适配器实现

**适配器1：SyslogAdapter**
- 文件：`client/src/collector/adapters/syslog_adapter.cpp/.h`
- 监听 UDP 514（可配置端口），解析 RFC 3164（传统）和 RFC 5424（结构化）
- syslog 设施映射：auth(4) → 事件类型 AUTH；authpriv(10) → AUTH_PRIV；audit(21) → AUDIT
- 每条 syslog 消息 → `AuditEvent{source="syslog", type=<映射>, raw=<原始文本>, ...}`

**适配器2：DatabaseAuditAdapter**
- 文件：`client/src/collector/adapters/db_audit_adapter.cpp/.h`
- 支持两种模式：
  - **MySQL audit plugin**：轮询 `mysql.audit_log` 表
  - **PostgreSQL pgaudit**：轮询 `pgaudit.log` 相关视图
- 通过 libpq / libmysqlclient 连接（可选依赖，CMake 条件编译）
- 每条审计记录 → `AuditEvent{source="db_audit", type=<DDL/DML/DDL>|...}`

**适配器3：BastionAdapter（堡垒机）**
- 文件：`client/src/collector/adapters/bastion_adapter.cpp/.h`
- 通过 HTTPS REST API 拉取堡垒机会话日志和命令日志
- 支持的 API 模式：分页拉取 + 游标（last_seen_id）增量同步
- 每条命令日志 → `AuditEvent{source="bastion", operator=<用户>, cmd=<命令>, asset=<目标主机>}`

#### 3.3.3 代码变更点

| 文件 | 变更类型 | 内容 |
|------|----------|------|
| `include/auditforwarder/security_adapter.h` | 新建 | SecurityAdapter 基类接口 |
| `client/src/collector/adapters/syslog_adapter.cpp/.h` | 新建 | UDP 514 监听 + RFC 3164/5424 解析 |
| `client/src/collector/adapters/db_audit_adapter.cpp/.h` | 新建 | MySQL/PostgreSQL 审计日志轮询 |
| `client/src/collector/adapters/bastion_adapter.cpp/.h` | 新建 | 堡垒机 REST API 拉取 |
| [agent.cpp](file:///c:/Users/30952/Desktop/AuditForwarder_ovo1102/client/src/core/agent.cpp) | 修改 | 从配置读取适配器列表，注册到采集流水线 |
| [CMakeLists.txt](file:///c:/Users/30952/Desktop/AuditForwarder_ovo1102/CMakeLists.txt) | 修改 | AF_CORE_SOURCES 追加适配器源码；可选 find_package(PostgreSQL)/find_package(MySQL) |
| 配置 | 新增 | config.yaml 中 `adapters:` 段，配置各适配器参数 |
| 测试 | 新增 | test_syslog_parse / test_bastion_api / test_db_audit |

### 3.4 验证标准

1. 用 `logger`（Linux 工具）发送测试 syslog → SyslogAdapter 接收到事件并转为 AuditEvent
2. 模拟堡垒机 API 返回固定 JSON → BastionAdapter 正确解析、增量游标推进
3. 3 个适配器同时运行无资源竞争
4. 适配器产出的事件经 Chain 签名后可在服务端验签通过
5. 安全产品类型计数 ≥ 3（满足报告要求）

---

## 四、措施3：集成 ONNX Runtime 加载预训练模型

### 4.1 当前状态

- [collusion.cpp](file:///c:/Users/30952/Desktop/AuditForwarder_ovo1102/server/src/collusion/collusion.cpp) 第 695-728 行的行为画像引擎是纯规则驱动（pair_counts、cross_domain、forged_ticket），**无任何 ML 模型推理**
- 项目中无 ONNX Runtime 依赖，无 LSTM/孤立森林模型文件
- 报告要求 LSTM 时序异常检测和孤立森林异常检测

### 4.2 目标架构

```
操作员行为日志流
      ↓
  特征工程层（C++实现）
  ├── 时序特征：操作间隔、操作序列熵、突发频率
  ├── 统计特征：操作类型分布、资产覆盖率、非工时占比
  └── 图结构特征：协作图度数、社区归属（供 M4 使用）
      ↓
  ONNX 推理层（C++ 调用 ONNX Runtime）
  ├── isolation_forest.onnx → 异常分数 0~1
  └── lstm_seq.onnx → 序列异常分数 0~1
      ↓
  分数融合 → 整合到风险评分
  ml_score = max(if_score, lstm_score)
  if ml_score > 0.7: total_score += ml_factor (上限 30)
```

### 4.3 具体设计

#### 4.3.1 ONNX 推理封装

```cpp
// include/auditforwarder/onnx_inference.h（新建）
#ifdef AF_HAVE_ONNXRUNTIME
class OnnxModel {
public:
    explicit OnnxModel(const std::string& model_path);
    ~OnnxModel();

    bool is_loaded() const;
    // 输入：展平的 float 特征向量；输出：模型推理结果
    std::vector<float> infer(const std::vector<float>& features);
    std::string input_name() const;
    std::string output_name() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
#endif
```

#### 4.3.2 特征工程

```cpp
// shared/src/ml/feature_extractor.cpp/.h（新建）
struct BehaviorFeatures {
    float op_interval_mean;       // 操作间隔均值（秒）
    float op_interval_std;        // 操作间隔标准差
    float op_type_entropy;       // 操作类型信息熵
    float burst_ratio;           // 突发操作占比（>10 ops/min）
    float cross_asset_ratio;     // 跨资产操作比例
    float off_hours_ratio;       // 非工时操作比例
    float cmd_repeat_ratio;      // 命令重复率
    // ... 共 ~20 维特征
    std::vector<float> to_vector() const;
};

class FeatureExtractor {
public:
    BehaviorFeatures extract(const std::vector<AuditEvent>& operator_events,
                             const ProfileSnapshot& profile);
};
```

#### 4.3.3 预训练模型

- 预训练方式：在 Python 中用 scikit-learn（孤立森林）和 PyTorch（LSTM）训练模型
- 导出为 ONNX 格式，放置在 `models/` 目录
- 模型文件：
  - `models/isolation_forest.onnx`：输入 [1, 20] float32，输出 [1] float32（异常分数）
  - `models/lstm_seq.onnx`：输入 [1, seq_len, feat_dim] float32，输出 [1] float32（异常分数）
- C++ 端加载模型时进行 ONNX Runtime 环境初始化，模型路径从配置读取

#### 4.3.4 collusion.cpp 集成

在行为画像引擎（collusion.cpp 第 695 行区域）中新增 ML 推理段：

```cpp
// ---- ML 异常检测引擎（ONNX 推理，因子上限 ml_max_factor）----
if (cfg.ml_enabled && onnx_if_ && onnx_if_->is_loaded()) {
    auto feats = feature_extractor_.extract(set_events, profile);
    auto if_score = onnx_if_->infer(feats.to_vector())[0];
    if (if_score > cfg.ml_high_threshold) {
        res.ml_factor += std::min(static_cast<int>(if_score * 30), cfg.ml_max_factor);
        res.ml_notes.push_back("孤立森林异常分数=" + std::to_string(if_score));
    }
}
// LSTM 序列检测同理（可选，独立模型）
```

#### 4.3.5 代码变更点

| 文件 | 变更类型 | 内容 |
|------|----------|------|
| `include/auditforwarder/onnx_inference.h` | 新建 | OnnxModel 封装类 |
| `shared/src/ml/onnx_inference.cpp` | 新建 | ONNX Runtime C API 封装实现 |
| `shared/src/ml/feature_extractor.cpp/.h` | 新建 | BehaviorFeatures 结构 + FeatureExtractor 类 |
| `models/isolation_forest.onnx` | 新建 | 预训练孤立森林模型（Python 导出） |
| `models/lstm_seq.onnx` | 新建 | 预训练 LSTM 序列模型（Python 导出） |
| [collusion.cpp](file:///c:/Users/30952/Desktop/AuditForwarder_ovo1102/server/src/collusion/collusion.cpp) | 修改 | 新增 ml_factor / ml_notes 字段；行为画像段追加 ONNX 推理调用 |
| [collusion.h](file:///c:/Users/30952/Desktop/AuditForwarder_ovo1102/include/auditforwarder/collusion.h) | 修改 | Engine 类新增 OnnxModel 成员；Config 新增 ml_enabled / ml_high_threshold / ml_max_factor |
| [CMakeLists.txt](file:///c:/Users/30952/Desktop/AuditForwarder_ovo1102/CMakeLists.txt) | 修改 | find_package(ONNXRuntime)；条件编译 AF_HAVE_ONNXRUNTIME；AF_CORE_SOURCES 追加 ml/ 源码 |
| 测试 | 新增 | test_feature_extractor / test_onnx_inference（模型未加载时 graceful 降级） |

### 4.4 验证标准

1. ONNX 模型文件加载成功，`is_loaded()` 返回 true
2. 特征提取器对 100 条操作日志产出 20 维特征向量
3. 注入异常操作模式（高频突发 + 跨域）后，`if_score > 0.7`
4. 模型文件缺失时 graceful 降级：不崩溃、ml_factor=0、日志告警
5. 现有 175 项测试无回归

---

## 五、措施4：补充轻量级图算法模块替代 GNN

### 5.1 当前状态

- collusion.cpp 的行为画像仅检查 pair_counts（两两协作次数）和 operator_assets（操作员-资产映射），**无图结构建模**
- 报告要求 GNN 行为图谱（将操作员和资产建模为图节点，用 GNN 学习异常子图模式）
- 完整 GNN 实现复杂度过高（需 PyTorch Geometric / DGL 训练 + ONNX 导出），采用**轻量级图算法**替代方案

### 5.2 目标架构

```
操作员-资产-操作 三元组日志
      ↓
  行为图构建层
  ├── 节点：operator / asset / op_type
  ├── 边：operator --performs--> op_type --on--> asset
  └── 边权重：频次
      ↓
  图分析层（纯 C++ 无外部依赖）
  ├── 度中心性异常：操作员节点度数偏离均值 >2σ
  ├── 社区检测（Louvain 算法）：陌生社区跨域操作
  ├── 三角形计数：异常密集协作三角
  └── 图相似度：与历史行为图的图编辑距离
      ↓
  图异常分数 → 整合到风险评分 graph_factor
```

### 5.3 具体设计

#### 5.3.1 行为图数据结构

```cpp
// include/auditforwarder/behavior_graph.h（新建）
class BehaviorGraph {
public:
    using NodeId = u32;
    enum class NodeType { Operator, Asset, OpType };

    NodeId add_node(NodeType type, const std::string& label);
    void add_edge(NodeId from, NodeId to, u64 weight = 1);

    // 图分析接口
    struct AnalysisResult {
        float degree_anomaly;      // 度中心性异常分数
        float community_anomaly;   // 社区归属异常分数
        float triangle_anomaly;    // 三角形密度异常分数
        float similarity_anomaly;  // 与历史图的相似度异常分数
        std::vector<std::string> notes;
    };
    AnalysisResult analyze(const BehaviorGraph& historical_baseline) const;

private:
    struct Node { NodeType type; std::string label; };
    struct Edge { NodeId to; u64 weight; };
    std::vector<Node> nodes_;
    std::vector<std::vector<Edge>> adj_;  // 邻接表
};
```

#### 5.3.2 图算法实现

- **度中心性异常**：计算所有操作员节点的度数，若某操作员度数 > 均值 + 2×标准差，则 degree_anomaly += 0.3
- **Louvain 社区检测**：实现模块度最大化的贪心算法（约 200 行 C++），操作员落入非日常社区则 community_anomaly += 0.3
- **三角形计数**：对操作员节点做三角形枚举，异常密集三角（3 人互相协作且历史无记录）则 triangle_anomaly += 0.25
- **图相似度**：与历史基线图做 Jaccard 边集相似度，similarity < 0.3 则 similarity_anomaly += 0.15

#### 5.3.3 collusion.cpp 集成

在行为画像引擎中新增图分析段（与 ML 推理并列）：

```cpp
// ---- 图行为分析引擎（轻量级图算法，因子上限 graph_max_factor）----
if (cfg.graph_enabled) {
    auto bg = build_behavior_graph(set_events);
    auto result = bg.analyze(*historical_baseline_);
    float graph_score = result.degree_anomaly + result.community_anomaly
                       + result.triangle_anomaly + result.similarity_anomaly;
    if (graph_score > cfg.graph_threshold) {
        res.graph_factor += std::min(static_cast<int>(graph_score * 25), cfg.graph_max_factor);
        res.graph_notes = std::move(result.notes);
    }
}
```

#### 5.3.4 代码变更点

| 文件 | 变更类型 | 内容 |
|------|----------|------|
| `include/auditforwarder/behavior_graph.h` | 新建 | BehaviorGraph 类 + AnalysisResult 结构 |
| `shared/src/graph/behavior_graph.cpp` | 新建 | 图构建 + 度中心性 + Louvain 社区检测 + 三角计数 + Jaccard 相似度 |
| [collusion.cpp](file:///c:/Users/30952/Desktop/AuditForwarder_ovo1102/server/src/collusion/collusion.cpp) | 修改 | 新增 graph_factor / graph_notes；行为画像段追加图分析调用；历史基线图加载 |
| [collusion.h](file:///c:/Users/30952/Desktop/AuditForwarder_ovo1102/include/auditforwarder/collusion.h) | 修改 | Engine 类新增 BehaviorGraph 基线成员；Config 新增 graph_enabled / graph_threshold / graph_max_factor |
| [CMakeLists.txt](file:///c:/Users/30952/Desktop/AuditForwarder_ovo1102/CMakeLists.txt) | 修改 | AF_CORE_SOURCES 追加 graph/behavior_graph.cpp |
| 测试 | 新增 | test_behavior_graph：图构建、Louvain 社区、三角形计数、相似度计算 |

### 5.4 验证标准

1. 3 个操作员 × 5 个资产的日志构建行为图后，节点数=8、边数=15
2. 注入异常三角（3 人互操作且历史无记录）后 triangle_anomaly > 0.2
3. Louvain 社区检测在已知社区结构上正确分区（与人工标注一致）
4. 历史基线图缺失时 graceful 降级
5. graph_factor 不超过 graph_max_factor 上限

---

## 六、实施顺序与依赖关系

```
Phase 1 (P1-独立):  M1 分层 Merkle 树重构
                     ↓ 无阻塞，可立即开始
                     ↓
Phase 2 (P1-独立):  M2 Syslog/API 适配器
                     ↓ 与 M1 可并行
                     ↓
Phase 3 (P1-依赖):  M3 ONNX Runtime 集成
                     ↑ 依赖 M2 的适配器数据（用于特征工程输入）
                     ↓
Phase 4 (P1-依赖):  M4 轻量级图算法
                     ↑ 依赖 M3 的特征工程（图结构特征复用）
```

| 阶段 | 措施 | 前置依赖 | 预计变更文件数 | 新增代码行 |
|------|------|----------|----------------|------------|
| Phase 1 | M1 分层 Merkle 树 | 无 | 4 | ~300 |
| Phase 2 | M2 安全产品适配器 | 无 | 8 | ~800 |
| Phase 3 | M3 ONNX Runtime | M2 适配器数据 | 9 | ~600 |
| Phase 4 | M4 轻量级图算法 | M3 特征工程 | 6 | ~500 |

---

## 七、风险与缓解

| 风险 | 影响 | 缓解措施 |
|------|------|----------|
| ONNX Runtime 在 MSYS2 环境编译困难 | M3 阻塞 | 预编译 ONNX Runtime 二进制放入 third_party/；CMake 条件编译，缺失时 graceful 降级 |
| 适配器增加客户端资源消耗 | M2 性能 | 适配器配置为可选启用；默认关闭，按需开启 |
| 分层 Merkle 树向后不兼容 | M1 回归 | 新增 SuperBatch 为可选层，不影响现有 EventBatch 验证路径 |
| 图算法精度不如 GNN | M4 效果 | 文档标注"轻量级替代"；保留 ONNX 模型扩展点，后续可替换为 GNN-ONNX |
| 预训练模型与实际数据分布不匹配 | M3 误报 | 模型仅提供线索因子（上限 30），不直接触发 HIGH 风险（受硬约束钳制） |

---

## 八、交付物清单

1. `docs/REMEDIATION_PLAN.md` — 本文档（补救方案设计）
2. M1：chain.h/chain.cpp 超级批次实现 + 单元测试
3. M2：3 个安全产品适配器 + agent.cpp 集成 + 配置模板
4. M3：ONNX 推理封装 + 特征工程 + 预训练 ONNX 模型 + collusion 集成
5. M4：行为图模块 + Louvain/三角/相似度算法 + collusion 集成
6. 更新后的 `docs/ARCHITECTURE.md`（补充新模块架构说明）
7. 完整回归测试通过（175 + 新增测试项）
