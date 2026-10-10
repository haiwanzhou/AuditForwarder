#pragma once
// AuditForwarder - 轻量级图算法模块（M4 措施4：替代 GNN 行为图谱）。
//
// 设计依据 docs/REMEDIATION_PLAN.md 第五章 5.x：
//   - 纯 C++ 实现，无外部依赖（不依赖 GNN/DGL/PyG 等重量级框架）；
//   - 从聚合事件集合（AggSet）+ 行为画像（ProfileSnapshot）构建操作员-资产-操作类型
//     异构图，用经典图算法（度中心性 / Louvain 社区检测 / 三角形计数 / Jaccard 相似度）
//     替代 GNN 学习式推理，作为合谋协同检测的补充线索；
//   - 仅产出线索因子（graph_factor），上限受 graph_max_factor 约束，不直接触发 HIGH 风险；
//   - analyze() 接受历史基线图（可选），与当前行为图对比以识别陌生协作模式。
//
// 图结构（三类节点 / 单一加权有向边）：
//   NodeType::Operator  操作员节点（label = oper_id）
//   NodeType::Asset     资产节点   （label = server_id 或 res_key 折叠）
//   NodeType::OpType    操作类型节点（label = op_type）
//   Edge: (from, to, weight)  权重默认 1，表示操作员→资产 / 操作员→操作类型 关系强度

#include "auditforwarder/types.h"

#include <string>
#include <vector>

namespace af::graph {

// 节点类型
enum class NodeType : u8 {
    Operator = 0,   // 操作员
    Asset    = 1,   // 资产
    OpType   = 2    // 操作类型
};

// 节点 ID（0-based 索引，u32 足够覆盖实际规模）
using NodeId = u32;

// 边（邻接表元素）
struct Edge {
    NodeId   to     { 0 };
    double   weight { 1.0 };
};

// 图节点
struct Node {
    NodeType  type  { NodeType::Operator };
    std::string label;           // 操作员 ID / 资产标识 / 操作类型
};

// 图分析结果（各异常分量均为非负 float，最终累加为 graph_factor）
struct AnalysisResult {
    float degree_anomaly    { 0.f };   // 度中心性异常分量
    float community_anomaly { 0.f };   // 社区结构异常分量
    float triangle_anomaly  { 0.f };   // 三角形密度异常分量
    float similarity_anomaly{ 0.f };   // 与历史基线相似度异常分量
    std::vector<std::string> notes;   // 异常描述（线索说明）
};

// 行为图谱（邻接表存储，支持多类型异构图）
class BehaviorGraph {
public:
    BehaviorGraph() = default;

    // ---- 图构建 ----
    // 添加节点（返回节点 ID；同 label+type 已存在则返回既有 ID）
    NodeId add_node(NodeType type, const std::string& label);

    // 添加边（from→to，权重累加；无向场景由调用方双向加边）
    void add_edge(NodeId from, NodeId to, double weight = 1.0);

    // 按标签查找节点（不存在返回 INVALID_NODE）
    NodeId find_node(NodeType type, const std::string& label) const;

    // ---- 查询 ----
    std::size_t node_count() const { return nodes_.size(); }
    std::size_t edge_count() const;   // 有向边总数
    const Node& node(NodeId id) const { return nodes_[id]; }
    const std::vector<Edge>& neighbors(NodeId id) const { return adj_[id]; }

    // 节点度数（出度+入度）
    std::size_t degree(NodeId id) const;

    // ---- 图算法（M4 核心，纯 C++ ~200 行）----
    // 对比历史基线图分析异常（任一分量超阈值即贡献 graph_factor）
    //   baseline: 历史行为图谱（可空图，表示无基线）
    AnalysisResult analyze(const BehaviorGraph& baseline) const;

    // 无效节点 ID（查找失败）
    static constexpr NodeId INVALID_NODE = static_cast<NodeId>(-1);

private:
    // ---- 算法1：度中心性异常 ----
    // 操作员节点度数 > 均值+2σ → degree_anomaly += 0.3 * 异常操作员比例
    float compute_degree_anomaly(std::vector<std::string>& notes) const;

    // ---- 算法2：Louvain 社区检测（贪心模块度最大化，简化版）----
    // 返回每个节点的社区 ID；陌生社区（仅含 1~2 个操作员且与基线不重合）→ 异常
    std::vector<u32> detect_communities() const;
    float compute_community_anomaly(const std::vector<u32>& communities,
                                    const BehaviorGraph& baseline,
                                    std::vector<std::string>& notes) const;

    // ---- 算法3：三角形计数（操作员节点）----
    // 操作员节点三角形数 > 均值+2σ → triangle_anomaly += 0.25 * 异常比例
    float compute_triangle_anomaly(std::vector<std::string>& notes) const;

    // ---- 算法4：Jaccard 边集相似度（与基线对比）----
    // 相似度 < 0.3 → similarity_anomaly += 0.15
    float compute_similarity_anomaly(const BehaviorGraph& baseline,
                                     std::vector<std::string>& notes) const;

    std::vector<Node> nodes_;
    std::vector<std::vector<Edge>> adj_;   // 邻接表（出边）
};

}  // namespace af::graph
