#pragma once
// AuditForwarder - 操作员合谋图谱（M7）。
//
// 设计依据 docs/ROADMAP_M5_M8.md「M7：合谋图谱增强」：
//   - 节点重构：图谱节点从「主机」升级为「操作员」，operator_id 为主键；
//   - 边类型：
//       1) 同对象共现边：两操作员在时间窗（微秒）内操作同一 object；
//       2) 角色互补边：两操作员的动作命中配置的危险互补动作组合
//          （示例：一人删备份、另一人卸载磁盘）；
//   - 时间窗稠密度：窗口内操作员两两交互频次密度，作为 graph_factor 输入；
//   - 复用 M4 BehaviorGraph 的度中心性 / Louvain 社区 / 三角形计数 / Jaccard，
//     仅产出补充线索因子；
//   - 硬约束：graph_factor ≤ max_factor（默认 25），不直接触发 HIGH 风险。

#include "auditforwarder/behavior_graph.h"

#include <cstddef>
#include <string>
#include <vector>

namespace af::graph {

// 图谱输入事件（由合谋引擎的 CleanEvent 转换而来）
struct OperatorEvent {
    std::string oper_id;         // 操作员唯一 ID（图谱主键）
    u64         ts_us { 0 };     // 操作时间（微秒）
    std::string object_key;      // 被操作对象标识（res_key / ocsf.object）
    std::string action;          // 操作动作（op_type / ocsf.activity_name）
    std::string target_system;   // 目标系统 / 主机标识（target_system / server_id）
};

// 危险互补动作组合（配置项 complementary_action_pairs）
struct ComplementPair {
    std::vector<std::string> first;    // 动作关键词（任一命中，大小写不敏感子串）
    std::vector<std::string> second;   // 与 first 构成危险组合的另一组动作
    std::string label;                 // 组合名称（证据链展示用）
};

struct OperatorGraphConfig {
    u64   window_us           { 15ull * 60ull * 1000000ull };   // 时间窗（微秒，默认 15 分钟）
    float density_threshold   { 0.3f };                          // 稠密度阈值
    int   max_factor          { 25 };                            // graph_factor 上限
    std::vector<ComplementPair> complement_pairs;                // 角色互补动作组合
};

// 操作员之间的边（无向，op_a 为字典序较小者）
struct OperatorEdge {
    std::string op_a;
    std::string op_b;
    std::size_t cooccur { 0 };               // 同对象共现次数
    std::size_t complement { 0 };            // 角色互补命中次数
    std::vector<std::string> objects;        // 共现对象（证据）
    std::vector<std::string> labels;         // 命中的互补组合名称（证据）
};

struct OperatorGraphAnalysis {
    std::size_t operator_count { 0 };
    std::size_t edge_count { 0 };
    std::size_t cooccur_edges { 0 };         // 含同对象共现的边数
    std::size_t complement_edges { 0 };      // 含角色互补的边数
    double      density { 0.0 };             // 时间窗内两两交互频次稠密度（0~1）
    float       degree_anomaly { 0.f };      // 以下四项复用 M4 图算法
    float       community_anomaly { 0.f };
    float       triangle_anomaly { 0.f };
    float       similarity_anomaly { 0.f };
    int         graph_factor { 0 };          // 最终线索因子（≤ max_factor）
    std::vector<OperatorEdge> edges;         // 边明细（证据链）
    std::vector<std::string> notes;          // 线索说明
};

// 构建操作员图谱并分析异常：
//   events    : 同一聚合窗口内的事件（内部按微秒升序稳定排序）
//   cfg       : 时间窗 / 稠密度阈值 / 互补动作组合 / 因子上限
//   baseline  : 可选历史基线图（用于 Jaccard 相似度与社区对比，可为空）
OperatorGraphAnalysis analyze_operator_graph(const std::vector<OperatorEvent>& events,
                                             const OperatorGraphConfig& cfg,
                                             const BehaviorGraph* baseline = nullptr);

}  // namespace af::graph
