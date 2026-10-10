// AuditForwarder - 轻量级图算法实现（M4 措施4：替代 GNN 行为图谱）。
//
// 设计依据 docs/REMEDIATION_PLAN.md 第五章：
//   - 纯 C++ 实现，无外部图框架依赖；
//   - 四类图算法：度中心性异常 / Louvain 社区检测（贪心模块度）/ 三角形计数 /
//     Jaccard 边集相似度；
//   - 全部为 O(V+E) ~ O(V*E) 复杂度，满足实际规模（节点 <10^4）。

#include "auditforwarder/behavior_graph.h"

#include <algorithm>
#include <cmath>
#include <set>
#include <unordered_map>

namespace af::graph {

// ---- 图构建 ----

NodeId BehaviorGraph::add_node(NodeType type, const std::string& label) {
    // 同 label+type 已存在则返回既有 ID（线性查找，规模可控）
    for (NodeId i = 0; i < nodes_.size(); ++i) {
        if (nodes_[i].type == type && nodes_[i].label == label) return i;
    }
    NodeId id = static_cast<NodeId>(nodes_.size());
    nodes_.push_back(Node{type, label});
    adj_.emplace_back();
    return id;
}

void BehaviorGraph::add_edge(NodeId from, NodeId to, double weight) {
    if (from >= nodes_.size() || to >= nodes_.size()) return;
    // 同目标边权重累加（避免重复边膨胀）
    for (auto& e : adj_[from]) {
        if (e.to == to) { e.weight += weight; return; }
    }
    adj_[from].push_back(Edge{to, weight});
}

NodeId BehaviorGraph::find_node(NodeType type, const std::string& label) const {
    for (NodeId i = 0; i < nodes_.size(); ++i) {
        if (nodes_[i].type == type && nodes_[i].label == label) return i;
    }
    return INVALID_NODE;
}

std::size_t BehaviorGraph::edge_count() const {
    std::size_t n = 0;
    for (const auto& adj : adj_) n += adj.size();
    return n;
}

std::size_t BehaviorGraph::degree(NodeId id) const {
    if (id >= nodes_.size()) return 0;
    std::size_t deg = adj_[id].size();   // 出度
    // 入度：扫描全部邻接表
    for (const auto& adj : adj_) {
        for (const auto& e : adj) {
            if (e.to == id) ++deg;
        }
    }
    return deg;
}

// ================ 算法1：度中心性异常 ================
// 操作员节点度数 > 均值+2σ → degree_anomaly += 0.3 * 异常操作员比例
float BehaviorGraph::compute_degree_anomaly(std::vector<std::string>& notes) const {
    std::vector<NodeId> ops;
    for (NodeId i = 0; i < nodes_.size(); ++i) {
        if (nodes_[i].type == NodeType::Operator) ops.push_back(i);
    }
    if (ops.size() < 2) return 0.f;   // 单操作员无度中心性可言

    // 计算度数均值与标准差
    double sum = 0, sum2 = 0;
    std::vector<std::size_t> degs;
    degs.reserve(ops.size());
    for (auto id : ops) {
        std::size_t d = degree(id);
        degs.push_back(d);
        sum += d;
        sum2 += static_cast<double>(d) * d;
    }
    double mean = sum / ops.size();
    double var  = sum2 / ops.size() - mean * mean;
    double sigma = std::sqrt(std::max(0.0, var));
    double threshold = mean + 2.0 * sigma;

    // 异常操作员比例
    int anomaly_cnt = 0;
    for (std::size_t i = 0; i < ops.size(); ++i) {
        if (static_cast<double>(degs[i]) > threshold && sigma > 1e-6) {
            ++anomaly_cnt;
            notes.push_back("操作员 " + nodes_[ops[i]].label +
                             " 度数 " + std::to_string(degs[i]) +
                             " > 均值+2σ(" + std::to_string(static_cast<int>(threshold)) + ")");
        }
    }
    if (anomaly_cnt == 0) return 0.f;
    float ratio = static_cast<float>(anomaly_cnt) / static_cast<float>(ops.size());
    return 0.3f * ratio;
}

// ================ 算法2：Louvain 社区检测（贪心模块度最大化，简化版） ================
// 简化策略：基于共同邻居的标签传播（Label Propagation），单次迭代收敛
std::vector<u32> BehaviorGraph::detect_communities() const {
    std::size_t n = nodes_.size();
    if (n == 0) return {};
    std::vector<u32> comm(n);
    for (std::size_t i = 0; i < n; ++i) comm[i] = static_cast<u32>(i);   // 初始每节点自成一社区

    // 标签传播：每节点选取邻居中最频繁的社区标签（平手取较小 ID）
    bool changed = true;
    int iter = 0;
    while (changed && iter < 10) {   // 最多 10 轮迭代
        changed = false;
        for (NodeId v = 0; v < static_cast<NodeId>(n); ++v) {
            if (adj_[v].empty()) continue;
            std::unordered_map<u32, double> cnt;
            for (const auto& e : adj_[v]) cnt[comm[e.to]] += e.weight;
            u32 best = comm[v];
            double best_w = -1.0;
            for (const auto& kv : cnt) {
                if (kv.second > best_w || (kv.second == best_w && kv.first < best)) {
                    best_w = kv.second;
                    best = kv.first;
                }
            }
            if (best != comm[v]) { comm[v] = best; changed = true; }
        }
        ++iter;
    }
    return comm;
}

float BehaviorGraph::compute_community_anomaly(const std::vector<u32>& communities,
                                               const BehaviorGraph& baseline,
                                               std::vector<std::string>& notes) const {
    if (communities.empty()) return 0.f;
    // 统计每个社区的操作员数量
    std::unordered_map<u32, int> op_in_comm;
    for (NodeId i = 0; i < nodes_.size(); ++i) {
        if (nodes_[i].type == NodeType::Operator) op_in_comm[communities[i]]++;
    }
    // 异常社区：仅含 1~2 个操作员的孤立小社区
    int anomaly_comm = 0;
    int total_comm = 0;
    for (const auto& kv : op_in_comm) {
        ++total_comm;
        if (kv.second <= 2 && kv.second >= 1) ++anomaly_comm;
    }
    if (anomaly_comm == 0) return 0.f;

    // 与基线对比：基线图中存在的社区不在异常判定范围
    if (baseline.node_count() > 0) {
        auto base_comm = baseline.detect_communities();
        std::set<u32> base_comm_ids(base_comm.begin(), base_comm.end());
        // 简化：基线存在任一同规模社区则不视为陌生（实际工程可加图同构匹配）
        // 这里仅按社区数对比：基线社区数 >= 当前 → 不视为陌生社区爆发
        if (base_comm_ids.size() >= op_in_comm.size()) return 0.05f;   // 仅小幅计分
    }

    float ratio = static_cast<float>(anomaly_comm) / static_cast<float>(std::max(1, total_comm));
    notes.push_back("发现 " + std::to_string(anomaly_comm) + " 个孤立小社区（操作员 ≤2）");
    return 0.3f * ratio;
}

// ================ 算法3：三角形计数（操作员节点） ================
float BehaviorGraph::compute_triangle_anomaly(std::vector<std::string>& notes) const {
    std::vector<NodeId> ops;
    for (NodeId i = 0; i < nodes_.size(); ++i) {
        if (nodes_[i].type == NodeType::Operator) ops.push_back(i);
    }
    if (ops.size() < 3) return 0.f;

    // 构建邻接集合（有向 → 视作无向）
    std::vector<std::set<NodeId>> adj_set(nodes_.size());
    for (NodeId u = 0; u < nodes_.size(); ++u) {
        for (const auto& e : adj_[u]) {
            adj_set[u].insert(e.to);
            adj_set[e.to].insert(u);
        }
    }

    // 枚举操作员节点的三角形（u-v-w，u<v<w 避免重复）
    auto tri_cnt_of = [&](NodeId u) -> int {
        int cnt = 0;
        const auto& Nu = adj_set[u];
        for (auto it = Nu.begin(); it != Nu.end(); ++it) {
            NodeId v = *it;
            if (v <= u) continue;
            // 求 Nu ∩ Nv
            const auto& Nv = adj_set[v];
            for (auto it2 = Nv.begin(); it2 != Nv.end(); ++it2) {
                NodeId w = *it2;
                if (w <= v) continue;
                if (Nu.count(w)) ++cnt;
            }
        }
        return cnt;
    };

    double sum = 0, sum2 = 0;
    std::vector<int> tris;
    tris.reserve(ops.size());
    for (auto id : ops) {
        int t = tri_cnt_of(id);
        tris.push_back(t);
        sum += t;
        sum2 += static_cast<double>(t) * t;
    }
    double mean = sum / ops.size();
    double var  = sum2 / ops.size() - mean * mean;
    double sigma = std::sqrt(std::max(0.0, var));
    double threshold = mean + 2.0 * sigma;

    int anomaly_cnt = 0;
    for (std::size_t i = 0; i < ops.size(); ++i) {
        if (static_cast<double>(tris[i]) > threshold && sigma > 1e-6) {
            ++anomaly_cnt;
            notes.push_back("操作员 " + nodes_[ops[i]].label +
                             " 三角形数 " + std::to_string(tris[i]) +
                             " > 均值+2σ(" + std::to_string(static_cast<int>(threshold)) + ")");
        }
    }
    if (anomaly_cnt == 0) return 0.f;
    float ratio = static_cast<float>(anomaly_cnt) / static_cast<float>(ops.size());
    return 0.25f * ratio;
}

// ================ 算法4：Jaccard 边集相似度（与基线对比） ================
float BehaviorGraph::compute_similarity_anomaly(const BehaviorGraph& baseline,
                                                std::vector<std::string>& notes) const {
    if (baseline.node_count() == 0) return 0.f;   // 无基线不计算

    // 用 "fromLabel|toLabel" 字符串集合表示边集（基于标签，跨图可比）
    auto edge_set = [](const BehaviorGraph& g) {
        std::set<std::string> s;
        for (NodeId u = 0; u < g.nodes_.size(); ++u) {
            const std::string& from_label = g.nodes_[u].label;
            for (const auto& e : g.adj_[u]) {
                s.insert(from_label + "|" + g.nodes_[e.to].label);
            }
        }
        return s;
    };

    auto cur_edges = edge_set(*this);
    auto base_edges = edge_set(baseline);
    if (cur_edges.empty() && base_edges.empty()) return 0.f;

    // Jaccard = |A∩B| / |A∪B|
    int inter = 0;
    for (const auto& e : cur_edges) {
        if (base_edges.count(e)) ++inter;
    }
    int uni = static_cast<int>(cur_edges.size() + base_edges.size() - inter);
    float jaccard = uni > 0 ? static_cast<float>(inter) / static_cast<float>(uni) : 0.f;

    if (jaccard < 0.3f) {
        notes.push_back("与历史基线 Jaccard 相似度 " + std::to_string(jaccard) +
                         " < 0.3（协作模式显著偏离历史）");
        return 0.15f;
    }
    return 0.f;
}

// ================ 综合分析入口 ================
AnalysisResult BehaviorGraph::analyze(const BehaviorGraph& baseline) const {
    AnalysisResult r;
    r.degree_anomaly = compute_degree_anomaly(r.notes);
    auto communities = detect_communities();
    r.community_anomaly = compute_community_anomaly(communities, baseline, r.notes);
    r.triangle_anomaly = compute_triangle_anomaly(r.notes);
    r.similarity_anomaly = compute_similarity_anomaly(baseline, r.notes);
    return r;
}

}  // namespace af::graph
