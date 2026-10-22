// AuditForwarder - 操作员合谋图谱实现（M7）。
//
// 两类边 + 时间窗稠密度，异常分量复用 M4 纯 C++ 图算法，最终收敛为 graph_factor。
// 全部为纯逻辑实现（无 IO），便于单元测试。

#include "auditforwarder/operator_graph.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <map>
#include <set>
#include <sstream>

namespace af::graph {

namespace {

constexpr std::size_t kMaxGraphEvents = 512;   // 单次分析的输入规模上限（保护 O(n²) 邻接枚举）

std::string lower_copy(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

// 关键词任一命中（大小写不敏感子串）
bool keyword_hit(const std::vector<std::string>& keywords, const std::string& lowered_text) {
    for (const auto& k : keywords) {
        if (k.empty()) continue;
        if (lowered_text.find(lower_copy(k)) != std::string::npos) return true;
    }
    return false;
}

std::string pair_key(const std::string& a, const std::string& b) {
    return (a < b) ? (a + "|" + b) : (b + "|" + a);
}

// 互补组合的上下文判定：优先比对目标系统，其次比对被操作对象
bool same_context(const OperatorEvent& a, const OperatorEvent& b) {
    if (!a.target_system.empty() && !b.target_system.empty()) {
        return lower_copy(a.target_system) == lower_copy(b.target_system);
    }
    if (!a.object_key.empty() && !b.object_key.empty()) return a.object_key == b.object_key;
    return false;
}

struct EdgeAcc {
    std::size_t cooccur { 0 };
    std::size_t complement { 0 };
    std::set<std::string> objects;
    std::set<std::string> labels;
};

struct Interaction {
    u64         ts_us { 0 };
    std::string key;      // 操作员对键
    std::string op_a;
    std::string op_b;
};

}  // namespace

OperatorGraphAnalysis analyze_operator_graph(const std::vector<OperatorEvent>& events,
                                             const OperatorGraphConfig& cfg,
                                             const BehaviorGraph* baseline) {
    OperatorGraphAnalysis r;

    // ---- 1. 输入整理：过滤空操作员，按微秒升序稳定排序 ----
    std::vector<OperatorEvent> evs;
    evs.reserve(events.size());
    for (const auto& e : events) {
        if (e.oper_id.empty()) continue;
        evs.push_back(e);
    }
    std::stable_sort(evs.begin(), evs.end(),
                     [](const OperatorEvent& a, const OperatorEvent& b) { return a.ts_us < b.ts_us; });
    if (evs.size() > kMaxGraphEvents) evs.resize(kMaxGraphEvents);
    if (evs.size() < 2) {
        r.operator_count = evs.size();
        if (!evs.empty()) r.notes.push_back("操作员图谱：仅 1 个操作员节点，无可分析协作边");
        return r;
    }
    std::set<std::string> ops_seen;
    for (const auto& e : evs) ops_seen.insert(e.oper_id);
    r.operator_count = ops_seen.size();

    // ---- 2. 同对象共现边：同一 object 且时间差 ≤ 窗口 ----
    std::map<std::string, EdgeAcc> edge_map;
    std::vector<Interaction> interactions;
    std::map<std::string, std::vector<std::size_t>> by_object;
    for (std::size_t i = 0; i < evs.size(); ++i) {
        if (!evs[i].object_key.empty()) by_object[evs[i].object_key].push_back(i);
    }
    for (const auto& kv : by_object) {
        const auto& idxs = kv.second;
        for (std::size_t a = 0; a < idxs.size(); ++a) {
            for (std::size_t b = a + 1; b < idxs.size(); ++b) {
                const auto& ea = evs[idxs[a]];
                const auto& eb = evs[idxs[b]];
                if (ea.oper_id == eb.oper_id) continue;
                if (eb.ts_us < ea.ts_us || eb.ts_us - ea.ts_us > cfg.window_us) continue;
                auto& acc = edge_map[pair_key(ea.oper_id, eb.oper_id)];
                ++acc.cooccur;
                acc.objects.insert(kv.first);
                interactions.push_back({ eb.ts_us, pair_key(ea.oper_id, eb.oper_id),
                                         ea.oper_id, eb.oper_id });
            }
        }
    }

    // ---- 3. 角色互补边：不同操作员在时间窗内命中危险互补动作组合 ----
    for (std::size_t i = 0; i < evs.size(); ++i) {
        const std::string text_i = lower_copy(evs[i].action + " " + evs[i].object_key);
        for (std::size_t j = i + 1; j < evs.size(); ++j) {
            if (evs[j].ts_us < evs[i].ts_us) continue;
            if (evs[j].ts_us - evs[i].ts_us > cfg.window_us) break;
            if (evs[i].oper_id == evs[j].oper_id) continue;
            if (!same_context(evs[i], evs[j])) continue;
            const std::string text_j = lower_copy(evs[j].action + " " + evs[j].object_key);
            for (const auto& cp : cfg.complement_pairs) {
                if (cp.first.empty() || cp.second.empty()) continue;
                const bool forward = keyword_hit(cp.first, text_i) && keyword_hit(cp.second, text_j);
                const bool backward = keyword_hit(cp.second, text_i) && keyword_hit(cp.first, text_j);
                if (!forward && !backward) continue;
                auto& acc = edge_map[pair_key(evs[i].oper_id, evs[j].oper_id)];
                ++acc.complement;
                acc.labels.insert(cp.label.empty() ? "complement" : cp.label);
                interactions.push_back({ evs[j].ts_us, pair_key(evs[i].oper_id, evs[j].oper_id),
                                         evs[i].oper_id, evs[j].oper_id });
            }
        }
    }

    // ---- 4. 无协作/互补边：不产生图线索（避免孤立节点被社区算法误判为异常）----
    if (edge_map.empty()) {
        std::ostringstream none;
        none << "操作员图谱：节点=" << r.operator_count << " 边=0，无同对象共现/角色互补边";
        r.notes.push_back(none.str());
        return r;
    }

    // ---- 5. 时间窗稠密度：窗口内不同操作员对 / 理论两两组合数 的最大值 ----
    std::sort(interactions.begin(), interactions.end(),
              [](const Interaction& a, const Interaction& b) { return a.ts_us < b.ts_us; });
    std::map<std::string, int> pair_in_window;   // 操作员对 -> 交互频次
    std::map<std::string, int> op_in_window;     // 窗口内操作员 -> 出现次数
    std::size_t left = 0;
    for (std::size_t right = 0; right < interactions.size(); ++right) {
        const auto& cur = interactions[right];
        ++pair_in_window[cur.key];
        ++op_in_window[cur.op_a];
        ++op_in_window[cur.op_b];
        while (cur.ts_us - interactions[left].ts_us > cfg.window_us) {
            const auto& old = interactions[left];
            auto pit = pair_in_window.find(old.key);
            if (pit != pair_in_window.end() && --pit->second <= 0) pair_in_window.erase(pit);
            auto ait = op_in_window.find(old.op_a);
            if (ait != op_in_window.end() && --ait->second <= 0) op_in_window.erase(ait);
            auto bit = op_in_window.find(old.op_b);
            if (bit != op_in_window.end() && --bit->second <= 0) op_in_window.erase(bit);
            ++left;
        }
        const double n = static_cast<double>(op_in_window.size());
        if (n >= 2.0) {
            const double denom = n * (n - 1.0) / 2.0;
            const double d = static_cast<double>(pair_in_window.size()) / denom;
            if (d > r.density) r.density = d;
        }
    }

    // ---- 6. 构建操作员图（复用 M4 算法：度中心性 / 社区 / 三角形 / Jaccard）----
    BehaviorGraph g;
    std::map<std::string, NodeId> ids;
    for (const auto& e : evs) {
        if (ids.find(e.oper_id) == ids.end()) {
            ids[e.oper_id] = g.add_node(NodeType::Operator, e.oper_id);
        }
    }

    for (const auto& kv : edge_map) {
        const auto& acc = kv.second;
        const auto pos = kv.first.find('|');
        const std::string a = kv.first.substr(0, pos);
        const std::string b = kv.first.substr(pos + 1);
        OperatorEdge edge;
        edge.op_a = a;
        edge.op_b = b;
        edge.cooccur = acc.cooccur;
        edge.complement = acc.complement;
        edge.objects.assign(acc.objects.begin(), acc.objects.end());
        edge.labels.assign(acc.labels.begin(), acc.labels.end());
        if (edge.cooccur > 0) ++r.cooccur_edges;
        if (edge.complement > 0) ++r.complement_edges;
        r.edges.push_back(std::move(edge));

        const double w = static_cast<double>(acc.cooccur + acc.complement);
        g.add_edge(ids[a], ids[b], w);
        g.add_edge(ids[b], ids[a], w);
    }
    std::sort(r.edges.begin(), r.edges.end(), [](const OperatorEdge& x, const OperatorEdge& y) {
        const std::size_t sx = x.cooccur + x.complement;
        const std::size_t sy = y.cooccur + y.complement;
        if (sx != sy) return sx > sy;
        return x.op_a < y.op_a;
    });
    r.edge_count = edge_map.size();

    BehaviorGraph empty_baseline;
    const BehaviorGraph& base = baseline ? *baseline : empty_baseline;
    const auto m4 = g.analyze(base);
    r.degree_anomaly = m4.degree_anomaly;
    r.community_anomaly = m4.community_anomaly;
    r.triangle_anomaly = m4.triangle_anomaly;
    r.similarity_anomaly = m4.similarity_anomaly;

    // ---- 7. 评分：M4 异常分量 + 稠密度分量 + 角色互补分量，受 max_factor 约束 ----
    float density_component = 0.f;
    if (r.density > static_cast<double>(cfg.density_threshold)) {
        density_component = 0.4f * static_cast<float>(r.density);
    }
    const float complement_component = std::min(
        0.3f, 0.15f * static_cast<float>(r.complement_edges));
    float total = r.degree_anomaly + r.community_anomaly + r.triangle_anomaly +
                  r.similarity_anomaly + density_component + complement_component;
    total = std::max(0.f, std::min(total, 1.f));
    const int cap = std::max(0, cfg.max_factor);
    r.graph_factor = std::min(cap, static_cast<int>(total * static_cast<float>(cap)));

    // ---- 8. 线索说明 ----
    std::ostringstream head;
    head << "操作员图谱：节点=" << r.operator_count << " 边=" << r.edge_count
         << "（同对象共现=" << r.cooccur_edges << " 角色互补=" << r.complement_edges << "）";
    r.notes.push_back(head.str());
    {
        std::ostringstream den;
        den << "时间窗稠密度=" << r.density << "（阈值=" << cfg.density_threshold
            << " 窗口=" << cfg.window_us << "us）";
        if (r.density > static_cast<double>(cfg.density_threshold)) {
            den << " 超阈值，计入稠密度线索";
        }
        r.notes.push_back(den.str());
    }
    for (const auto& e : r.edges) {
        if (e.complement == 0) continue;
        std::ostringstream cn;
        cn << "角色互补：" << e.op_a << " + " << e.op_b << " [";
        for (std::size_t i = 0; i < e.labels.size(); ++i) {
            if (i) cn << ",";
            cn << e.labels[i];
        }
        cn << "] 命中 " << e.complement << " 次";
        r.notes.push_back(cn.str());
    }
    for (const auto& n : m4.notes) r.notes.push_back(n);
    if (r.graph_factor == 0 && !r.edges.empty()) {
        r.notes.push_back("图异常分未超阈值，不计入 graph_factor");
    }
    return r;
}

}  // namespace af::graph
