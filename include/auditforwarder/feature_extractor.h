#pragma once
// AuditForwarder - 行为特征工程（M3 措施3 前置层）。
//
// 设计依据 docs/REMEDIATION_PLAN.md 第四章 4.3.2：
//   - 从聚合事件集合（AggSet.events: CleanEvent）+ 行为画像（ProfileSnapshot）
//     提取 ~20 维行为特征向量，供 ONNX 推理（孤立森林/LSTM）输入；
//   - 纯 C++ 逻辑，不依赖 ONNX Runtime，可独立单元测试；
//   - 特征维度固定为 20，顺序固定（与预训练模型输入对齐）。
//
// 特征列表（顺序即 to_vector() 输出顺序）：
//   0. op_interval_mean       操作间隔均值（秒）
//   1. op_interval_std        操作间隔标准差
//   2. op_type_entropy        操作类型信息熵（归一化 0~1）
//   3. burst_ratio            突发操作占比（>10 ops/min 的时间窗口占比）
//   4. cross_asset_ratio      跨资产操作比例（distinct server / total）
//   5. off_hours_ratio       非工时操作占比（UTC 9~18 以外）
//   6. cmd_repeat_ratio       命令重复率（重复 op_param 占比）
//   7. distinct_op_type_ratio 操作类型多样性（distinct/total）
//   8. distinct_server_ratio  目标服务器多样性
//   9. distinct_res_ratio    资源多样性
//  10. max_interval_sec       最大操作间隔（秒，归一化）
//  11. min_interval_sec       最小操作间隔（秒，归一化）
//  12. op_count_norm          操作总数（归一化 log2）
//  13. ops_per_minute         每分钟操作频率
//  14. pair_familiarity       协作熟悉度（画像 pair_counts 均值，归一化）
//  15. asset_familiarity      资产熟悉度（画像 operator_assets 均值，归一化）
//  16. cross_domain_ratio     跨域操作员比例（画像中该资产组<2次）
//  17. night_ratio            深夜操作占比（UTC 0~6）
//  18. weekend_ratio          周末操作占比
//  19. param_avg_len_norm     操作参数平均长度（归一化）

#include "auditforwarder/collusion.h"   // CleanEvent / ProfileSnapshot
#include <string>
#include <vector>

namespace af::ml {

// 行为特征向量（固定 20 维）
struct BehaviorFeatures {
    float op_interval_mean      { 0.f };
    float op_interval_std       { 0.f };
    float op_type_entropy       { 0.f };
    float burst_ratio           { 0.f };
    float cross_asset_ratio     { 0.f };
    float off_hours_ratio       { 0.f };
    float cmd_repeat_ratio      { 0.f };
    float distinct_op_type_ratio{ 0.f };
    float distinct_server_ratio { 0.f };
    float distinct_res_ratio    { 0.f };
    float max_interval_sec      { 0.f };
    float min_interval_sec      { 0.f };
    float op_count_norm         { 0.f };
    float ops_per_minute        { 0.f };
    float pair_familiarity      { 0.f };
    float asset_familiarity     { 0.f };
    float cross_domain_ratio    { 0.f };
    float night_ratio           { 0.f };
    float weekend_ratio         { 0.f };
    float param_avg_len_norm    { 0.f };

    // 转为 float 向量（顺序固定，供 ONNX 推理输入）
    std::vector<float> to_vector() const;

    // 特征维度
    static constexpr std::size_t DIM = 20;
};

// 行为特征提取器（无状态，可独立单元测试）
class FeatureExtractor {
public:
    // 从聚合事件集合提取行为特征
    //   events: 按 ts_ms 升序排列的清洗后事件
    //   profile: 行为画像快照（协作关系 + 资产域分布）
    //   asset_group: 当前聚合集合的资产组（用于跨域判定）
    BehaviorFeatures extract(const std::vector<af::collusion::CleanEvent>& events,
                            const af::collusion::ProfileSnapshot& profile,
                            const std::string& asset_group) const;
};

}  // namespace af::ml
