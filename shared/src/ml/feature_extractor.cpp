// AuditForwarder - 行为特征工程实现（M3 措施3）。
// 纯 C++ 逻辑，不依赖 ONNX Runtime。
// 详见 include/auditforwarder/feature_extractor.h 特征列表注释。

#include "auditforwarder/feature_extractor.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <ctime>
#include <map>
#include <set>
#include <string>
#include <unordered_map>

namespace af::ml {

// ---- 辅助函数 ----

namespace {

// UTC 星期几（0=周日, 1=周一, ..., 6=周六）
int utc_weekday(u64 ts_ms) {
    std::time_t t = static_cast<std::time_t>(ts_ms / 1000);
    std::tm tm{};
#ifdef AF_PLATFORM_WINDOWS
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    return tm.tm_wday;
}

// UTC 小时（0~23）
int utc_hour(u64 ts_ms) {
    std::time_t t = static_cast<std::time_t>(ts_ms / 1000);
    std::tm tm{};
#ifdef AF_PLATFORM_WINDOWS
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    return tm.tm_hour;
}

// 安全归一化到 [0, 1]
float clamp01(float v) {
    if (v < 0.f) return 0.f;
    if (v > 1.f) return 1.f;
    return v;
}

// 归一化间隔（秒）到 [0, 1]，上限 3600 秒
float norm_interval(float sec) {
    return clamp01(sec / 3600.f);
}

// log2 归一化操作数（上限 ~256 → 1.0）
float norm_count(std::size_t n) {
    if (n == 0) return 0.f;
    return clamp01(std::log2(static_cast<float>(n + 1)) / 8.f);
}

// Shannon 熵归一化（log2(N) 为最大熵）
float normalized_entropy(const std::map<std::string, int>& counts, int total) {
    if (total <= 0 || counts.empty()) return 0.f;
    float entropy = 0.f;
    for (const auto& [k, cnt] : counts) {
        if (cnt <= 0) continue;
        float p = static_cast<float>(cnt) / total;
        entropy -= p * std::log2(p);
    }
    float max_entropy = std::log2(static_cast<float>(counts.size()));
    if (max_entropy <= 0.f) return 0.f;
    return clamp01(entropy / max_entropy);
}

}  // namespace

// ---- BehaviorFeatures ----

std::vector<float> BehaviorFeatures::to_vector() const {
    return {
        op_interval_mean, op_interval_std, op_type_entropy, burst_ratio,
        cross_asset_ratio, off_hours_ratio, cmd_repeat_ratio,
        distinct_op_type_ratio, distinct_server_ratio, distinct_res_ratio,
        max_interval_sec, min_interval_sec, op_count_norm, ops_per_minute,
        pair_familiarity, asset_familiarity, cross_domain_ratio,
        night_ratio, weekend_ratio, param_avg_len_norm
    };
}

// ---- FeatureExtractor ----

BehaviorFeatures FeatureExtractor::extract(
    const std::vector<af::collusion::CleanEvent>& events,
    const af::collusion::ProfileSnapshot& profile,
    const std::string& asset_group) const
{
    BehaviorFeatures f;
    if (events.empty()) return f;

    const std::size_t n = events.size();

    // ---- 操作间隔统计 ----
    std::vector<double> intervals;   // 秒
    intervals.reserve(n > 0 ? n - 1 : 0);
    for (std::size_t i = 1; i < n; ++i) {
        double diff_ms = static_cast<double>(events[i].ts_ms) - static_cast<double>(events[i-1].ts_ms);
        intervals.push_back(diff_ms / 1000.0);  // 转秒
    }

    if (!intervals.empty()) {
        double sum = 0.0;
        for (double v : intervals) sum += v;
        double mean = sum / intervals.size();
        double sq_sum = 0.0;
        for (double v : intervals) sq_sum += (v - mean) * (v - mean);
        double stddev = std::sqrt(sq_sum / intervals.size());

        f.op_interval_mean = norm_interval(static_cast<float>(mean));
        f.op_interval_std  = norm_interval(static_cast<float>(stddev));

        double max_i = *std::max_element(intervals.begin(), intervals.end());
        double min_i = *std::min_element(intervals.begin(), intervals.end());
        f.max_interval_sec = norm_interval(static_cast<float>(max_i));
        f.min_interval_sec = norm_interval(static_cast<float>(min_i));
    }

    // ---- 操作类型分布与熵 ----
    std::map<std::string, int> op_type_counts;
    std::map<std::string, int> server_counts;
    std::map<std::string, int> res_counts;
    std::map<std::string, int> param_counts;
    int off_hours_cnt = 0;
    int night_cnt = 0;
    int weekend_cnt = 0;
    int total_param_len = 0;

    for (const auto& ev : events) {
        op_type_counts[ev.op_type]++;
        server_counts[ev.server_id]++;
        res_counts[ev.res_key]++;
        param_counts[ev.op_param]++;
        total_param_len += static_cast<int>(ev.op_param.size());

        int hr = utc_hour(ev.ts_ms);
        if (hr < 9 || hr >= 18) ++off_hours_cnt;       // 非工时 9~18 UTC 以外
        if (hr < 6) ++night_cnt;                       // 深夜 0~6
        int wd = utc_weekday(ev.ts_ms);
        if (wd == 0 || wd == 6) ++weekend_cnt;          // 周末
    }

    f.op_type_entropy = normalized_entropy(op_type_counts, static_cast<int>(n));
    f.off_hours_ratio = clamp01(static_cast<float>(off_hours_cnt) / n);
    f.night_ratio      = clamp01(static_cast<float>(night_cnt) / n);
    f.weekend_ratio    = clamp01(static_cast<float>(weekend_cnt) / n);

    // ---- 突发操作占比（>10 ops/min 的时间窗口） ----
    // 滑动窗口：对每个事件，检查 60 秒内的事件数 >10 则为突发
    int burst_count = 0;
    for (std::size_t i = 0; i < n; ++i) {
        u64 window_start = events[i].ts_ms;
        u64 window_end = window_start + 60000;  // 60 秒
        int cnt = 0;
        for (std::size_t j = i; j < n && events[j].ts_ms <= window_end; ++j) {
            ++cnt;
        }
        if (cnt > 10) { ++burst_count; break; }  // 只标记一次即可
    }
    f.burst_ratio = burst_count > 0 ? 1.f : 0.f;

    // ---- 多样性比例 ----
    f.distinct_op_type_ratio = clamp01(static_cast<float>(op_type_counts.size()) / n);
    f.distinct_server_ratio  = clamp01(static_cast<float>(server_counts.size()) / n);
    f.distinct_res_ratio      = clamp01(static_cast<float>(res_counts.size()) / n);
    f.cross_asset_ratio       = f.distinct_server_ratio;  // 跨资产 = 多服务器

    // ---- 命令重复率 ----
    int repeat_params = 0;
    for (const auto& [k, cnt] : param_counts) {
        if (cnt > 1) repeat_params += (cnt - 1);
    }
    f.cmd_repeat_ratio = clamp01(static_cast<float>(repeat_params) / n);

    // ---- 操作总数归一化 ----
    f.op_count_norm = norm_count(n);

    // ---- 每分钟操作频率 ----
    if (n >= 2) {
        double span_sec = static_cast<double>(events[n-1].ts_ms - events[0].ts_ms) / 1000.0;
        if (span_sec > 0) {
            double rate = static_cast<double>(n) / (span_sec / 60.0);
            f.ops_per_minute = clamp01(static_cast<float>(rate / 60.f));  // 60 ops/min → 1.0
        }
    }

    // ---- 操作参数平均长度归一化 ----
    if (n > 0) {
        float avg_len = static_cast<float>(total_param_len) / n;
        f.param_avg_len_norm = clamp01(avg_len / 256.f);
    }

    // ---- 协作熟悉度（画像 pair_counts 均值） ----
    if (!profile.pair_counts.empty()) {
        u64 pair_sum = 0;
        for (const auto& [k, cnt] : profile.pair_counts) pair_sum += cnt;
        float avg = static_cast<float>(pair_sum) / profile.pair_counts.size();
        f.pair_familiarity = clamp01(avg / 20.f);  // 20 次以上 → 1.0
    }

    // ---- 资产熟悉度（画像 operator_assets 均值） ----
    if (!profile.operator_assets.empty()) {
        u64 asset_sum = 0;
        for (const auto& [op, assets] : profile.operator_assets) {
            for (const auto& [grp, cnt] : assets) asset_sum += cnt;
        }
        float avg = static_cast<float>(asset_sum) / profile.operator_assets.size();
        f.asset_familiarity = clamp01(avg / 20.f);
    }

    // ---- 跨域操作员比例 ----
    // 从 events 提取操作员列表，检查画像中该 asset_group 的操作次数 < 2
    std::set<std::string> ops;
    for (const auto& ev : events) ops.insert(ev.oper_id);
    int cross_domain = 0;
    for (const auto& op : ops) {
        auto it = profile.operator_assets.find(op);
        if (it == profile.operator_assets.end()) { ++cross_domain; continue; }
        auto git = it->second.find(asset_group);
        if (git == it->second.end() || git->second < 2) ++cross_domain;
    }
    f.cross_domain_ratio = ops.empty() ? 0.f : clamp01(static_cast<float>(cross_domain) / ops.size());

    return f;
}

}  // namespace af::ml
