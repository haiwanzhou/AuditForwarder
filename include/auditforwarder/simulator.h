#pragma once
// AuditForwarder - 多操作员行为模拟器（M8）。
//
// 设计依据 docs/ROADMAP_M5_M8.md「M8：模拟与演示」：
//   - 按 CERT r4.2 insider threat 剧本改编，生成多操作员正常行为 + 合谋攻击序列；
//   - 输出为服务端 /collusion/ingest 可直接消费的 JSONL（每行一条事件）；
//   - 事件时间戳统一微秒（event_timestamp_us），保证跨主机/跨事件规则口径一致。
//
// 模拟场景 cert_r42 覆盖：
//   正常行为：多名操作员对图书管理系统（book-web）的读/建/改操作；
//   攻击 A：备份销毁合谋（删备份 + 卸载备份卷 + 快照），命中 R-001 与图谱角色互补；
//   攻击 B：数据批量外泄（提权 + 导出 + 清除），命中 R-004；
//   攻击 C：同一操作员导出后清除，命中 R-006（group_by=operator）；
//   攻击 D：同对象提权后外泄，命中 R-007（group_by=object）。

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace af::sim {

struct SimConfig {
    std::string scenario   { "cert_r42" };
    int         operators  { 4 };              // 正常行为操作员数（2~10）
    std::size_t normal_events_per_operator { 8 };   // 每人正常操作条数
    std::uint64_t base_epoch_ms { 0 };         // 基准时间（毫秒，0 = 当前时间）
    std::uint64_t seed { 20261022 };           // 随机种子（可复现）
    bool        inject_attacks { true };       // 是否注入合谋攻击序列
};

// 生成 JSONL 文本（每行一条事件，末尾带换行；空配置返回空串）
std::string simulate_jsonl(const SimConfig& cfg);

// 场景说明（--list 展示）
std::vector<std::string> scenario_catalog();

}  // namespace af::sim
