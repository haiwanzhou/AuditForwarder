// AuditForwarder - CERT r4.2 改编的多操作员行为模拟器实现（M8）。
//
// 纯逻辑实现：不访问网络与文件，直接产出 JSONL 文本，便于单元测试与外部投递工具复用。

#include "auditforwarder/simulator.h"

#include <algorithm>
#include <chrono>
#include <sstream>

namespace af::sim {

namespace {

// 极简可复现随机数（xorshift64*）：不依赖 <random> 的平台差异
class Rng {
public:
    explicit Rng(std::uint64_t seed) : s_(seed ? seed : 88172645463325252ull) {}
    std::uint64_t next() {
        s_ ^= s_ >> 12;
        s_ ^= s_ << 25;
        s_ ^= s_ >> 27;
        return s_ * 2685821657736338717ull;
    }
    std::size_t below(std::size_t n) { return n == 0 ? 0 : static_cast<std::size_t>(next() % n); }

private:
    std::uint64_t s_;
};

struct SimEvent {
    std::string oper_id;
    std::string operator_name;
    std::uint64_t ts_us { 0 };
    std::string server_id;
    std::string op_type;
    std::string action_norm;   // <verb>.<object>，规则精确匹配用
    std::string res_key;
    std::string op_param;
};

std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    static const char* hex = "0123456789abcdef";
                    out += "\\u00";
                    out.push_back(hex[(c >> 4) & 0xF]);
                    out.push_back(hex[c & 0xF]);
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    return out;
}

std::string event_line(const SimEvent& e) {
    std::ostringstream o;
    o << "{"
      << "\"oper_id\": \"" << json_escape(e.oper_id) << "\", "
      << "\"operator_name\": \"" << json_escape(e.operator_name) << "\", "
      << "\"event_timestamp_us\": " << e.ts_us << ", "
      << "\"server_id\": \"" << json_escape(e.server_id) << "\", "
      << "\"op_type\": \"" << json_escape(e.op_type) << "\", "
      << "\"action_norm\": \"" << json_escape(e.action_norm) << "\", "
      << "\"res_key\": \"" << json_escape(e.res_key) << "\", "
      << "\"op_param\": \"" << json_escape(e.op_param) << "\", "
      << "\"return_code\": 0"
      << "}";
    return o.str();
}

// 正常图书管理系统操作模板：动作与资源均不含攻击关键词，避免误报
struct NormalTemplate {
    const char* op_type;
    const char* res_key;
    const char* param;
};

const NormalTemplate kNormalTemplates[] = {
    { "http/read",   "/books?id=42",          "GET /books?id=42" },
    { "http/read",   "/books?page=2",         "GET /books?page=2" },
    { "http/create", "/books",                "POST /books title=Network+Security" },
    { "http/update", "/books?id=7",           "PUT /books?id=7 stock=30" },
    { "http/read",   "/orders?status=open",   "GET /orders?status=open" },
    { "http/update", "/orders?id=108",        "PUT /orders?id=108 state=shipped" },
    { "http/read",   "/reports/daily.csv",    "GET /reports/daily.csv" },
    { "http/create", "/readers",              "POST /readers name=zhangsan" },
};

}  // namespace

std::vector<std::string> scenario_catalog() {
    return {
        "cert_r42  多操作员图书系统正常行为 + 4 组 insider threat 攻击序列（推荐用于演示）",
    };
}

std::string simulate_jsonl(const SimConfig& cfg) {
    if (cfg.scenario != "cert_r42") return {};

    const int op_count = std::min(std::max(cfg.operators, 2), 10);
    Rng rng(cfg.seed);
    std::uint64_t base_ms = cfg.base_epoch_ms;
    if (base_ms == 0) {
        base_ms = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count());
    }
    // 从基准时间起，正常行为按 2~6 秒间隔推进
    std::uint64_t cursor_us = (base_ms + 1000ull) * 1000ull;   // 预留 1 秒
    std::vector<SimEvent> events;

    // ---- 1. 正常行为：每名操作员一组读/建/改操作 ----
    for (int i = 0; i < op_count; ++i) {
        SimEvent e;
        e.oper_id = "op_r" + std::to_string(i + 1);
        e.operator_name = "Reader " + std::to_string(i + 1);
        e.server_id = "book-web";
        for (std::size_t n = 0; n < cfg.normal_events_per_operator; ++n) {
            const auto& tpl = kNormalTemplates[rng.below(sizeof(kNormalTemplates) /
                                                         sizeof(kNormalTemplates[0]))];
            e.op_type = tpl.op_type;
            e.res_key = tpl.res_key;
            e.op_param = tpl.param;
            cursor_us += (2000000ull + rng.below(4000001ull));   // 2~6 秒
            e.ts_us = cursor_us;
            events.push_back(e);
        }
    }

    if (cfg.inject_attacks) {
        // ---- 2. 攻击 A：备份销毁合谋（R-001 + 图谱角色互补）----
        // 三人分工：删除备份 → 卸载备份卷 → 生成快照（同一备份资产组、15 分钟窗口内）
        {
            const std::uint64_t t0 = cursor_us + 120ull * 1000000ull;
            SimEvent a1;
            a1.oper_id = "op_dba1";
            a1.operator_name = "DBA Li";
            a1.server_id = "db-srv";
            a1.op_type = "file/delete";
            a1.action_norm = "delete.backup";
            a1.res_key = "/backup/library_full_backup.bak";
            a1.op_param = "rm -f /backup/library_full_backup.bak";
            a1.ts_us = t0;
            events.push_back(a1);

            SimEvent a2 = a1;
            a2.oper_id = "op_dba2";
            a2.operator_name = "DBA Wang";
            a2.op_type = "disk/unmount";
            a2.action_norm = "unmount.volume";
            a2.res_key = "/backup/backup_volume";
            a2.op_param = "umount /backup/backup_volume";
            a2.ts_us = t0 + 3ull * 60ull * 1000000ull;
            events.push_back(a2);

            SimEvent a3 = a1;
            a3.oper_id = "op_dba3";
            a3.operator_name = "DBA Zhao";
            a3.op_type = "file/snapshot";
            a3.action_norm = "delete.snapshot";
            a3.res_key = "/backup/library_snapshot";
            a3.op_param = "snapshot --target /backup/library_snapshot";
            a3.ts_us = t0 + 6ull * 60ull * 1000000ull;
            events.push_back(a3);
        }

        // ---- 3. 攻击 B：数据批量外泄（R-004，db-group，3 步序列）----
        {
            const std::uint64_t t0 = cursor_us + 20ull * 60ull * 1000000ull;
            SimEvent b1;
            b1.oper_id = "op_svc1";
            b1.operator_name = "Service Admin";
            b1.server_id = "db-srv";
            b1.op_type = "db/grant";
            b1.action_norm = "grant.user";
            b1.res_key = "/var/db/library.sql";
            b1.op_param = "GRANT ALL ON library.* TO tmp_user";
            b1.ts_us = t0;
            events.push_back(b1);

            SimEvent b2 = b1;
            b2.oper_id = "op_svc2";
            b2.operator_name = "Service Operator";
            b2.op_type = "db/export";
            b2.action_norm = "export.book";
            b2.res_key = "/var/db/library.sql";
            b2.op_param = "mysqldump --result-file=/tmp/library.sql library";
            b2.ts_us = t0 + 2ull * 60ull * 1000000ull;
            events.push_back(b2);

            SimEvent b3 = b2;
            b3.op_type = "db/clear";
            b3.action_norm = "clear.book_audit";
            b3.op_param = "TRUNCATE TABLE loans";
            b3.ts_us = t0 + 5ull * 60ull * 1000000ull;
            events.push_back(b3);
        }

        // ---- 4. 攻击 C：同一操作员导出后清除（R-006，group_by=operator）----
        {
            const std::uint64_t t0 = cursor_us + 40ull * 60ull * 1000000ull;
            SimEvent c1;
            c1.oper_id = "op_ins1";
            c1.operator_name = "Insider Chen";
            c1.server_id = "book-web";
            c1.op_type = "file/export";
            c1.action_norm = "export.book";
            c1.res_key = "/reports/all_loans.csv";
            c1.op_param = "export --all --format csv";
            c1.ts_us = t0;
            events.push_back(c1);

            SimEvent c2 = c1;
            c2.op_type = "file/clear";
            c2.action_norm = "clear.book_audit";
            c2.op_param = "clear --path /reports --all";
            c2.ts_us = t0 + 3ull * 60ull * 1000000ull;
            events.push_back(c2);
        }

        // ---- 5. 攻击 D：同对象提权后外泄（R-007，group_by=object，跨操作员）----
        {
            const std::uint64_t t0 = cursor_us + 60ull * 60ull * 1000000ull;
            SimEvent d1;
            d1.oper_id = "op_ins2";
            d1.operator_name = "Insider Sun";
            d1.server_id = "db-srv";
            d1.op_type = "db/grant";
            d1.action_norm = "grant.user";
            d1.res_key = "/var/db/secret.sql";
            d1.op_param = "GRANT SELECT ON secret.* TO backup_user";
            d1.ts_us = t0;
            events.push_back(d1);

            SimEvent d2 = d1;
            d2.oper_id = "op_ins3";
            d2.operator_name = "Insider Zhou";
            d2.op_type = "db/export";
            d2.action_norm = "export.book";
            d2.op_param = "mysqldump --result-file=/tmp/secret.sql secret";
            d2.ts_us = t0 + 2ull * 60ull * 1000000ull;
            events.push_back(d2);
        }
    }

    // ---- 6. 统一按微秒时间升序输出（同刻保持生成顺序）----
    std::stable_sort(events.begin(), events.end(),
                     [](const SimEvent& a, const SimEvent& b) { return a.ts_us < b.ts_us; });

    std::ostringstream out;
    for (const auto& e : events) out << event_line(e) << "\n";
    return out.str();
}

}  // namespace af::sim
