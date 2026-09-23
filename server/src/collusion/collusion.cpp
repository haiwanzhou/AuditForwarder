// AuditForwarder - 跨操作员合谋协同检测模块实现。
// 数据流：操作日志流 → 事件清洗 → 资产组+时间窗口聚合（不按操作员分组）
//        → 双路检测（规则引擎 + 行为画像引擎）→ 风险评分 → 分级告警与处置闭环。
// 详见《跨操作员合谋协同行为检测子系统-系统设计方案》与 include/auditforwarder/collusion.h。

#include "auditforwarder/collusion.h"

#include "auditforwarder/crypto.h"
#include "auditforwarder/fs.h"
#include "auditforwarder/logger.h"
#include "manager/log_policy_util.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <sstream>

namespace af::collusion {

namespace {

// ---------------- 基础工具 ----------------

constexpr std::size_t kMaxRawEvidence = 4096;      // 单条证据链原文截断
constexpr std::size_t kMaxStoredEvents = 5000;     // 风险事件文件行数上限

u64 now_ms() {
    return static_cast<u64>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

u64 now_epoch() {
    return static_cast<u64>(std::time(nullptr));
}

std::string iso_time_epoch(u64 epoch) {
    if (epoch == 0) return {};
    std::time_t t = static_cast<std::time_t>(epoch);
    std::tm tm{};
#ifdef AF_PLATFORM_WINDOWS
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

std::string iso_time_ms(u64 ms) {
    if (ms == 0) return {};
    return iso_time_epoch(ms / 1000);
}

std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
                    out += buf;
                } else {
                    out.push_back(c);
                }
        }
    }
    return out;
}

std::string json_array_of_strings(const std::vector<std::string>& v) {
    std::string o = "[";
    for (std::size_t i = 0; i < v.size(); ++i) {
        if (i) o += ",";
        o += "\"" + json_escape(v[i]) + "\"";
    }
    o += "]";
    return o;
}

std::string to_lower_copy(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

bool json_has_field(const std::string& json, const std::string& key) {
    return json.find("\"" + key + "\"") != std::string::npos;
}

// 提取 JSON 中某个对象字段的原文（含花括号），如 "dispose":{...}；深度感知字符串
std::string json_object_text(const std::string& json, const std::string& key) {
    auto marker = "\"" + key + "\"";
    auto p = json.find(marker);
    if (p == std::string::npos) return {};
    auto start = json.find('{', p + marker.size());
    if (start == std::string::npos) return {};
    int depth = 0;
    bool in_str = false, esc = false;
    for (std::size_t i = start; i < json.size(); ++i) {
        char c = json[i];
        if (in_str) {
            if (esc) esc = false;
            else if (c == '\\') esc = true;
            else if (c == '"') in_str = false;
            continue;
        }
        if (c == '"') in_str = true;
        else if (c == '{') ++depth;
        else if (c == '}') {
            --depth;
            if (depth == 0) return json.substr(start, i - start + 1);
        }
    }
    return {};
}

bool json_bool_field(const std::string& json, const std::string& key, bool def) {
    auto marker = "\"" + key + "\"";
    auto p = json.find(marker);
    if (p == std::string::npos) return def;
    p = json.find(':', p + marker.size());
    if (p == std::string::npos) return def;
    ++p;
    while (p < json.size() && std::isspace(static_cast<unsigned char>(json[p]))) ++p;
    if (json.compare(p, 4, "true") == 0) return true;
    if (json.compare(p, 5, "false") == 0) return false;
    return def;
}

// 读取文件全部文本；失败返回空串
std::string read_file_text(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return {};
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

bool write_file_text(const std::string& path, const std::string& text) {
    auto dir = fs::dirname(path);
    if (!dir.empty()) (void)fs::create_directories(dir);
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out << text;
    out.flush();
    return static_cast<bool>(out);
}

std::vector<std::string> read_jsonl(const std::string& path) {
    std::vector<std::string> lines;
    auto content = read_file_text(path);
    if (content.empty()) return lines;
    std::istringstream in(content);
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty()) lines.push_back(line);
    }
    return lines;
}

// 在 JSON 对象中替换 "key":{...} 的整个对象值（深度感知字符串，用于处置状态更新）
bool json_replace_object_field(std::string& json, const std::string& key, const std::string& new_obj) {
    auto marker = "\"" + key + "\"";
    auto p = json.find(marker);
    if (p == std::string::npos) return false;
    p = json.find('{', p + marker.size());
    if (p == std::string::npos) return false;
    int depth = 0;
    bool in_str = false, esc = false;
    for (std::size_t i = p; i < json.size(); ++i) {
        char c = json[i];
        if (in_str) {
            if (esc) esc = false;
            else if (c == '\\') esc = true;
            else if (c == '"') in_str = false;
            continue;
        }
        if (c == '"') in_str = true;
        else if (c == '{') ++depth;
        else if (c == '}') {
            --depth;
            if (depth == 0) {
                json = json.substr(0, p) + new_obj + json.substr(i + 1);
                return true;
            }
        }
    }
    return false;
}

// ---------------- 存储路径 ----------------

std::string collusion_dir(const std::string& data_dir) {
    return fs::join(data_dir.empty() ? "data" : data_dir, "collusion");
}
std::string events_path(const std::string& data_dir) {
    return fs::join(collusion_dir(data_dir), "events.jsonl");
}
std::string audit_path(const std::string& data_dir) {
    return fs::join(collusion_dir(data_dir), "audit.jsonl");
}
std::string profile_path(const std::string& data_dir) {
    return fs::join(collusion_dir(data_dir), "profiles.json");
}
std::string policy_dir(const std::string& data_dir) {
    return fs::join(data_dir.empty() ? "data" : data_dir, "policies");
}
std::string config_path(const std::string& data_dir) {
    return fs::join(policy_dir(data_dir), "collusion_config.json");
}
std::string rules_path(const std::string& data_dir) {
    return fs::join(policy_dir(data_dir), "collusion_rules.json");
}
std::string workorders_path(const std::string& data_dir) {
    return fs::join(policy_dir(data_dir), "collusion_workorders.json");
}

// ---------------- 默认配置 / 规则 / 工单桩（首次运行自动生成，支持热更新） ----------------

std::string default_config_json() {
    return R"({
  "enabled": true,
  "note": "跨操作员合谋协同检测配置（热更新）；asset_groups.patterns 支持通配符 * 与 ?",
  "short_window_minutes": 15,
  "long_window_hours": 4,
  "flush_grace_seconds": 10,
  "rule_max_factor": 40,
  "profile_max_factor": 25,
  "work_order_deduct": 40,
  "forged_ticket_bonus": 10,
  "score_high": 80,
  "score_mid": 40,
  "alert_dedup_seconds": 300,
  "emergency_mode": false,
  "emergency_until_epoch": 0,
  "profile_enabled": true,
  "asset_groups": [
    { "name": "backup-group",    "patterns": ["*backup*", "*snapshot*", "*快照*", "*.bak", "*备份*"] },
    { "name": "key-mgmt-group",  "patterns": ["*key*", "*secret*", "*cert*", "*.pem", "*密钥*"] },
    { "name": "sys-config-group","patterns": ["*config*", "*.conf", "*.ini", "*.yaml", "*.yml", "*.service", "*hosts*"] },
    { "name": "db-group",        "patterns": ["*database*", "*.db", "*.sql", "*mysql*", "*postgres*", "*oracle*", "*redis*"] },
    { "name": "general-group",   "patterns": ["*"], "note": "兜底资产组：仅产生低风险线索，可按需删除" }
  ],
  "whitelist_groups": [
    { "name": "示例-数据库协同组", "operators": ["op_dba1", "op_dba2"], "valid_until_epoch": 0,
      "note": "预登记合法协同小组示例：请替换为实际操作员清单，0 表示长期有效" }
  ]
}
)";
}

std::string default_rules_json() {
    // 预置 5 条典型合谋规则（R-001~R-005），sequence 为按时间有序的操作子序列，
    // 每一步任一关键词命中即视为完成该步骤；支持配置化扩展与热加载。
    return R"({
  "rules": [
    { "rule_id": "R-001", "name": "备份销毁合谋", "enabled": true,
      "asset_group": "backup-group", "min_operator_cnt": 2, "base_score": 85,
      "op_sequence": [
        { "any_of": ["delete", "remove", "删除"] },
        { "any_of": ["unmount", "detach", "卸载", "取消挂载"] },
        { "any_of": ["snapshot", "快照"] }
      ] },
    { "rule_id": "R-002", "name": "密钥权限拆分绕过", "enabled": true,
      "asset_group": "key-mgmt-group", "min_operator_cnt": 3, "base_score": 80,
      "op_sequence": [
        { "any_of": ["generate", "create", "生成"] },
        { "any_of": ["distribut", "grant", "分发", "授权"] },
        { "any_of": ["clear", "clean", "清理", "清除"] }
      ] },
    { "rule_id": "R-003", "name": "配置篡改链路", "enabled": true,
      "asset_group": "sys-config-group", "min_operator_cnt": 2, "base_score": 70,
      "op_sequence": [
        { "any_of": ["write", "modify", "set", "修改", "配置"] },
        { "any_of": ["restart", "stop", "start", "重启", "停止"] },
        { "any_of": ["clear", "clean", "清空", "清除"] }
      ] },
    { "rule_id": "R-004", "name": "数据批量外泄", "enabled": true,
      "asset_group": "db-group", "min_operator_cnt": 2, "base_score": 82,
      "op_sequence": [
        { "any_of": ["privilege", "elevat", "grant", "提权", "授权"] },
        { "any_of": ["export", "download", "dump", "导出", "下载"] },
        { "any_of": ["clear", "clean", "清除"] }
      ] },
    { "rule_id": "R-005", "name": "权限晋升合谋", "enabled": true,
      "asset_group": "*", "min_operator_cnt": 3, "base_score": 75,
      "op_sequence": [
        { "any_of": ["role", "useradd", "创建角色", "创建用户", "new-user"] },
        { "any_of": ["member", "assign", "加入", "添加"] },
        { "any_of": ["admin", "sensitive", "exec", "敏感", "提权"] }
      ] }
  ]
}
)";
}

std::string default_workorders_json() {
    // 外部工单系统 API 的本地桩：生产环境应替换为对接外部工单系统核验接口。
    // 不采信日志内自带工单号，只有登记于此（模拟外部核验通过）的工单才能触发减分。
    return R"({
  "workorders": [
    { "work_order_id": "WO-2026-0001", "status": "执行中",
      "allowed_operators": ["op_dba1", "op_dba2"],
      "valid_from_epoch": 0, "valid_until_epoch": 0,
      "note": "示例工单：合谋演示环境使用" }
  ]
}
)";
}

// ---------------- 结构化读写 ----------------

std::string patterns_json(const std::vector<std::string>& patterns) {
    return json_array_of_strings(patterns);
}

std::string config_to_json(const EngineConfig& c) {
    std::ostringstream o;
    o << "{\n"
      << "  \"enabled\": " << (c.enabled ? "true" : "false") << ",\n"
      << "  \"short_window_minutes\": " << (c.short_window_ms / 60000) << ",\n"
      << "  \"long_window_hours\": " << (c.long_window_ms / 3600000) << ",\n"
      << "  \"flush_grace_seconds\": " << (c.flush_grace_ms / 1000) << ",\n"
      << "  \"rule_max_factor\": " << c.rule_max_factor << ",\n"
      << "  \"profile_max_factor\": " << c.profile_max_factor << ",\n"
      << "  \"work_order_deduct\": " << c.work_order_deduct << ",\n"
      << "  \"forged_ticket_bonus\": " << c.forged_ticket_bonus << ",\n"
      << "  \"score_high\": " << c.score_high << ",\n"
      << "  \"score_mid\": " << c.score_mid << ",\n"
      << "  \"alert_dedup_seconds\": " << c.alert_dedup_seconds << ",\n"
      << "  \"emergency_mode\": " << (c.emergency_mode ? "true" : "false") << ",\n"
      << "  \"emergency_until_epoch\": " << c.emergency_until_epoch << ",\n"
      << "  \"profile_enabled\": " << (c.profile_enabled ? "true" : "false") << ",\n"
      << "  \"asset_groups\": [\n";
    for (std::size_t i = 0; i < c.asset_groups.size(); ++i) {
        o << "    { \"name\": \"" << json_escape(c.asset_groups[i].name)
          << "\", \"patterns\": " << patterns_json(c.asset_groups[i].patterns) << " }";
        if (i + 1 < c.asset_groups.size()) o << ",";
        o << "\n";
    }
    o << "  ],\n  \"whitelist_groups\": [\n";
    for (std::size_t i = 0; i < c.whitelist_groups.size(); ++i) {
        const auto& w = c.whitelist_groups[i];
        o << "    { \"name\": \"" << json_escape(w.name)
          << "\", \"operators\": " << json_array_of_strings(w.operators)
          << ", \"valid_until_epoch\": " << w.valid_until_epoch << " }";
        if (i + 1 < c.whitelist_groups.size()) o << ",";
        o << "\n";
    }
    o << "  ]\n}\n";
    return o.str();
}

EngineConfig config_from_json(const std::string& j) {
    EngineConfig c;
    c.enabled = json_bool_field(j, "enabled", true);
    u64 short_min = static_cast<u64>(logpolicy::json_size_field(j, "short_window_minutes", 15));
    short_min = std::min<u64>(std::max<u64>(short_min, 5), 30);     // 设计约束：5~30 分钟
    c.short_window_ms = short_min * 60000;
    u64 long_hours = static_cast<u64>(logpolicy::json_size_field(j, "long_window_hours", 4));
    long_hours = std::min<u64>(std::max<u64>(long_hours, 1), 24);
    c.long_window_ms = long_hours * 3600000;
    u64 grace = static_cast<u64>(logpolicy::json_size_field(j, "flush_grace_seconds", 10));
    c.flush_grace_ms = std::min<u64>(grace, 300) * 1000;
    c.rule_max_factor = std::min(std::max(static_cast<int>(logpolicy::json_size_field(j, "rule_max_factor", 40)), 10), 60);
    c.profile_max_factor = std::min(std::max(static_cast<int>(logpolicy::json_size_field(j, "profile_max_factor", 25)), 5), 40);
    c.work_order_deduct = std::min(static_cast<int>(logpolicy::json_size_field(j, "work_order_deduct", 40)), 100);
    c.forged_ticket_bonus = std::min(static_cast<int>(logpolicy::json_size_field(j, "forged_ticket_bonus", 10)), 40);
    c.score_high = std::min(std::max(static_cast<int>(logpolicy::json_size_field(j, "score_high", 80)), 50), 100);
    c.score_mid = std::min(std::max(static_cast<int>(logpolicy::json_size_field(j, "score_mid", 40)), 10), c.score_high - 1);
    c.alert_dedup_seconds = static_cast<u64>(logpolicy::json_size_field(j, "alert_dedup_seconds", 300));
    c.emergency_mode = json_bool_field(j, "emergency_mode", false);
    c.emergency_until_epoch = static_cast<u64>(logpolicy::json_size_field(j, "emergency_until_epoch", 0));
    c.profile_enabled = json_bool_field(j, "profile_enabled", true);
    for (const auto& rec : logpolicy::json_object_array_field(j, "asset_groups")) {
        AssetGroup g;
        g.name = logpolicy::json_string_field(rec, "name");
        if (g.name.empty()) continue;
        g.patterns = logpolicy::json_string_array_field(rec, "patterns");
        c.asset_groups.push_back(std::move(g));
    }
    for (const auto& rec : logpolicy::json_object_array_field(j, "whitelist_groups")) {
        WhitelistGroup w;
        w.name = logpolicy::json_string_field(rec, "name");
        if (w.name.empty()) continue;
        w.operators = logpolicy::json_string_array_field(rec, "operators");
        w.valid_until_epoch = static_cast<u64>(logpolicy::json_size_field(rec, "valid_until_epoch", 0));
        c.whitelist_groups.push_back(std::move(w));
    }
    return c;
}

std::string rules_to_json(const std::vector<Rule>& rules) {
    std::ostringstream o;
    o << "{\n  \"rules\": [\n";
    for (std::size_t i = 0; i < rules.size(); ++i) {
        const auto& r = rules[i];
        o << "    { \"rule_id\": \"" << json_escape(r.rule_id)
          << "\", \"name\": \"" << json_escape(r.name)
          << "\", \"enabled\": " << (r.enabled ? "true" : "false")
          << ", \"asset_group\": \"" << json_escape(r.asset_group)
          << "\", \"min_operator_cnt\": " << r.min_operator_cnt
          << ", \"base_score\": " << r.base_score
          << ",\n      \"op_sequence\": [\n";
        for (std::size_t k = 0; k < r.sequence.size(); ++k) {
            o << "        { \"any_of\": " << json_array_of_strings(r.sequence[k].any_of) << " }";
            if (k + 1 < r.sequence.size()) o << ",";
            o << "\n";
        }
        o << "      ] }";
        if (i + 1 < rules.size()) o << ",";
        o << "\n";
    }
    o << "  ]\n}\n";
    return o.str();
}

std::vector<Rule> rules_from_json(const std::string& j) {
    std::vector<Rule> out;
    for (const auto& rec : logpolicy::json_object_array_field(j, "rules")) {
        Rule r;
        r.rule_id = logpolicy::json_string_field(rec, "rule_id");
        if (r.rule_id.empty()) r.rule_id = logpolicy::json_string_field(rec, "id");
        if (r.rule_id.empty()) continue;
        r.name = logpolicy::json_string_field(rec, "name");
        r.enabled = json_bool_field(rec, "enabled", true);
        r.asset_group = logpolicy::json_string_field(rec, "asset_group");
        if (r.asset_group.empty()) r.asset_group = "*";
        r.min_operator_cnt = std::max(2, static_cast<int>(logpolicy::json_size_field(rec, "min_operator_cnt", 2)));
        r.base_score = std::min(std::max(static_cast<int>(logpolicy::json_size_field(rec, "base_score", 80)), 1), 100);
        for (const auto& step : logpolicy::json_object_array_field(rec, "op_sequence")) {
            RuleStep s;
            s.any_of = logpolicy::json_string_array_field(step, "any_of");
            if (!s.any_of.empty()) r.sequence.push_back(std::move(s));
        }
        if (!r.sequence.empty()) out.push_back(std::move(r));
    }
    return out;
}

std::string workorders_to_json(const std::vector<WorkOrder>& wos) {
    std::ostringstream o;
    o << "{\n  \"workorders\": [\n";
    for (std::size_t i = 0; i < wos.size(); ++i) {
        const auto& w = wos[i];
        o << "    { \"work_order_id\": \"" << json_escape(w.work_order_id)
          << "\", \"status\": \"" << json_escape(w.status)
          << "\", \"allowed_operators\": " << json_array_of_strings(w.allowed_operators)
          << ", \"valid_from_epoch\": " << w.valid_from_epoch
          << ", \"valid_until_epoch\": " << w.valid_until_epoch << " }";
        if (i + 1 < wos.size()) o << ",";
        o << "\n";
    }
    o << "  ]\n}\n";
    return o.str();
}

std::vector<WorkOrder> workorders_from_json(const std::string& j) {
    std::vector<WorkOrder> out;
    for (const auto& rec : logpolicy::json_object_array_field(j, "workorders")) {
        WorkOrder w;
        w.work_order_id = logpolicy::json_string_field(rec, "work_order_id");
        if (w.work_order_id.empty()) continue;
        w.status = logpolicy::json_string_field(rec, "status");
        w.allowed_operators = logpolicy::json_string_array_field(rec, "allowed_operators");
        w.valid_from_epoch = static_cast<u64>(logpolicy::json_size_field(rec, "valid_from_epoch", 0));
        w.valid_until_epoch = static_cast<u64>(logpolicy::json_size_field(rec, "valid_until_epoch", 0));
        out.push_back(std::move(w));
    }
    return out;
}

std::string pair_key(const std::string& a, const std::string& b) {
    return a < b ? a + "|" + b : b + "|" + a;
}

}  // namespace

// ---------------- 纯逻辑函数 ----------------

bool wildcard_match(const std::string& pattern, const std::string& text) {
    std::string p = to_lower_copy(pattern);
    std::string t = to_lower_copy(text);
    // 迭代式通配符匹配（* 与 ?），避免递归在长文本上退化
    std::size_t pi = 0, ti = 0, star = std::string::npos, mark = 0;
    while (ti < t.size()) {
        if (pi < p.size() && (p[pi] == '?' || p[pi] == t[ti])) { ++pi; ++ti; }
        else if (pi < p.size() && p[pi] == '*') { star = pi++; mark = ti; }
        else if (star != std::string::npos) { pi = star + 1; ti = ++mark; }
        else return false;
    }
    while (pi < p.size() && p[pi] == '*') ++pi;
    return pi == p.size();
}

bool any_keyword_hit(const std::vector<std::string>& keywords, const std::string& text) {
    if (keywords.empty()) return false;
    std::string t = to_lower_copy(text);
    for (const auto& k : keywords) {
        if (k.empty()) continue;
        if (t.find(to_lower_copy(k)) != std::string::npos) return true;
    }
    return false;
}

bool is_subsequence(const std::vector<RuleStep>& sequence, const std::vector<CleanEvent>& events) {
    if (sequence.empty()) return false;
    std::size_t si = 0;
    for (const auto& e : events) {
        if (si >= sequence.size()) break;
        std::string searchable = e.op_type + " " + e.res_key + " " + e.op_param;
        if (any_keyword_hit(sequence[si].any_of, searchable)) ++si;
    }
    return si == sequence.size();
}

std::string match_asset_group(const std::vector<AssetGroup>& groups, const std::string& res_key) {
    if (res_key.empty()) return {};
    for (const auto& g : groups) {
        for (const auto& p : g.patterns) {
            if (wildcard_match(p, res_key)) return g.name;
        }
    }
    return {};
}

bool clean_event_json(const std::string& json, CleanEvent& out) {
    // 字段映射：优先设计文档原生字段，兼容现有审计日志字段；
    // 缺失关键直接丢弃（设计方案 3.1：缺失关键字段的日志直接丢弃）。
    out = CleanEvent{};
    out.oper_id = logpolicy::json_string_field(json, "oper_id");
    if (out.oper_id.empty()) out.oper_id = logpolicy::json_string_field(json, "operator");
    if (out.oper_id.empty()) out.oper_id = logpolicy::json_string_field(json, "actor");
    if (out.oper_id.empty()) return false;

    out.ts_ms = static_cast<u64>(logpolicy::json_size_field(json, "event_timestamp", 0));
    if (out.ts_ms == 0) out.ts_ms = static_cast<u64>(logpolicy::json_size_field(json, "client_ts", 0));
    if (out.ts_ms == 0) out.ts_ms = static_cast<u64>(logpolicy::json_size_field(json, "server_ts", 0));
    if (out.ts_ms == 0) return false;

    out.server_id = logpolicy::json_string_field(json, "server_id");
    if (out.server_id.empty()) out.server_id = logpolicy::json_string_field(json, "host_id");
    if (out.server_id.empty()) return false;

    out.op_type = logpolicy::json_string_field(json, "op_type");
    if (out.op_type.empty()) {
        auto ot = logpolicy::json_string_field(json, "operation_type");
        auto et = logpolicy::json_string_field(json, "event_type");
        out.op_type = ot.empty() ? et : (et.empty() ? ot : ot + "/" + et);
    }
    if (out.op_type.empty()) return false;

    out.res_key = logpolicy::json_string_field(json, "res_key");
    if (out.res_key.empty()) out.res_key = logpolicy::json_string_field(json, "target");
    if (out.res_key.empty()) return false;

    out.op_param = logpolicy::json_string_field(json, "op_param");
    if (out.op_param.empty()) out.op_param = logpolicy::json_string_field(json, "message");
    out.work_order_id = logpolicy::json_string_field(json, "work_order_id");
    if (out.work_order_id.empty()) out.work_order_id = logpolicy::json_string_field(json, "ticket_id");

    // 只处理执行成功的操作：return_code 存在且非 0 → 丢弃；
    // outcome 明确为失败/拒绝 → 丢弃（现有审计日志 outcome=unknown 视为成功入库）。
    if (json_has_field(json, "return_code")) {
        auto rc = logpolicy::json_size_field(json, "return_code", 0);
        if (rc != 0) return false;
    }
    auto outcome = to_lower_copy(logpolicy::json_string_field(json, "outcome"));
    if (outcome == "failed" || outcome == "failure" || outcome == "error" ||
        outcome == "denied" || outcome == "blocked") {
        return false;
    }

    out.raw = json.size() > kMaxRawEvidence ? json.substr(0, kMaxRawEvidence) : json;
    return true;
}

bool verify_work_order(const std::vector<WorkOrder>& registry, const WorkOrder& wo,
                       const std::vector<std::string>& operators, u64 now_epoch) {
    // 外部工单核验四要素：真实存在 + 状态有效 + 人员匹配 + 有效期覆盖
    if (wo.work_order_id.empty()) return false;
    bool status_ok = (wo.status == "执行中" || wo.status == "已完成" ||
                      wo.status == "in_progress" || wo.status == "done" || wo.status == "closed");
    if (!status_ok) return false;
    if (wo.valid_from_epoch && now_epoch < wo.valid_from_epoch) return false;
    if (wo.valid_until_epoch && now_epoch > wo.valid_until_epoch) return false;
    for (const auto& op : operators) {
        bool found = false;
        for (const auto& allow : wo.allowed_operators) {
            if (allow == "*" || allow == op) { found = true; break; }
        }
        if (!found) return false;
    }
    (void)registry;
    return true;
}

bool in_whitelist(const std::vector<WhitelistGroup>& groups, const AggSet& set, u64 now_epoch) {
    if (set.operator_ids.empty()) return false;
    for (const auto& g : groups) {
        if (g.valid_until_epoch && now_epoch > g.valid_until_epoch) continue;
        bool all_in = true;
        for (const auto& op : set.operator_ids) {
            if (std::find(g.operators.begin(), g.operators.end(), op) == g.operators.end()) {
                all_in = false;
                break;
            }
        }
        if (all_in) return true;
    }
    return false;
}

DetectionResult detect(const AggSet& set,
                       const EngineConfig& cfg,
                       const std::vector<Rule>& rules,
                       const ProfileSnapshot& profile,
                       const std::vector<WorkOrder>& workorders,
                       u64 now_epoch) {
    DetectionResult res;

    // ---- 白名单预检：预登记合法协同组直接放行（仅保留低级别线索记录） ----
    if (in_whitelist(cfg.whitelist_groups, set, now_epoch)) {
        res.whitelisted = true;
        res.score_notes.push_back("命中操作员白名单协同组，判定为合法协同（仅保留线索记录）");
        res.total_score = 0;
        res.level = "LOW";
        return res;
    }

    // ---- 工单外部核验（不采信日志自带字段，仅登记于工单桩的才有效） ----
    for (const auto& wo_id : set.work_order_ids) {
        bool found = false;
        for (const auto& wo : workorders) {
            if (wo.work_order_id != wo_id) continue;
            found = true;
            if (verify_work_order(workorders, wo, set.operator_ids, now_epoch)) {
                res.ticket_valid = true;
                res.score_notes.push_back("关联有效工单 " + wo_id + "（外部核验通过，减 " +
                                          std::to_string(cfg.work_order_deduct) + " 分）");
            }
            break;
        }
        if (!found) {
            res.forged_ticket = true;
            res.score_notes.push_back("工单 " + wo_id + " 外部核验不通过（疑似伪造，加 " +
                                      std::to_string(cfg.forged_ticket_bonus) + " 分）");
        }
        if (res.ticket_valid) break;
    }
    if (set.work_order_ids.empty()) {
        res.score_notes.push_back("无关联工单");
    }

    // ---- 规则引擎：确定性规则覆盖已知合谋模式 ----
    if (!rules.empty()) {
        Rule const* first_hit = nullptr;
        int extra = 0;
        for (const auto& r : rules) {
            if (!r.enabled) continue;
            if (r.asset_group != "*" && r.asset_group != set.asset_group) continue;
            if (set.distinct_op_count() < r.min_operator_cnt) continue;
            if (!is_subsequence(r.sequence, set.events)) continue;
            res.hit_rules.push_back(r.rule_id + " " + r.name);
            if (!first_hit) {
                first_hit = &r;
                res.rule_factor += r.base_score;   // 首条规则基础分直接计入（50~85）
            } else {
                extra += r.base_score;             // 多规则命中：累加部分受 rule_max_factor 限制
            }
        }
        if (first_hit) {
            res.rule_factor += std::min(extra, cfg.rule_max_factor);
            // 涉事操作员数量：超过 2 人后 +5 分/人（仅与规则命中叠加，封顶 20）
            if (set.distinct_op_count() > 2) {
                res.rule_factor += std::min((set.distinct_op_count() - 2) * 5, 20);
            }
        }
    }

    // ---- 行为画像异常引擎：仅提供线索，因子上限 profile_max_factor ----
    if (cfg.profile_enabled) {
        // 陌生协作：集合内操作员两两之间历史协作次数均极少（<2）
        bool any_pair = false;
        for (std::size_t i = 0; i < set.operator_ids.size() && !any_pair; ++i) {
            for (std::size_t k = i + 1; k < set.operator_ids.size(); ++k) {
                auto it = profile.pair_counts.find(pair_key(set.operator_ids[i], set.operator_ids[k]));
                if (it != profile.pair_counts.end() && it->second >= 2) { any_pair = true; break; }
            }
        }
        if (!any_pair) {
            res.profile_factor += 12;
            res.profile_notes.push_back("聚合内操作员历史无协同记录（陌生协作 +12）");
        }
        // 跨域操作：操作员几乎从不接触该资产组
        int cross_domain = 0;
        for (const auto& op : set.operator_ids) {
            auto it = profile.operator_assets.find(op);
            if (it == profile.operator_assets.end()) { ++cross_domain; continue; }
            auto git = it->second.find(set.asset_group);
            if (git == it->second.end() || git->second < 2) ++cross_domain;
        }
        if (cross_domain > 0) {
            int add = std::min(cross_domain * 6, 13);
            res.profile_factor += add;
            res.profile_notes.push_back(std::to_string(cross_domain) +
                                        " 名操作员操作非日常资产组（跨域操作 +" + std::to_string(add) + "）");
        }
        // 伪造工单是强风险信号（6.5：不仅不减分，反而小幅加分）
        if (res.forged_ticket) {
            res.profile_factor += cfg.forged_ticket_bonus;
        }
        res.profile_factor = std::min(res.profile_factor, cfg.profile_max_factor);
    }

    // ---- 风险评分：total = 规则因子 + 画像因子 - 有效工单扣减，收敛 0~100 ----
    int total = res.rule_factor + res.profile_factor -
                (res.ticket_valid ? cfg.work_order_deduct : 0);
    res.total_score = std::max(0, std::min(total, 100));

    // ---- 硬约束：仅画像异常、规则零命中时，禁止触发高风险（防画像误报） ----
    if (res.rule_factor == 0 && res.total_score >= cfg.score_high) {
        res.total_score = cfg.score_high - 1;
        res.score_notes.push_back("规则零命中，画像线索不触发高风险（评分钳制）");
    }

    if (res.total_score >= cfg.score_high) res.level = "HIGH";
    else if (res.total_score >= cfg.score_mid) res.level = "MID";
    else if (res.total_score > 0) res.level = "LOW";
    else res.level = "NONE";
    return res;
}

// ---------------- Engine 单例 ----------------

Engine& Engine::instance() {
    static Engine inst;
    return inst;
}

void Engine::start(const std::string& data_dir) {
    std::lock_guard<std::mutex> lk(mutex_);
    data_dir_ = data_dir.empty() ? "data" : data_dir;
    (void)fs::create_directories(collusion_dir(data_dir_));
    (void)fs::create_directories(policy_dir(data_dir_));

    // 首次运行生成默认配置 / 规则 / 工单桩，后续热更新
    auto cfg_text = read_file_text(config_path(data_dir_));
    if (cfg_text.empty()) {
        write_file_text(config_path(data_dir_), default_config_json());
        cfg_text = default_config_json();
    }
    cfg_ = config_from_json(cfg_text);

    auto rules_text = read_file_text(rules_path(data_dir_));
    if (rules_text.empty()) {
        write_file_text(rules_path(data_dir_), default_rules_json());
        rules_text = default_rules_json();
    }
    rules_ = rules_from_json(rules_text);

    auto wo_text = read_file_text(workorders_path(data_dir_));
    if (wo_text.empty()) {
        write_file_text(workorders_path(data_dir_), default_workorders_json());
        wo_text = default_workorders_json();
    }
    workorders_ = workorders_from_json(wo_text);

    load_profile_locked();
    started_ = true;
    AF_LOG_INFO("collusion: 模块已启动 short_window=" << (cfg_.short_window_ms / 60000)
                << "min long_window=" << (cfg_.long_window_ms / 3600000)
                << "h rules=" << rules_.size()
                << " asset_groups=" << cfg_.asset_groups.size()
                << (cfg_.enabled ? "" : "（当前已禁用）"));
}

void Engine::stop() {
    std::lock_guard<std::mutex> lk(mutex_);
    if (!started_) return;
    save_profile_locked();
    profile_dirty_ = false;
    started_ = false;
    AF_LOG_INFO("collusion: 模块已停止，画像已落盘");
}

void Engine::load_profile_locked() {
    profile_ = ProfileSnapshot{};
    auto text = read_file_text(profile_path(data_dir_));
    if (text.empty()) return;
    for (const auto& rec : logpolicy::json_object_array_field(text, "pairs")) {
        auto k = logpolicy::json_string_field(rec, "key");
        if (!k.empty()) profile_.pair_counts[k] = static_cast<u64>(logpolicy::json_size_field(rec, "count", 0));
    }
    for (const auto& rec : logpolicy::json_object_array_field(text, "operator_assets")) {
        auto op = logpolicy::json_string_field(rec, "operator");
        if (op.empty()) continue;
        for (const auto& g : logpolicy::json_object_array_field(rec, "assets")) {
            auto name = logpolicy::json_string_field(g, "group");
            if (!name.empty()) {
                profile_.operator_assets[op][name] =
                    static_cast<u64>(logpolicy::json_size_field(g, "count", 0));
            }
        }
    }
}

void Engine::save_profile_locked() {
    std::ostringstream o;
    o << "{\n  \"updated_at\": \"" << iso_time_epoch(now_epoch()) << "\",\n";
    o << "  \"note\": \"操作员协作画像：滚动累计，供陌生协作/跨域操作判定\",\n";
    o << "  \"pairs\": [\n";
    bool first = true;
    for (const auto& kv : profile_.pair_counts) {
        if (!first) o << ",\n";
        first = false;
        o << "    { \"key\": \"" << json_escape(kv.first) << "\", \"count\": " << kv.second << " }";
    }
    o << "\n  ],\n  \"operator_assets\": [\n";
    first = true;
    for (const auto& okv : profile_.operator_assets) {
        if (!first) o << ",\n";
        first = false;
        o << "    { \"operator\": \"" << json_escape(okv.first) << "\", \"assets\": [";
        bool gfirst = true;
        for (const auto& gkv : okv.second) {
            if (!gfirst) o << ", ";
            gfirst = false;
            o << "{ \"group\": \"" << json_escape(gkv.first) << "\", \"count\": " << gkv.second << " }";
        }
        o << "] }";
    }
    o << "\n  ]\n}\n";
    write_file_text(profile_path(data_dir_), o.str());
}

void Engine::maybe_reload_locked(u64 now_ms) {
    // 热更新节流：每 2 秒最多检查一次配置/规则文件变化
    if (now_ms < cfg_mtime_check_ms_ + 2000) return;
    cfg_mtime_check_ms_ = now_ms;
    auto cfg_text = read_file_text(config_path(data_dir_));
    if (!cfg_text.empty()) {
        auto cand = config_from_json(cfg_text);
        if (config_to_json(cand) != config_to_json(cfg_)) {
            bool emergency_was = cfg_.emergency_mode;
            u64 until_was = cfg_.emergency_until_epoch;
            cfg_ = cand;
            // 应急状态不由配置文件覆盖写丢失（保持运行时状态优先）
            cfg_.emergency_mode = cand.emergency_mode || emergency_was;
            cfg_.emergency_until_epoch = std::max(cand.emergency_until_epoch, until_was);
            AF_LOG_INFO("collusion: 配置热更新已生效");
        }
    }
    auto rules_text = read_file_text(rules_path(data_dir_));
    if (!rules_text.empty()) {
        auto cand = rules_from_json(rules_text);
        if (rules_to_json(cand) != rules_to_json(rules_)) {
            rules_ = cand;
            AF_LOG_INFO("collusion: 规则热加载已生效 rules=" << rules_.size());
        }
    }
    auto wo_text = read_file_text(workorders_path(data_dir_));
    if (!wo_text.empty()) {
        auto cand = workorders_from_json(wo_text);
        if (workorders_to_json(cand) != workorders_to_json(workorders_)) {
            workorders_ = cand;
        }
    }
}

void Engine::append_audit_locked(const std::string& action, const std::string& detail) {
    std::ostringstream line;
    line << "{"
         << "\"timestamp\":\"" << iso_time_epoch(now_epoch()) << "\","
         << "\"action\":\"" << json_escape(action) << "\","
         << "\"detail\":\"" << json_escape(detail) << "\""
         << "}";
    auto path = audit_path(data_dir_);
    std::ofstream out(path, std::ios::binary | std::ios::app);
    if (out) out << line.str() << "\n";
}

void Engine::ingest_json(const std::string& event_json) {
    std::lock_guard<std::mutex> lk(mutex_);
    if (!started_ || !cfg_.enabled) return;
    u64 now = now_ms();
    maybe_reload_locked(now);

    CleanEvent e;
    if (!clean_event_json(event_json, e)) return;
    auto ag = match_asset_group(cfg_.asset_groups, e.res_key);
    if (ag.empty()) return;   // 未纳入任何资产组的资源不参与合谋聚合

    auto add = [&](std::map<std::string, AggSet>& m, const char* kind) {
        u64 win = (std::string(kind) == "short") ? cfg_.short_window_ms : cfg_.long_window_ms;
        u64 ws = e.ts_ms - (e.ts_ms % win);
        std::string key = ag + "|" + std::to_string(ws) + "|" + std::to_string(ws + win) + "|" + kind;
        auto& s = m[key];
        if (s.operator_ids.empty()) {
            s.aggregate_key = key;
            s.asset_group = ag;
            s.window_kind = kind;
            s.window_start_ms = ws;
            s.window_end_ms = ws + win;
        }
        if (std::find(s.operator_ids.begin(), s.operator_ids.end(), e.oper_id) == s.operator_ids.end())
            s.operator_ids.push_back(e.oper_id);
        if (!e.work_order_id.empty() &&
            std::find(s.work_order_ids.begin(), s.work_order_ids.end(), e.work_order_id) == s.work_order_ids.end())
            s.work_order_ids.push_back(e.work_order_id);
        s.events.push_back(e);
    };
    add(short_sets_, "short");
    add(long_sets_, "long");

    flush_due_locked(now);
}

int Engine::ingest_native_json(const std::string& body) {
    std::lock_guard<std::mutex> lk(mutex_);
    if (!started_ || !cfg_.enabled) return 0;
    u64 now = now_ms();
    maybe_reload_locked(now);

    int accepted = 0;
    auto objects = logpolicy::json_object_array_field(body, "events");
    if (objects.empty()) {
        // 单对象或数组直接按事件清洗（要求 oper_id 可解析）
        CleanEvent probe;
        if (clean_event_json(body, probe)) objects.push_back(body);
    }
    for (const auto& obj : objects) {
        CleanEvent e;
        if (!clean_event_json(obj, e)) continue;
        auto ag = match_asset_group(cfg_.asset_groups, e.res_key);
        if (ag.empty()) continue;
        auto add = [&](std::map<std::string, AggSet>& m, const char* kind) {
            u64 win = (std::string(kind) == "short") ? cfg_.short_window_ms : cfg_.long_window_ms;
            u64 ws = e.ts_ms - (e.ts_ms % win);
            std::string key = ag + "|" + std::to_string(ws) + "|" + std::to_string(ws + win) + "|" + kind;
            auto& s = m[key];
            if (s.operator_ids.empty()) {
                s.aggregate_key = key;
                s.asset_group = ag;
                s.window_kind = kind;
                s.window_start_ms = ws;
                s.window_end_ms = ws + win;
            }
            if (std::find(s.operator_ids.begin(), s.operator_ids.end(), e.oper_id) == s.operator_ids.end())
                s.operator_ids.push_back(e.oper_id);
            if (!e.work_order_id.empty() &&
                std::find(s.work_order_ids.begin(), s.work_order_ids.end(), e.work_order_id) == s.work_order_ids.end())
                s.work_order_ids.push_back(e.work_order_id);
            s.events.push_back(e);
        };
        add(short_sets_, "short");
        add(long_sets_, "long");
        ++accepted;
    }
    flush_due_locked(now);
    return accepted;
}

void Engine::flush_due_locked(u64 now) {
    auto flush_map = [this](std::map<std::string, AggSet>& m, u64 now) {
        for (auto it = m.begin(); it != m.end();) {
            if (it->second.window_end_ms + cfg_.flush_grace_ms <= now) {
                evaluate_locked(it->second);
                it = m.erase(it);
            } else {
                ++it;
            }
        }
    };
    flush_map(short_sets_, now);
    flush_map(long_sets_, now);
    if (profile_dirty_ && now >= profile_save_ms_ + 60000) {
        save_profile_locked();      // 画像周期性落盘（至少每分钟一次）
        profile_dirty_ = false;
        profile_save_ms_ = now;
    }
}

void Engine::update_profile_locked(const AggSet& set) {
    if (!cfg_.profile_enabled) return;
    for (std::size_t i = 0; i < set.operator_ids.size(); ++i) {
        for (std::size_t k = i + 1; k < set.operator_ids.size(); ++k) {
            profile_.pair_counts[pair_key(set.operator_ids[i], set.operator_ids[k])] += 1;
        }
        profile_.operator_assets[set.operator_ids[i]][set.asset_group] += 1;
    }
    profile_dirty_ = true;
}

void Engine::evaluate_locked(const AggSet& set) {
    // 过滤规则：集合内不同操作员 < 2 直接丢弃（单人操作交由原有单条审计处理）
    if (set.distinct_op_count() < 2) return;

    u64 now_ep = now_epoch();
    auto res = detect(set, cfg_, rules_, profile_, workorders_, now_ep);

    // 画像以本次集合为历史：先检测后更新（保证“陌生/跨域”基于此前基线判定）
    update_profile_locked(set);

    if (res.level == "NONE") return;   // 0 分无风险：直接丢弃不存储

    // 长窗口为弱关联线索：最高只记为中风险（不触发高危）
    if (set.window_kind == "long" && res.level == "HIGH") {
        res.level = "MID";
        res.score_notes.push_back("长窗口弱关联线索：等级由 HIGH 降为 MID");
    }
    // 应急运维模式：等级自动降一级（开关操作留审计日志）
    bool emergency_active = cfg_.emergency_mode &&
        (cfg_.emergency_until_epoch == 0 || now_ep <= cfg_.emergency_until_epoch);
    if (emergency_active && res.level != "LOW") {
        res.level = (res.level == "HIGH") ? "MID" : "LOW";
        res.score_notes.push_back("应急运维模式生效：等级自动降一级");
    }

    // 告警降噪：相同聚合 key 在降噪窗口内只告警一次
    u64 last = 0;
    auto it = last_alert_epoch_.find(set.aggregate_key);
    if (it != last_alert_epoch_.end()) last = it->second;
    u64 now_ms_v = now_ms();
    if (res.level != "LOW" && last && now_ms_v < last + cfg_.alert_dedup_seconds * 1000) {
        res.score_notes.push_back("同一聚合 key 告警降噪窗口内，抑制重复告警");
        return;
    }
    if (res.level != "LOW") last_alert_epoch_[set.aggregate_key] = now_ms_v;

    // ---- 构造完整风险事件（含证据链）并存储 ----
    std::string event_id = "ce-" + crypto::random_hex(8);
    std::string alert_id = "alert-" + crypto::random_hex(8);
    std::string created_iso = iso_time_epoch(now_ep);

    // 注意：events.jsonl 为 JSONL 存储，事件对象必须是紧凑单行 JSON，
    // 多行格式会被 read_jsonl 按行拆成碎片导致统计与检索错乱。
    std::ostringstream ev;
    ev << "{"
       << "\"event_id\": \"" << event_id << "\","
       << "\"alert_id\": \"" << alert_id << "\","
       << "\"created_at\": \"" << created_iso << "\","
       << "\"created_epoch\": " << now_ep << ","
       << "\"window_kind\": \"" << set.window_kind << "\","
       << "\"asset_group\": \"" << json_escape(set.asset_group) << "\","
       << "\"aggregate_key\": \"" << json_escape(set.aggregate_key) << "\","
       << "\"window_start\": \"" << iso_time_ms(set.window_start_ms) << "\","
       << "\"window_end\": \"" << iso_time_ms(set.window_end_ms) << "\","
       << "\"risk_level\": \"" << res.level << "\","
       << "\"risk_score\": " << res.total_score << ","
       << "\"rule_factor\": " << res.rule_factor << ","
       << "\"profile_factor\": " << res.profile_factor << ","
       << "\"matched_rules\": " << json_array_of_strings(res.hit_rules) << ","
       << "\"operators\": " << json_array_of_strings(set.operator_ids) << ","
       << "\"operator_count\": " << set.operator_ids.size() << ","
       << "\"work_order_ids\": " << json_array_of_strings(set.work_order_ids) << ","
       << "\"profile_notes\": " << json_array_of_strings(res.profile_notes) << ","
       << "\"score_notes\": " << json_array_of_strings(res.score_notes) << ","
       << "\"dispose\": { \"status\": \"待复核\", \"disposer\": \"\", \"note\": \"\", \"time\": \"\" },";

    // 证据时间线：按时间升序的完整操作明细
    auto sorted = set.events;
    std::sort(sorted.begin(), sorted.end(), [](const CleanEvent& a, const CleanEvent& b) {
        return a.ts_ms < b.ts_ms;
    });
    ev << "\"evidence_timeline\": [";
    for (std::size_t i = 0; i < sorted.size(); ++i) {
        const auto& e = sorted[i];
        ev << "{ \"ts\": \"" << iso_time_ms(e.ts_ms) << "\", \"ts_ms\": " << e.ts_ms
           << ", \"oper_id\": \"" << json_escape(e.oper_id)
           << "\", \"server_id\": \"" << json_escape(e.server_id)
           << "\", \"op_type\": \"" << json_escape(e.op_type)
           << "\", \"res_key\": \"" << json_escape(e.res_key)
           << "\", \"op_param\": \"" << json_escape(e.op_param) << "\" }";
        if (i + 1 < sorted.size()) ev << ",";
    }
    ev << "]}";

    // 存储分层：中高风险 180 天、低风险 90 天（按 created_epoch 秒过滤），行数上限保护
    (void)fs::create_directories(collusion_dir(data_dir_));   // 确保 JSONL 存储目录存在（ofstream 不会自动建目录）
    auto lines = read_jsonl(events_path(data_dir_));
    u64 keep_sec = (res.level == "LOW") ? 90ull * 86400 : 180ull * 86400;
    u64 cutoff_epoch = now_ep >= keep_sec ? now_ep - keep_sec : 0;
    std::vector<std::string> kept;
    kept.reserve(lines.size() + 1);
    for (const auto& l : lines) {
        u64 ce = static_cast<u64>(logpolicy::json_size_field(l, "created_epoch", 0));
        if (ce < cutoff_epoch) continue;   // 超过保存周期的历史事件清除
        kept.push_back(l);
    }
    kept.push_back(ev.str());
    if (kept.size() > kMaxStoredEvents) {
        kept.erase(kept.begin(), kept.begin() + static_cast<std::ptrdiff_t>(kept.size() - kMaxStoredEvents));
    }
    {
        std::ofstream out(events_path(data_dir_), std::ios::binary | std::ios::trunc);
        if (out) {
            for (const auto& l : kept) out << l << "\n";
        }
    }

    // 平台告警（复用现有 alerts/<host>.jsonl，可在“日志与告警”面板查看）：
    // HIGH/MID 推送；LOW 仅留存线索，不推送。
    if (res.level == "HIGH" || res.level == "MID") {
        std::string host = sorted.empty() ? "collusion" : sorted.front().server_id;
        std::string severity = res.level == "HIGH" ? "critical" : "warning";
        std::ostringstream msg;
        msg << "跨操作员合谋" << (res.level == "HIGH" ? "高风险" : "中风险")
            << "事件 " << res.level << "(" << res.total_score << "分) 资产组="
            << set.asset_group << " 操作员数=" << set.operator_ids.size();
        if (!res.hit_rules.empty()) msg << " 规则=" << res.hit_rules.front();
        std::ostringstream evidence;
        evidence << "{\"event_id\":\"" << event_id << "\",\"asset_group\":\""
                 << json_escape(set.asset_group) << "\",\"operators\":"
                 << json_array_of_strings(set.operator_ids) << ",\"matched_rules\":"
                 << json_array_of_strings(res.hit_rules) << ",\"window\":\""
                 << iso_time_ms(set.window_start_ms) << "~" << iso_time_ms(set.window_end_ms)
                 << "\"}";
        std::ostringstream aline;
        aline << "{"
              << "\"alert_id\":\"" << alert_id << "\","
              << "\"timestamp\":\"" << created_iso << "\","
              << "\"host_id\":\"" << json_escape(host) << "\","
              << "\"source\":\"collusion\","
              << "\"severity\":\"" << severity << "\","
              << "\"rule_id\":\"" << json_escape(res.hit_rules.empty() ? "profile_anomaly" : res.hit_rules.front()) << "\","
              << "\"message\":\"" << json_escape(msg.str()) << "\","
              << "\"evidence\":\"" << json_escape(evidence.str()) << "\","
              << "\"status\":\"open\""
              << "}";
        auto adir = fs::join(data_dir_.empty() ? "data" : data_dir_, "alerts");
        (void)fs::create_directories(adir);
        std::ofstream aout(fs::join(adir, host + ".jsonl"), std::ios::binary | std::ios::app);
        if (aout) aout << aline.str() << "\n";
        AF_LOG_WARN("collusion: " << msg.str() << " event_id=" << event_id);
    } else {
        AF_LOG_INFO("collusion: 低风险线索 event_id=" << event_id << " score=" << res.total_score
                    << " asset_group=" << set.asset_group);
    }
}

// ---------------- 查询 / 处置 API ----------------

std::string Engine::overview_json() {
    std::lock_guard<std::mutex> lk(mutex_);
    if (started_) {
        u64 now = now_ms();
        maybe_reload_locked(now);
        flush_due_locked(now);   // 查询时顺带冲刷到期窗口，保证展示及时
    }
    auto lines = read_jsonl(events_path(data_dir_));
    u64 high = 0, mid = 0, low = 0, pending_review = 0;
    for (const auto& l : lines) {
        auto lv = logpolicy::json_string_field(l, "risk_level");
        if (lv == "HIGH") ++high;
        else if (lv == "MID") ++mid;
        else if (lv == "LOW") ++low;
        auto st = logpolicy::json_string_field(json_object_text(l, "dispose"), "status");
        if (st.empty()) st = "待复核";
        if (st == "待复核") ++pending_review;
    }
    bool emergency_active = cfg_.emergency_mode &&
        (cfg_.emergency_until_epoch == 0 || now_epoch() <= cfg_.emergency_until_epoch);
    std::ostringstream o;
    o << "{\n"
      << "  \"enabled\": " << (cfg_.enabled ? "true" : "false") << ",\n"
      << "  \"started\": " << (started_ ? "true" : "false") << ",\n"
      << "  \"short_window_minutes\": " << (cfg_.short_window_ms / 60000) << ",\n"
      << "  \"long_window_hours\": " << (cfg_.long_window_ms / 3600000) << ",\n"
      << "  \"score_high\": " << cfg_.score_high << ",\n"
      << "  \"score_mid\": " << cfg_.score_mid << ",\n"
      << "  \"emergency_mode\": " << (emergency_active ? "true" : "false") << ",\n"
      << "  \"emergency_until\": \"" << iso_time_epoch(cfg_.emergency_until_epoch) << "\",\n"
      << "  \"rules_count\": " << rules_.size() << ",\n"
      << "  \"asset_groups_count\": " << cfg_.asset_groups.size() << ",\n"
      << "  \"profile_operators\": " << profile_.operator_assets.size() << ",\n"
      << "  \"profile_pairs\": " << profile_.pair_counts.size() << ",\n"
      << "  \"active_windows\": { \"short\": " << short_sets_.size()
      << ", \"long\": " << long_sets_.size() << " },\n"
      << "  \"event_counts\": { \"HIGH\": " << high << ", \"MID\": " << mid
      << ", \"LOW\": " << low << " },\n"
      << "  \"pending_review\": " << pending_review << "\n"
      << "}";
    return o.str();
}

std::string Engine::events_json(const std::string& level, const std::string& status, std::size_t limit) {
    std::lock_guard<std::mutex> lk(mutex_);
    auto lines = read_jsonl(events_path(data_dir_));
    std::vector<std::string> matched;
    for (auto it = lines.rbegin(); it != lines.rend(); ++it) {   // 新事件在前
        const auto& l = *it;
        if (!level.empty() && logpolicy::json_string_field(l, "risk_level") != level) continue;
        if (!status.empty()) {
            auto st = logpolicy::json_string_field(json_object_text(l, "dispose"), "status");
            if (st.empty()) st = "待复核";
            if (st != status) continue;
        }
        matched.push_back(l);
        if (limit && matched.size() >= limit) break;
    }
    std::ostringstream o;
    o << "{\n  \"count\": " << matched.size() << ",\n  \"events\": [\n";
    for (std::size_t i = 0; i < matched.size(); ++i) {
        o << "  " << matched[i];
        if (i + 1 < matched.size()) o << ",";
        o << "\n";
    }
    o << "  ]\n}";
    return o.str();
}

std::string Engine::event_detail_json(const std::string& event_id) {
    std::lock_guard<std::mutex> lk(mutex_);
    for (const auto& l : read_jsonl(events_path(data_dir_))) {
        if (logpolicy::json_string_field(l, "event_id") == event_id) return l;
    }
    return "{}";
}

std::string Engine::export_event_json(const std::string& event_id) {
    // 证据链导出：完整风险事件 JSON（含时间线、规则命中、处置记录）
    return event_detail_json(event_id);
}

bool Engine::dispose_event(const std::string& event_id, const std::string& status,
                           const std::string& disposer, const std::string& note, std::string& err) {
    static const char* kAllowed[] = { "待复核", "确认合谋攻击", "合法运维（误报）", "待进一步调查" };
    bool ok = false;
    for (auto s : kAllowed) if (status == s) { ok = true; break; }
    if (!ok) {
        err = "处置状态必须是：待复核 / 确认合谋攻击 / 合法运维（误报） / 待进一步调查";
        return false;
    }
    if (event_id.empty()) {
        err = "事件 ID 不能为空";
        return false;
    }
    std::lock_guard<std::mutex> lk(mutex_);
    auto lines = read_jsonl(events_path(data_dir_));
    bool found = false;
    std::ostringstream dispose_obj;
    dispose_obj << "{ \"status\": \"" << json_escape(status)
                << "\", \"disposer\": \"" << json_escape(disposer)
                << "\", \"note\": \"" << json_escape(note)
                << "\", \"time\": \"" << iso_time_epoch(now_epoch()) << "\" }";
    for (auto& l : lines) {
        if (logpolicy::json_string_field(l, "event_id") != event_id) continue;
        found = true;
        json_replace_object_field(l, "dispose", dispose_obj.str());
        break;
    }
    if (!found) {
        err = "风险事件不存在：" + event_id;
        return false;
    }
    {
        std::ofstream out(events_path(data_dir_), std::ios::binary | std::ios::trunc);
        if (!out) {
            err = "处置结果写盘失败";
            return false;
        }
        for (const auto& l : lines) out << l << "\n";
    }
    append_audit_locked("dispose", "event=" + event_id + " status=" + status +
                        " disposer=" + disposer + " note=" + note);
    AF_LOG_INFO("collusion: 风险事件处置 event=" << event_id << " status=" << status
                << " disposer=" << disposer);
    return true;
}

std::string Engine::config_json() {
    std::lock_guard<std::mutex> lk(mutex_);
    auto text = read_file_text(config_path(data_dir_));
    if (text.empty()) return config_to_json(cfg_);
    return text;
}

bool Engine::save_config_json(const std::string& body, std::string& err) {
    if (body.find('{') == std::string::npos) {
        err = "配置必须是 JSON 对象";
        return false;
    }
    std::lock_guard<std::mutex> lk(mutex_);
    auto cand = config_from_json(body);   // 解析失败字段自动取默认，越界值自动钳制
    if (cand.asset_groups.empty()) {
        err = "asset_groups 不能为空（至少保留一个资产组用于聚合）";
        return false;
    }
    cfg_ = cand;
    if (!write_file_text(config_path(data_dir_), config_to_json(cfg_))) {
        err = "配置写盘失败";
        return false;
    }
    append_audit_locked("config_update", "合谋检测配置已更新（热生效）");
    AF_LOG_INFO("collusion: 配置已热更新");
    return true;
}

std::string Engine::rules_json() {
    std::lock_guard<std::mutex> lk(mutex_);
    auto text = read_file_text(rules_path(data_dir_));
    if (text.empty()) return rules_to_json(rules_);
    return text;
}

bool Engine::save_rules_json(const std::string& body, std::string& err) {
    if (body.find("\"rules\"") == std::string::npos) {
        err = "规则配置必须包含 rules 数组";
        return false;
    }
    std::lock_guard<std::mutex> lk(mutex_);
    auto cand = rules_from_json(body);
    if (cand.empty()) {
        err = "rules 数组为空或格式不正确（至少保留一条有效规则）";
        return false;
    }
    rules_ = cand;
    if (!write_file_text(rules_path(data_dir_), rules_to_json(rules_))) {
        err = "规则写盘失败";
        return false;
    }
    append_audit_locked("rules_update", "检测规则已更新（热加载）");
    AF_LOG_INFO("collusion: 规则已热加载 rules=" << rules_.size());
    return true;
}

std::string Engine::workorders_json() {
    std::lock_guard<std::mutex> lk(mutex_);
    auto text = read_file_text(workorders_path(data_dir_));
    if (text.empty()) return workorders_to_json(workorders_);
    return text;
}

bool Engine::save_workorders_json(const std::string& body, std::string& err) {
    if (body.find("\"workorders\"") == std::string::npos) {
        err = "工单配置必须包含 workorders 数组";
        return false;
    }
    std::lock_guard<std::mutex> lk(mutex_);
    workorders_ = workorders_from_json(body);
    if (!write_file_text(workorders_path(data_dir_), workorders_to_json(workorders_))) {
        err = "工单写盘失败";
        return false;
    }
    append_audit_locked("workorders_update", "工单桩登记已更新（模拟外部工单系统核验数据）");
    return true;
}

std::string Engine::set_emergency(bool enabled, u64 duration_minutes, const std::string& actor) {
    std::lock_guard<std::mutex> lk(mutex_);
    cfg_.emergency_mode = enabled;
    cfg_.emergency_until_epoch = 0;
    if (enabled && duration_minutes > 0) {
        cfg_.emergency_until_epoch = now_epoch() + duration_minutes * 60;
    }
    // 持久化到配置文件（保留其余字段），重启后应急状态不丢失语义
    auto text = read_file_text(config_path(data_dir_));
    if (!text.empty()) {
        auto c = config_from_json(text);
        c.emergency_mode = cfg_.emergency_mode;
        c.emergency_until_epoch = cfg_.emergency_until_epoch;
        (void)write_file_text(config_path(data_dir_), config_to_json(c));
    }
    std::ostringstream detail;
    detail << (enabled ? "开启" : "关闭") << "应急运维模式 actor=" << actor;
    if (enabled && cfg_.emergency_until_epoch) {
        detail << " 截止=" << iso_time_epoch(cfg_.emergency_until_epoch);
    }
    append_audit_locked("emergency_mode", detail.str());
    AF_LOG_WARN("collusion: " << detail.str());

    bool active = cfg_.emergency_mode &&
        (cfg_.emergency_until_epoch == 0 || now_epoch() <= cfg_.emergency_until_epoch);
    std::ostringstream o;
    o << "{\n  \"emergency_mode\": " << (active ? "true" : "false") << ",\n"
      << "  \"until\": \"" << iso_time_epoch(cfg_.emergency_until_epoch) << "\",\n"
      << "  \"note\": \"开启后新产生的风险事件等级自动降一级，操作已留审计日志\"\n}";
    return o.str();
}

std::string Engine::report_json(int days) {
    std::lock_guard<std::mutex> lk(mutex_);
    if (days <= 0) days = 7;
    u64 now_ep = now_epoch();
    u64 from = now_ep >= static_cast<u64>(days) * 86400 ? now_ep - static_cast<u64>(days) * 86400 : 0;
    auto lines = read_jsonl(events_path(data_dir_));

    std::map<std::string, int> by_level, by_rule, by_dispose, by_day;
    int total = 0, misreports = 0, confirmed = 0;
    long long score_sum = 0;
    for (const auto& l : lines) {
        u64 ce = static_cast<u64>(logpolicy::json_size_field(l, "created_epoch", 0));
        if (ce < from) continue;
        ++total;
        score_sum += static_cast<long long>(logpolicy::json_size_field(l, "risk_score", 0));
        auto lv = logpolicy::json_string_field(l, "risk_level");
        if (!lv.empty()) ++by_level[lv];
        for (const auto& r : logpolicy::json_string_array_field(l, "matched_rules")) {
            ++by_rule[r.substr(0, 5)];   // 规则编号（R-001）
        }
        auto st = logpolicy::json_string_field(json_object_text(l, "dispose"), "status");
        if (st.empty()) st = "待复核";
        ++by_dispose[st];
        if (st == "合法运维（误报）") ++misreports;
        if (st == "确认合谋攻击") ++confirmed;
        // 按日分布（UTC 日期）
        auto iso = iso_time_epoch(ce);
        if (iso.size() >= 10) ++by_day[iso.substr(0, 10)];
    }
    std::ostringstream o;
    o << "{\n  \"days\": " << days << ",\n  \"total_events\": " << total << ",\n"
      << "  \"avg_score\": " << (total ? score_sum / total : 0) << ",\n"
      << "  \"confirmed_attacks\": " << confirmed << ",\n"
      << "  \"misreports\": " << misreports << ",\n"
      << "  \"by_level\": {";
    bool first = true;
    for (const auto& kv : by_level) {
        if (!first) o << ",";
        first = false;
        o << " \"" << kv.first << "\": " << kv.second;
    }
    o << " },\n  \"by_rule\": {";
    first = true;
    for (const auto& kv : by_rule) {
        if (!first) o << ",";
        first = false;
        o << " \"" << json_escape(kv.first) << "\": " << kv.second;
    }
    o << " },\n  \"by_dispose_status\": {";
    first = true;
    for (const auto& kv : by_dispose) {
        if (!first) o << ",";
        first = false;
        o << " \"" << json_escape(kv.first) << "\": " << kv.second;
    }
    o << " },\n  \"by_day\": {";
    first = true;
    for (const auto& kv : by_day) {
        if (!first) o << ",";
        first = false;
        o << " \"" << kv.first << "\": " << kv.second;
    }
    o << " }\n}";
    return o.str();
}

}  // namespace af::collusion
