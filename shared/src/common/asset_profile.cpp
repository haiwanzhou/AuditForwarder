#include "auditforwarder/asset_profile.h"

#include "auditforwarder/fs.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>

namespace af::asset {

// ============================================================================
// 枚举字符串转换
// ============================================================================
const char* to_string(AccessMode m) noexcept {
    switch (m) {
        case AccessMode::Http:     return "http";
        case AccessMode::Db:       return "db";
        case AccessMode::Terminal: return "terminal";
        case AccessMode::Unknown:  return "unknown";
    }
    return "unknown";
}

AccessMode access_mode_from_string(const std::string& s) noexcept {
    std::string v;
    v.reserve(s.size());
    for (unsigned char c : s) v.push_back(static_cast<char>(std::tolower(c)));
    if (v == "http" || v == "web" || v == "https" || v == "api") return AccessMode::Http;
    if (v == "db" || v == "database" || v == "sql" || v == "mysql" || v == "postgres") return AccessMode::Db;
    if (v == "terminal" || v == "shell" || v == "ssh" || v == "bastion") return AccessMode::Terminal;
    return AccessMode::Unknown;
}

const char* to_string(ResourceType t) noexcept {
    switch (t) {
        case ResourceType::DataRecord: return "data_record";
        case ResourceType::Table:      return "table";
        case ResourceType::Backup:     return "backup";
        case ResourceType::Credential: return "credential";
        case ResourceType::Config:     return "config";
        case ResourceType::Log:        return "log";
        case ResourceType::System:     return "system";
        case ResourceType::Other:      return "other";
    }
    return "other";
}

ResourceType resource_type_from_string(const std::string& s) noexcept {
    std::string v;
    v.reserve(s.size());
    for (unsigned char c : s) v.push_back(static_cast<char>(std::tolower(c)));
    if (v == "data_record" || v == "data" || v == "record" || v == "row" || v == "business") return ResourceType::DataRecord;
    if (v == "table" || v == "db_table" || v == "collection") return ResourceType::Table;
    if (v == "backup" || v == "snapshot" || v == "dump") return ResourceType::Backup;
    if (v == "credential" || v == "secret" || v == "key" || v == "password") return ResourceType::Credential;
    if (v == "config" || v == "configuration" || v == "admin") return ResourceType::Config;
    if (v == "log" || v == "audit_log" || v == "trace") return ResourceType::Log;
    if (v == "system" || v == "host" || v == "os" || v == "disk" || v == "service") return ResourceType::System;
    return ResourceType::Other;
}

const char* to_string(Sensitivity s) noexcept {
    switch (s) {
        case Sensitivity::Public:       return "public";
        case Sensitivity::Internal:     return "internal";
        case Sensitivity::Confidential: return "confidential";
        case Sensitivity::Secret:       return "secret";
    }
    return "internal";
}

Sensitivity sensitivity_from_string(const std::string& s) noexcept {
    std::string v;
    v.reserve(s.size());
    for (unsigned char c : s) v.push_back(static_cast<char>(std::tolower(c)));
    if (v == "public" || v == "low" || v == "0") return Sensitivity::Public;
    if (v == "internal" || v == "medium" || v == "1") return Sensitivity::Internal;
    if (v == "confidential" || v == "high" || v == "2") return Sensitivity::Confidential;
    if (v == "secret" || v == "critical" || v == "3") return Sensitivity::Secret;
    return Sensitivity::Internal;
}

// ============================================================================
// 工具函数
// ============================================================================
namespace {

std::string lower_copy(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string json_escape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\b': o += "\\b";  break;
            case '\f': o += "\\f";  break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            default:
                if (c < 0x20) {
                    static const char* hex = "0123456789abcdef";
                    o += "\\u00";
                    o += hex[(c >> 4) & 0xF];
                    o += hex[c & 0xF];
                } else {
                    o.push_back(static_cast<char>(c));
                }
        }
    }
    return o;
}

std::vector<std::string> string_list(const ConfigValue& node) {
    std::vector<std::string> out;
    if (node.type() != ConfigValue::Type::List) return out;
    for (const auto& item : node.as_list()) {
        auto v = item.as_string();
        if (!v.empty()) out.push_back(std::move(v));
    }
    return out;
}

std::string join_string_list(const std::vector<std::string>& items) {
    std::string o = "[";
    for (std::size_t i = 0; i < items.size(); ++i) {
        if (i) o += ',';
        o += '"';
        o += json_escape(items[i]);
        o += '"';
    }
    o += ']';
    return o;
}

bool read_file(const std::string& path, std::string& out) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    std::ostringstream ss;
    ss << in.rdbuf();
    out = ss.str();
    return true;
}

}  // namespace

bool wildcard_match(const std::string& pattern, const std::string& text) {
    const std::string p = lower_copy(pattern);
    const std::string t = lower_copy(text);
    std::size_t pi = 0, ti = 0, star = std::string::npos, mark = 0;
    while (ti < t.size()) {
        if (pi < p.size() && (p[pi] == '?' || p[pi] == t[ti])) {
            ++pi;
            ++ti;
        } else if (pi < p.size() && p[pi] == '*') {
            star = pi++;
            mark = ti;
        } else if (star != std::string::npos) {
            pi = star + 1;
            ti = ++mark;
        } else {
            return false;
        }
    }
    while (pi < p.size() && p[pi] == '*') ++pi;
    return pi == p.size();
}

// ============================================================================
// AssetProfile
// ============================================================================
const RoleBaseline* AssetProfile::find_role(const std::string& role) const {
    const auto want = lower_copy(role);
    for (const auto& rb : roles) {
        if (lower_copy(rb.role) == want) return &rb;
    }
    return nullptr;
}

std::string AssetProfile::role_of(const std::string& operator_id) const {
    auto it = operator_roles.find(operator_id);
    return it == operator_roles.end() ? std::string() : it->second;
}

// ============================================================================
// YAML 解析
// ============================================================================
Result<AssetProfile> parse_asset_profile(const std::string& yaml, const std::string& source) {
    ConfigValue root;
    auto parsed = parse_minimal_yaml(yaml, root);
    if (parsed.is_err()) {
        return Result<AssetProfile>(Error::Code::Parse,
                                    "资产画像 YAML 解析失败：" + parsed.error().message());
    }
    if (root.type() != ConfigValue::Type::Map) {
        return Result<AssetProfile>(Error::Code::Parse, "资产画像必须是 YAML 映射结构");
    }

    AssetProfile p;
    p.source       = source;
    p.system_id    = root["system_id"].as_string();
    p.display_name = root["display_name"].as_string();
    if (p.system_id.empty()) {
        return Result<AssetProfile>(Error::Code::Parse, "资产画像缺少 system_id");
    }
    if (p.display_name.empty()) p.display_name = p.system_id;

    p.access_mode = access_mode_from_string(root["access_mode"].as_string());
    p.target_systems = string_list(root["target_systems"]);
    if (root.has("default_sensitivity")) {
        p.default_sensitivity = sensitivity_from_string(root["default_sensitivity"].as_string());
    }
    if (root.has("default_resource_type")) {
        p.default_resource_type = resource_type_from_string(root["default_resource_type"].as_string());
    }

    for (const auto& item : root["resources"].as_list()) {
        ResourceRule rule;
        rule.pattern = item["pattern"].as_string();
        if (rule.pattern.empty()) continue;
        rule.type = resource_type_from_string(item["type"].as_string());
        rule.sensitivity = item.has("sensitivity")
                               ? sensitivity_from_string(item["sensitivity"].as_string())
                               : p.default_sensitivity;
        p.resources.push_back(std::move(rule));
    }

    for (const auto& item : root["roles"].as_list()) {
        RoleBaseline rb;
        rb.role = item["role"].as_string();
        if (rb.role.empty()) continue;
        rb.allowed_actions = string_list(item["allowed_actions"]);
        rb.denied_actions  = string_list(item["denied_actions"]);
        p.roles.push_back(std::move(rb));
    }

    for (const auto& [op, role] : root["operator_roles"].as_map()) {
        auto role_name = role.as_string();
        if (op.empty() || role_name.empty()) continue;
        p.operator_roles[op] = std::move(role_name);
    }

    return p;
}

// ============================================================================
// AssetProfileRegistry
// ============================================================================
std::size_t AssetProfileRegistry::load_directory(const std::string& dir,
                                                 std::vector<std::string>* errors) {
    if (dir.empty()) return 0;
    auto listed = fs::list_directory(dir);
    if (listed.is_err()) {
        if (errors) errors->push_back("无法读取资产画像目录：" + dir);
        return 0;
    }
    std::size_t loaded = 0;
    for (const auto& path : listed.value()) {
        auto ext = fs::extension(path);
        if (ext != ".yaml" && ext != ".yml") continue;
        std::string text;
        if (!read_file(path, text)) {
            if (errors) errors->push_back("无法读取资产画像文件：" + path);
            continue;
        }
        auto r = add_yaml(text, path);
        if (r.is_err()) {
            if (errors) errors->push_back(path + "：" + r.error().message());
            continue;
        }
        ++loaded;
    }
    return loaded;
}

Result<void> AssetProfileRegistry::add_yaml(const std::string& yaml, const std::string& source) {
    auto parsed = parse_asset_profile(yaml, source);
    if (parsed.is_err()) return Result<void>(parsed.error());
    AssetProfile p = std::move(parsed).value();
    // 同一 system_id 覆盖旧画像，便于热加载
    for (auto& existing : profiles_) {
        if (lower_copy(existing.system_id) == lower_copy(p.system_id)) {
            existing = std::move(p);
            return Result<void>::ok();
        }
    }
    profiles_.push_back(std::move(p));
    return Result<void>::ok();
}

const AssetProfile* AssetProfileRegistry::find_system(const std::string& system_id) const {
    if (system_id.empty()) return nullptr;
    const auto want = lower_copy(system_id);
    for (const auto& p : profiles_) {
        if (lower_copy(p.system_id) == want) return &p;
    }
    return nullptr;
}

const AssetProfile* AssetProfileRegistry::find_for_target(const std::string& target_system) const {
    if (target_system.empty()) return nullptr;
    const auto want = lower_copy(target_system);
    // 先按系统标识匹配，再按 target_systems 别名匹配
    if (auto* p = find_system(target_system)) return p;
    for (const auto& p : profiles_) {
        for (const auto& alias : p.target_systems) {
            if (lower_copy(alias) == want) return &p;
        }
    }
    return nullptr;
}

ResourceMatch AssetProfileRegistry::classify(const AssetProfile& profile,
                                             const std::string& object) const {
    ResourceMatch match;
    for (const auto& rule : profile.resources) {
        if (wildcard_match(rule.pattern, object)) {
            match.matched     = true;
            match.type        = rule.type;
            match.sensitivity = rule.sensitivity;
            match.pattern     = rule.pattern;
            return match;
        }
    }
    match.type        = profile.default_resource_type;
    match.sensitivity = profile.default_sensitivity;
    return match;
}

ActionVerdict AssetProfileRegistry::check_action(const AssetProfile& profile,
                                                 const std::string& role,
                                                 const std::string& action) const {
    ActionVerdict v;
    v.role = role;
    const RoleBaseline* rb = profile.find_role(role);
    if (!rb) {
        v.verdict = RoleVerdict::UnknownRole;
        v.reason  = "unknown_role";
        return v;
    }
    for (const auto& pat : rb->denied_actions) {
        if (wildcard_match(pat, action)) {
            v.verdict = RoleVerdict::Denied;
            v.reason  = "denied_action:" + pat;
            return v;
        }
    }
    for (const auto& pat : rb->allowed_actions) {
        if (wildcard_match(pat, action)) {
            v.verdict = RoleVerdict::Allowed;
            v.reason  = "allowed_action:" + pat;
            return v;
        }
    }
    v.verdict = RoleVerdict::Denied;
    v.reason  = "not_in_allowed_actions";
    return v;
}

ActionVerdict AssetProfileRegistry::check_operator_action(const AssetProfile& profile,
                                                          const std::string& operator_id,
                                                          const std::string& action) const {
    const auto role = profile.role_of(operator_id);
    if (role.empty()) {
        ActionVerdict v;
        v.verdict = RoleVerdict::UnknownRole;
        v.reason  = "unknown_operator_role";
        return v;
    }
    return check_action(profile, role, action);
}

// ============================================================================
// JSON 输出
// ============================================================================
std::string to_json(const AssetProfile& profile) {
    std::ostringstream o;
    o << "{"
      << "\"system_id\":\"" << json_escape(profile.system_id) << "\","
      << "\"display_name\":\"" << json_escape(profile.display_name) << "\","
      << "\"access_mode\":\"" << to_string(profile.access_mode) << "\","
      << "\"target_systems\":" << join_string_list(profile.target_systems) << ","
      << "\"default_sensitivity\":\"" << to_string(profile.default_sensitivity) << "\","
      << "\"default_sensitivity_level\":" << static_cast<int>(profile.default_sensitivity) << ","
      << "\"default_resource_type\":\"" << to_string(profile.default_resource_type) << "\","
      << "\"resources\":[";
    for (std::size_t i = 0; i < profile.resources.size(); ++i) {
        const auto& r = profile.resources[i];
        if (i) o << ',';
        o << "{\"pattern\":\"" << json_escape(r.pattern) << "\","
          << "\"type\":\"" << to_string(r.type) << "\","
          << "\"sensitivity\":\"" << to_string(r.sensitivity) << "\","
          << "\"level\":" << static_cast<int>(r.sensitivity) << '}';
    }
    o << "],\"roles\":[";
    for (std::size_t i = 0; i < profile.roles.size(); ++i) {
        const auto& rb = profile.roles[i];
        if (i) o << ',';
        o << "{\"role\":\"" << json_escape(rb.role) << "\","
          << "\"allowed_actions\":" << join_string_list(rb.allowed_actions) << ","
          << "\"denied_actions\":" << join_string_list(rb.denied_actions) << '}';
    }
    o << "],\"operator_roles\":{";
    bool first = true;
    for (const auto& [op, role] : profile.operator_roles) {
        if (!first) o << ',';
        first = false;
        o << '"' << json_escape(op) << "\":\"" << json_escape(role) << '"';
    }
    o << "},\"source\":\"" << json_escape(profile.source) << "\"}";
    return o.str();
}

std::string AssetProfileRegistry::to_json() const {
    std::ostringstream o;
    o << "{\"count\":" << profiles_.size() << ",\"profiles\":[";
    for (std::size_t i = 0; i < profiles_.size(); ++i) {
        if (i) o << ',';
        o << af::asset::to_json(profiles_[i]);
    }
    o << "]}";
    return o.str();
}

}  // namespace af::asset
