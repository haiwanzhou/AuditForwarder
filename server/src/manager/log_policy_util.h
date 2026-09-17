#pragma once

// 日志过滤策略档（strict / lenient）的纯逻辑工具：
// 不依赖 ManagerConfig / 文件系统，便于单元测试直接覆盖。
// manager_server.cpp 中的 resolve/apply 逻辑复用本头文件实现。

#include <cctype>
#include <cstddef>
#include <string>
#include <vector>

namespace af {
namespace logpolicy {

inline constexpr const char* kEtwCollector = "etw_win";
inline constexpr const char* kModeStrict   = "strict";
inline constexpr const char* kModeLenient  = "lenient";

struct Profile {
    std::string              collector {"default"};
    std::string              mode {"strict"};      // strict | lenient
    std::size_t              message_max_len {512};
    std::vector<std::string> drop_fields;          // strict 下丢弃（可命中 attrs 嵌套字段）
    std::size_t              retention_lines {50000};
};

inline std::string default_profiles_json() {
    return "{\n"
           "  \"profiles\": [\n"
           "    { \"collector\": \"etw_win\", \"mode\": \"lenient\", \"message_max_len\": 8192,\n"
           "      \"drop_fields\": [], \"retention_lines\": 50000,\n"
           "      \"note\": \"ETW 安全日志宽松档：保留全部原始字段（含 raw_xml），不做内容截断\" },\n"
           "    { \"collector\": \"default\", \"mode\": \"strict\", \"message_max_len\": 512,\n"
           "      \"drop_fields\": [\"raw_xml\"], \"retention_lines\": 50000,\n"
           "      \"note\": \"其他采集器严格档：丢弃原始载荷字段并截断长消息\" }\n"
           "  ]\n"
           "}";
}

// ---------------- 最小化 JSON 扫描（与 manager_server 内部实现保持同一语义） ----------------

inline std::string json_unescape_value(const std::string& raw) {
    std::string out;
    out.reserve(raw.size());
    for (std::size_t i = 0; i < raw.size(); ++i) {
        if (raw[i] != '\\' || i + 1 >= raw.size()) { out.push_back(raw[i]); continue; }
        char n = raw[++i];
        switch (n) {
            case 'n':  out.push_back('\n'); break;
            case 't':  out.push_back('\t'); break;
            case 'r':  out.push_back('\r'); break;
            case 'b':  out.push_back('\b'); break;
            case 'f':  out.push_back('\f'); break;
            case '"':  out.push_back('"');  break;
            case '\\': out.push_back('\\'); break;
            case '/':  out.push_back('/');  break;
            default:   out.push_back('\\'); out.push_back(n); break;
        }
    }
    return out;
}

inline std::string json_string_field(const std::string& json, const std::string& key) {
    const std::string marker = "\"" + key + "\"";
    auto p = json.find(marker);
    if (p == std::string::npos) return {};
    p = json.find(':', p + marker.size());
    if (p == std::string::npos) return {};
    p = json.find('"', p + 1);
    if (p == std::string::npos) return {};
    std::string raw;
    bool esc = false;
    for (++p; p < json.size(); ++p) {
        char c = json[p];
        if (esc) { raw.push_back('\\'); raw.push_back(c); esc = false; continue; }
        if (c == '\\') { esc = true; continue; }
        if (c == '"') break;
        raw.push_back(c);
    }
    return json_unescape_value(raw);
}

inline std::size_t json_size_field(const std::string& json, const std::string& key, std::size_t def) {
    const std::string marker = "\"" + key + "\"";
    auto p = json.find(marker);
    if (p == std::string::npos) return def;
    p = json.find(':', p + marker.size());
    if (p == std::string::npos) return def;
    ++p;
    while (p < json.size() && std::isspace(static_cast<unsigned char>(json[p]))) ++p;
    std::size_t value = 0;
    bool any = false;
    while (p < json.size() && std::isdigit(static_cast<unsigned char>(json[p]))) {
        any = true;
        value = value * 10 + static_cast<std::size_t>(json[p] - '0');
        ++p;
    }
    return any ? value : def;
}

inline std::vector<std::string> json_string_array_field(const std::string& json, const std::string& key) {
    std::vector<std::string> values;
    const std::string marker = "\"" + key + "\"";
    auto p = json.find(marker);
    if (p == std::string::npos) return values;
    p = json.find(':', p + marker.size());
    if (p == std::string::npos) return values;
    p = json.find('[', p + 1);
    if (p == std::string::npos) return values;
    for (++p; p < json.size(); ++p) {
        while (p < json.size() && std::isspace(static_cast<unsigned char>(json[p]))) ++p;
        if (p >= json.size() || json[p] == ']') break;
        if (json[p] != '"') continue;
        std::string raw;
        bool esc = false;
        for (++p; p < json.size(); ++p) {
            char c = json[p];
            if (esc) { raw.push_back('\\'); raw.push_back(c); esc = false; continue; }
            if (c == '\\') { esc = true; continue; }
            if (c == '"') break;
            raw.push_back(c);
        }
        values.push_back(json_unescape_value(raw));
    }
    return values;
}

inline std::vector<std::string> json_object_array_field(const std::string& json, const std::string& key) {
    std::vector<std::string> objects;
    const std::string marker = "\"" + key + "\"";
    auto p = json.find(marker);
    if (p == std::string::npos) return objects;
    p = json.find('[', p + marker.size());
    if (p == std::string::npos) return objects;
    bool in_string = false;
    bool esc = false;
    int depth = 0;
    std::size_t start = std::string::npos;
    for (; p < json.size(); ++p) {
        char c = json[p];
        if (in_string) {
            if (esc) esc = false;
            else if (c == '\\') esc = true;
            else if (c == '"') in_string = false;
            continue;
        }
        if (c == '"') {
            in_string = true;
        } else if (c == '{') {
            if (depth == 0) start = p;
            ++depth;
        } else if (c == '}') {
            --depth;
            if (depth == 0 && start != std::string::npos) {
                objects.push_back(json.substr(start, p - start + 1));
                start = std::string::npos;
            }
        } else if (c == ']' && depth == 0) {
            break;
        }
    }
    return objects;
}

// ---------------- 字段删除 / 消息截断 / 策略应用 ----------------

// 删除 JSON 文本中某个 "key":value 字段（字符串值按转义感知扫描），可命中嵌套对象。
inline std::string json_remove_field(const std::string& s, const std::string& key) {
    const std::string pat = "\"" + key + "\"";
    auto p = s.find(pat);
    if (p == std::string::npos) return s;
    std::size_t q = p + pat.size();
    while (q < s.size() && (s[q] == ' ' || s[q] == '\t')) ++q;
    if (q >= s.size() || s[q] != ':') return s;
    ++q;
    while (q < s.size() && (s[q] == ' ' || s[q] == '\t')) ++q;
    std::size_t end = q;
    if (q < s.size() && s[q] == '"') {
        ++q;
        while (q < s.size()) {
            if (s[q] == '\\') { q += 2; continue; }
            if (s[q] == '"') break;
            ++q;
        }
        end = q + 1;
    } else {
        while (end < s.size() && s[end] != ',' && s[end] != '}' && s[end] != ']') ++end;
    }
    if (end < s.size() && s[end] == ',') {
        ++end;
    } else if (p > 0 && s[p - 1] == ',') {
        --p;
    }
    return s.substr(0, p) + s.substr(end);
}

// 截断某字符串字段到 max_len 个「逻辑字符」（转义序列整体保留，不破坏 JSON）。
inline std::string json_truncate_string_field(const std::string& s,
                                              const std::string& key,
                                              std::size_t max_len) {
    const std::string pat = "\"" + key + "\"";
    auto p = s.find(pat);
    if (p == std::string::npos) return s;
    std::size_t q = p + pat.size();
    while (q < s.size() && (s[q] == ' ' || s[q] == '\t')) ++q;
    if (q >= s.size() || s[q] != ':') return s;
    ++q;
    while (q < s.size() && (s[q] == ' ' || s[q] == '\t')) ++q;
    if (q >= s.size() || s[q] != '"') return s;
    const std::size_t val_begin = q + 1;
    std::size_t i = val_begin;
    std::size_t logical = 0;
    std::size_t cut = std::string::npos;
    while (i < s.size()) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            if (logical < max_len) cut = i + 2;   // 保留完整转义序列
            i += 2;
        } else if (s[i] == '"') {
            break;
        } else {
            ++logical;
            if (logical <= max_len) cut = i + 1;
            ++i;
        }
    }
    if (i >= s.size() || cut == std::string::npos) return s;
    if (i == cut) return s;  // 未超长
    return s.substr(0, cut) + s.substr(i);
}

inline std::string apply_profile(const std::string& item, const Profile& prof) {
    std::string out = item;
    if (prof.mode == kModeStrict) {
        for (const auto& field : prof.drop_fields) out = json_remove_field(out, field);
    }
    // lenient 仅在超大上限处截断；strict 使用小上限
    if (prof.message_max_len > 0)
        out = json_truncate_string_field(out, "message", prof.message_max_len);
    return out;
}

// 从策略 JSON 文本解析单个采集器的生效策略：
// 精确 collector 命中优先，其次 default 兜底；配置缺失时 etw_win 内置宽松、其余内置严格。
inline Profile resolve_profile_json(const std::string& raw_json, const std::string& collector) {
    Profile prof;
    prof.collector = collector;
    Profile default_prof;  // collector == "default"
    bool has_default = false;
    for (const auto& rec : json_object_array_field(raw_json, "profiles")) {
        const std::string c = json_string_field(rec, "collector");
        if (c != collector && c != "default") continue;
        Profile cand;
        cand.collector = c;
        cand.mode = json_string_field(rec, "mode");
        if (cand.mode.empty()) cand.mode = kModeStrict;
        cand.message_max_len = json_size_field(rec, "message_max_len", cand.message_max_len);
        cand.retention_lines = json_size_field(rec, "retention_lines", cand.retention_lines);
        cand.drop_fields = json_string_array_field(rec, "drop_fields");
        if (c == collector) return cand;  // 精确命中
        default_prof = cand;
        has_default = true;
    }
    if (has_default) return default_prof;
    if (collector == kEtwCollector) {
        Profile etw;
        etw.collector = kEtwCollector;
        etw.mode = kModeLenient;
        etw.message_max_len = 8192;
        etw.retention_lines = 50000;
        return etw;
    }
    return Profile{};
}

}  // namespace logpolicy
}  // namespace af
