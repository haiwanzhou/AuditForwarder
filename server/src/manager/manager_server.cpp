#include "auditforwarder/manager.h"

#include "auditforwarder/config.h"
#include "auditforwarder/crypto.h"
#include "auditforwarder/fs.h"
#include "auditforwarder/log_meta.h"
#include "log_policy_util.h"
#include "auditforwarder/logger.h"
#include "auditforwarder/process.h"

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <ctime>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <thread>
#include <vector>

#include <openssl/err.h>
#include <openssl/ssl.h>

#ifdef AF_PLATFORM_UNIX
#  include <arpa/inet.h>
#  include <fcntl.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <unistd.h>
#endif
#ifdef AF_PLATFORM_WINDOWS
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  pragma comment(lib, "ws2_32.lib")
#  define close closesocket
#endif

namespace af {

namespace {
std::string url_decode(const std::string& s) {
    std::string o; o.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c == '+') o.push_back(' ');
        else if (c == '%' && i + 2 < s.size()) {
            char hi = s[i + 1], lo = s[i + 2];
            auto h = [](char x) {
                if (x >= '0' && x <= '9') return x - '0';
                if (x >= 'a' && x <= 'f') return x - 'a' + 10;
                if (x >= 'A' && x <= 'F') return x - 'A' + 10;
                return 0;
            };
            o.push_back(static_cast<char>((h(hi) << 4) | h(lo)));
            i += 2;
        } else o.push_back(c);
    }
    return o;
}
std::string status_text(int code) {
    switch (code) {
        case 200: return "OK";
        case 202: return "Accepted";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 409: return "Conflict";
        case 429: return "Too Many Requests";
        case 422: return "Unprocessable Entity";
        case 500: return "Internal Server Error";
        case 503: return "Service Unavailable";
    }
    return "OK";
}

bool starts_with(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

bool is_ui_path(const std::string& path) {
    return path == "/" || path == "/ui" || path == "/ui/" ||
           path == "/index.html" || starts_with(path, "/assets/");
}

bool is_public_path(const std::string& path) {
    return is_ui_path(path) || path == "/auth/login";
}

std::string content_type_for(const std::string& path) {
    if (path == "/" || path == "/ui" || path == "/ui/" || path == "/index.html") {
        return "text/html; charset=utf-8";
    }
    if (path.size() >= 4 && path.substr(path.size() - 4) == ".css") {
        return "text/css; charset=utf-8";
    }
    if (path.size() >= 3 && path.substr(path.size() - 3) == ".js") {
        return "application/javascript; charset=utf-8";
    }
    if (path.size() >= 4 && path.substr(path.size() - 4) == ".svg") {
        return "image/svg+xml";
    }
    return "application/octet-stream";
}

std::string ui_relative_path(const std::string& path) {
    if (path == "/" || path == "/ui" || path == "/ui/" || path == "/index.html") {
        return "server/web/index.html";
    }
    if (starts_with(path, "/assets/")) {
        std::string rel = path.substr(1);
        if (rel.find("..") != std::string::npos || rel.find('\\') != std::string::npos) return {};
        return "server/web/" + rel;
    }
    return {};
}

std::string peer_ip(int fd) {
    sockaddr_storage addr {};
    socklen_t len = sizeof(addr);
    if (getpeername(fd, reinterpret_cast<sockaddr*>(&addr), &len) != 0) return "unknown";
    char buf[INET6_ADDRSTRLEN] {};
    if (addr.ss_family == AF_INET) {
        auto* a = reinterpret_cast<sockaddr_in*>(&addr);
        if (inet_ntop(AF_INET, &a->sin_addr, buf, sizeof(buf))) return buf;
    } else if (addr.ss_family == AF_INET6) {
        auto* a = reinterpret_cast<sockaddr_in6*>(&addr);
        if (inet_ntop(AF_INET6, &a->sin6_addr, buf, sizeof(buf))) return buf;
    }
    return "unknown";
}

Result<std::string> read_text_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return Result<std::string>(Error::Code::NotFound, path);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

Result<std::string> read_ui_asset(const std::string& request_path) {
    auto rel = ui_relative_path(request_path);
    if (rel.empty()) return Result<std::string>(Error::Code::NotFound, request_path);

    // 支持从项目根目录运行，也支持从 build 目录运行调试。
    auto direct = read_text_file(rel);
    if (direct.is_ok()) return direct;
    auto parent = read_text_file("../" + rel);
    if (parent.is_ok()) return parent;
    return direct;
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

std::string json_unescape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c != '\\' || i + 1 >= s.size()) {
            out.push_back(c);
            continue;
        }
        char n = s[++i];
        switch (n) {
            case '"': out.push_back('"'); break;
            case '\\': out.push_back('\\'); break;
            case '/': out.push_back('/'); break;
            case 'b': out.push_back('\b'); break;
            case 'f': out.push_back('\f'); break;
            case 'n': out.push_back('\n'); break;
            case 'r': out.push_back('\r'); break;
            case 't': out.push_back('\t'); break;
            default:
                out.push_back('\\');
                out.push_back(n);
                break;
        }
    }
    return out;
}

std::string json_string_field(const std::string& json, const std::string& key) {
    auto marker = "\"" + key + "\"";
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
        if (esc) {
            raw.push_back('\\');
            raw.push_back(c);
            esc = false;
            continue;
        }
        if (c == '\\') {
            esc = true;
            continue;
        }
        if (c == '"') break;
        raw.push_back(c);
    }
    return json_unescape(raw);
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

// 提取 JSON 中某个数组字段的原文（含方括号），如 "collectors":[...]。
// 仅用于原样透传采集器状态，不做完整解析。
std::string json_array_text(const std::string& json, const std::string& key) {
    auto marker = "\"" + key + "\"";
    auto p = json.find(marker);
    if (p == std::string::npos) return {};
    p = json.find(':', p + marker.size());
    if (p == std::string::npos) return {};
    p = json.find('[', p + 1);
    if (p == std::string::npos) return {};
    int depth = 0;
    bool in_str = false;
    bool esc = false;
    for (std::size_t i = p; i < json.size(); ++i) {
        char c = json[i];
        if (in_str) {
            if (esc) esc = false;
            else if (c == '\\') esc = true;
            else if (c == '"') in_str = false;
            continue;
        }
        if (c == '"') { in_str = true; continue; }
        if (c == '[') ++depth;
        else if (c == ']') {
            --depth;
            if (depth == 0) return json.substr(p, i - p + 1);
        }
    }
    return {};
}

std::size_t json_size_field(const std::string& json, const std::string& key, std::size_t def) {
    auto marker = "\"" + key + "\"";
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

std::vector<std::string> json_string_array_field(const std::string& json, const std::string& key) {
    std::vector<std::string> values;
    auto marker = "\"" + key + "\"";
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
            if (esc) {
                raw.push_back('\\');
                raw.push_back(c);
                esc = false;
                continue;
            }
            if (c == '\\') {
                esc = true;
                continue;
            }
            if (c == '"') break;
            raw.push_back(c);
        }
        values.push_back(json_unescape(raw));
    }
    return values;
}

u64 json_u64_field(const std::string& json, const std::string& key, u64 def = 0) {
    auto marker = "\"" + key + "\"";
    auto p = json.find(marker);
    if (p == std::string::npos) return def;
    p = json.find(':', p + marker.size());
    if (p == std::string::npos) return def;
    ++p;
    while (p < json.size() && std::isspace(static_cast<unsigned char>(json[p]))) ++p;
    u64 value = 0;
    bool any = false;
    while (p < json.size() && std::isdigit(static_cast<unsigned char>(json[p]))) {
        any = true;
        value = value * 10 + static_cast<u64>(json[p] - '0');
        ++p;
    }
    return any ? value : def;
}

double json_number_field(const std::string& json, const std::string& key, double def = 0.0) {
    auto marker = "\"" + key + "\"";
    auto p = json.find(marker);
    if (p == std::string::npos) return def;
    p = json.find(':', p + marker.size());
    if (p == std::string::npos) return def;
    ++p;
    while (p < json.size() && std::isspace(static_cast<unsigned char>(json[p]))) ++p;
    std::size_t end = p;
    if (end < json.size() && (json[end] == '-' || json[end] == '+')) ++end;
    bool any = false;
    while (end < json.size() &&
           (std::isdigit(static_cast<unsigned char>(json[end])) || json[end] == '.')) {
        any = true;
        ++end;
    }
    if (!any) return def;
    try {
        return std::stod(json.substr(p, end - p));
    } catch (...) {
        return def;
    }
}

double json_nested_number_field(const std::string& json,
                                const std::string& object_key,
                                const std::string& number_key,
                                double def = 0.0) {
    auto marker = "\"" + object_key + "\"";
    auto p = json.find(marker);
    if (p == std::string::npos) return def;
    auto start = json.find('{', p + marker.size());
    if (start == std::string::npos) return def;
    bool in_string = false;
    bool esc = false;
    int depth = 0;
    for (std::size_t i = start; i < json.size(); ++i) {
        char c = json[i];
        if (in_string) {
            if (esc) esc = false;
            else if (c == '\\') esc = true;
            else if (c == '"') in_string = false;
            continue;
        }
        if (c == '"') in_string = true;
        else if (c == '{') ++depth;
        else if (c == '}') {
            --depth;
            if (depth == 0) {
                return json_number_field(json.substr(start, i - start + 1), number_key, def);
            }
        }
    }
    return def;
}

std::mutex& host_store_mutex() {
    static std::mutex m;
    return m;
}

int conn_recv(int fd, void* tls, char* buf, int len) {
    if (tls) return SSL_read(static_cast<SSL*>(tls), buf, len);
    return ::recv(fd, buf, len, 0);
}

int conn_send(int fd, void* tls, const char* buf, int len) {
    if (tls) return SSL_write(static_cast<SSL*>(tls), buf, len);
    return ::send(fd, buf, len, 0);
}

std::string query_param(const std::string& query, const std::string& key) {
    std::size_t pos = 0;
    while (pos <= query.size()) {
        auto amp = query.find('&', pos);
        auto part = query.substr(pos, amp == std::string::npos ? std::string::npos : amp - pos);
        auto eq = part.find('=');
        auto k = url_decode(eq == std::string::npos ? part : part.substr(0, eq));
        if (k == key) return url_decode(eq == std::string::npos ? "" : part.substr(eq + 1));
        if (amp == std::string::npos) break;
        pos = amp + 1;
    }
    return {};
}

u64 epoch_seconds() {
    return static_cast<u64>(std::time(nullptr));
}

std::string iso_time(u64 epoch) {
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

struct HostRecord {
    std::string id;
    std::string name;
    std::string ip_address;
    std::string hardware;
    std::string os_version;
    std::string network_status;
    std::string note;
    std::vector<std::string> permissions;
    u64 last_seen_epoch { 0 };
    u64 cpu_usage_percent { 0 };
    u64 memory_usage_percent { 0 };
    // 最近一次心跳上报的采集器状态，JSON 数组原文：[{"name":"file_win","running":true}]
    std::string collectors_state;
};

struct ValidationIssue {
    std::string field;
    std::string code;
    std::string message;
};

bool is_valid_host_id(const std::string& id) {
    if (id.empty()) return true;
    if (id.size() < 2 || id.size() > 64) return false;
    for (char c : id) {
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_')) return false;
    }
    return true;
}

bool is_valid_ipv4(const std::string& ip) {
    if (ip.empty()) return true;
    int parts = 0;
    std::size_t pos = 0;
    while (pos <= ip.size()) {
        auto dot = ip.find('.', pos);
        auto part = ip.substr(pos, dot == std::string::npos ? std::string::npos : dot - pos);
        if (part.empty() || part.size() > 3) return false;
        int value = 0;
        for (char c : part) {
            if (!std::isdigit(static_cast<unsigned char>(c))) return false;
            value = value * 10 + (c - '0');
        }
        if (value > 255) return false;
        ++parts;
        if (dot == std::string::npos) break;
        pos = dot + 1;
    }
    return parts == 4;
}

bool is_valid_permission(const std::string& p) {
    if (p.empty() || p.size() > 40) return false;
    for (char c : p) {
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-' || c == '*')) return false;
    }
    return true;
}

void require_text(std::vector<ValidationIssue>& issues,
                  const std::string& field,
                  const std::string& label,
                  const std::string& value,
                  std::size_t min_len,
                  std::size_t max_len) {
    if (value.size() < min_len) {
        issues.push_back({field, "required", label + "不能为空"});
        return;
    }
    if (value.size() > max_len) {
        issues.push_back({field, "length", label + "长度不能超过 " + std::to_string(max_len) + " 个字符"});
    }
}

std::vector<ValidationIssue> validate_host_record(const HostRecord& h, bool require_name) {
    std::vector<ValidationIssue> issues;
    if (!is_valid_host_id(h.id)) {
        issues.push_back({"id", "format", "主机 ID 只能包含字母、数字、短横线和下划线，长度为 2 到 64 个字符"});
    }
    if (require_name || !h.name.empty()) require_text(issues, "name", "主机名称", h.name, 1, 80);
    if (!is_valid_ipv4(h.ip_address)) {
        issues.push_back({"ip_address", "format", "IP 地址格式不正确，应为 IPv4，例如 192.168.1.10"});
    }
    if (h.hardware.size() > 120) {
        issues.push_back({"hardware", "length", "硬件配置长度不能超过 120 个字符"});
    }
    if (h.os_version.size() > 120) {
        issues.push_back({"os_version", "length", "操作系统版本长度不能超过 120 个字符"});
    }
    if (h.note.size() > 240) {
        issues.push_back({"note", "length", "备注长度不能超过 240 个字符"});
    }
    if (h.cpu_usage_percent > 100) {
        issues.push_back({"cpu_usage_percent", "range", "CPU 占用率必须在 0 到 100 之间"});
    }
    if (h.memory_usage_percent > 100) {
        issues.push_back({"memory_usage_percent", "range", "内存占用率必须在 0 到 100 之间"});
    }
    if (h.permissions.size() > 20) {
        issues.push_back({"permissions", "range", "权限项不能超过 20 个"});
    }
    for (const auto& p : h.permissions) {
        if (!is_valid_permission(p)) {
            issues.push_back({"permissions", "format", "权限项只能包含字母、数字、下划线、短横线或 *"});
            break;
        }
    }
    return issues;
}

std::vector<ValidationIssue> validate_remote_command(const std::string& target_id,
                                                     const std::string& command_type,
                                                     const std::string& payload) {
    std::vector<ValidationIssue> issues;
    require_text(issues, "target_host_id", "目标主机 ID", target_id, 1, 64);
    if (!target_id.empty() && !is_valid_host_id(target_id)) {
        issues.push_back({"target_host_id", "format", "目标主机 ID 格式不正确"});
    }
    require_text(issues, "command_type", "指令类型", command_type, 1, 40);
    if (!command_type.empty() && !is_valid_permission(command_type)) {
        issues.push_back({"command_type", "format", "指令类型只能包含字母、数字、下划线和短横线"});
    }
    if (payload.size() > 2048) {
        issues.push_back({"payload", "length", "指令参数长度不能超过 2048 个字符"});
    }
    return issues;
}

bool enrollment_key_valid(const ManagerConfig& cfg, const std::string& body) {
    if (cfg.enrollment_key.empty()) return true;
    auto key = json_string_field(body, "enrollment_key");
    if (key.empty()) key = json_string_field(body, "specific_key");
    return key == cfg.enrollment_key;
}

std::string validation_error_json(const std::vector<ValidationIssue>& issues) {
    std::ostringstream o;
    o << "{\n"
      << "  \"error\": \"validation_failed\",\n"
      << "  \"message\": \"输入信息验证失败，请根据字段提示修改后重试\",\n"
      << "  \"validation_errors\": [\n";
    for (std::size_t i = 0; i < issues.size(); ++i) {
        const auto& e = issues[i];
        o << "    {\n"
          << "      \"field\": \"" << json_escape(e.field) << "\",\n"
          << "      \"code\": \"" << json_escape(e.code) << "\",\n"
          << "      \"message\": \"" << json_escape(e.message) << "\"\n"
          << "    }";
        if (i + 1 < issues.size()) o << ',';
        o << "\n";
    }
    o << "  ]\n"
      << "}";
    return o.str();
}

std::string validation_rules_json() {
    return "{\n"
           "  \"rules\": {\n"
           "    \"host.name\": { \"required\": true, \"min_length\": 1, \"max_length\": 80 },\n"
           "    \"host.id\": { \"required\": false, \"pattern\": \"[A-Za-z0-9_-]{2,64}\" },\n"
           "    \"host.ip_address\": { \"required\": false, \"format\": \"ipv4\" },\n"
           "    \"host.hardware\": { \"required\": false, \"max_length\": 120 },\n"
           "    \"host.os_version\": { \"required\": false, \"max_length\": 120 },\n"
           "    \"host.note\": { \"required\": false, \"max_length\": 240 },\n"
           "    \"host.permissions\": { \"required\": false, \"format\": \"permission_list\", \"max_items\": 20 },\n"
           "    \"host.cpu_usage_percent\": { \"required\": false, \"min\": 0, \"max\": 100 },\n"
           "    \"host.memory_usage_percent\": { \"required\": false, \"min\": 0, \"max\": 100 },\n"
           "    \"host.enrollment_key\": { \"required\": true, \"min_length\": 8, \"max_length\": 128 },\n"
           "    \"remote.target_host_id\": { \"required\": true, \"pattern\": \"[A-Za-z0-9_-]{2,64}\" },\n"
           "    \"remote.command_type\": { \"required\": true, \"pattern\": \"[A-Za-z0-9_-]{1,40}\" },\n"
           "    \"remote.payload\": { \"required\": false, \"max_length\": 2048 },\n"
           "    \"upgrade.url\": { \"required\": true, \"format\": \"http_url\", \"max_length\": 2048 }\n"
           "  },\n"
           "  \"extension\": \"新增业务字段时，可在前端 validationRules 中追加规则，并在后端增加对应 validate_* 函数或复用 required/format/length/range 校验。\"\n"
           "}";
}

bool has_permission(const HostRecord& h, const std::string& permission) {
    for (const auto& p : h.permissions) {
        if (p == "*" || p == "remote_control" || p == permission) return true;
    }
    return false;
}

bool host_online(const HostRecord& h, u64 now, u64 timeout_sec) {
    return h.last_seen_epoch > 0 && now >= h.last_seen_epoch &&
           now - h.last_seen_epoch <= timeout_sec && h.network_status != "offline";
}

std::string default_host_id(const HostRecord& h) {
    std::string seed = h.name + "|" + h.ip_address + "|" + h.hardware + "|" + h.os_version;
    if (seed == "|||") seed = proc::hostname() + "|" + crypto::random_hex(8);
    return "host-" + crypto::sha256_hex(seed).substr(0, 16);
}

std::vector<std::string> json_object_array_field(const std::string& json, const std::string& key) {
    std::vector<std::string> objects;
    auto marker = "\"" + key + "\"";
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

HostRecord host_from_json(const std::string& json) {
    HostRecord h;
    h.id = json_string_field(json, "id");
    if (h.id.empty()) h.id = json_string_field(json, "host_id");
    h.name = json_string_field(json, "name");
    if (h.name.empty()) h.name = json_string_field(json, "host_name");
    h.ip_address = json_string_field(json, "ip_address");
    if (h.ip_address.empty()) h.ip_address = json_string_field(json, "ip");
    h.hardware = json_string_field(json, "hardware");
    h.os_version = json_string_field(json, "os_version");
    h.network_status = json_string_field(json, "network_status");
    h.note = json_string_field(json, "note");
    h.permissions = json_string_array_field(json, "permissions");
    h.collectors_state = json_array_text(json, "collectors");
    if (h.collectors_state.empty()) h.collectors_state = "[]";
    h.last_seen_epoch = json_u64_field(json, "last_seen_epoch", 0);
    h.cpu_usage_percent = json_u64_field(json, "cpu_usage_percent", 0);
    h.memory_usage_percent = json_u64_field(json, "memory_usage_percent", 0);
    if (h.permissions.empty()) h.permissions = {"status_view"};
    if (h.network_status.empty()) h.network_status = "unknown";
    if (h.id.empty()) h.id = default_host_id(h);
    return h;
}

std::string host_to_json(const HostRecord& h, bool comma, u64 now, u64 timeout_sec) {
    std::ostringstream o;
    bool online = host_online(h, now, timeout_sec);
    o << "    {\n"
      << "      \"id\": \"" << json_escape(h.id) << "\",\n"
      << "      \"name\": \"" << json_escape(h.name) << "\",\n"
      << "      \"ip_address\": \"" << json_escape(h.ip_address) << "\",\n"
      << "      \"hardware\": \"" << json_escape(h.hardware) << "\",\n"
      << "      \"os_version\": \"" << json_escape(h.os_version) << "\",\n"
      << "      \"network_status\": \"" << json_escape(online ? "online" : h.network_status) << "\",\n"
      << "      \"online\": " << (online ? "true" : "false") << ",\n"
      << "      \"last_seen_epoch\": " << h.last_seen_epoch << ",\n"
      << "      \"last_seen\": \"" << json_escape(iso_time(h.last_seen_epoch)) << "\",\n"
      << "      \"cpu_usage_percent\": " << h.cpu_usage_percent << ",\n"
      << "      \"memory_usage_percent\": " << h.memory_usage_percent << ",\n"
      << "      \"note\": \"" << json_escape(h.note) << "\",\n"
      << "      \"permissions\": [";
    for (std::size_t i = 0; i < h.permissions.size(); ++i) {
        if (i) o << ", ";
        o << "\"" << json_escape(h.permissions[i]) << "\"";
    }
    o << "],\n"
      << "      \"collectors\": " << (h.collectors_state.empty() ? "[]" : h.collectors_state) << "\n"
      << "    }";
    if (comma) o << ",";
    o << "\n";
    return o.str();
}

std::string hosts_path(const ManagerConfig& cfg) {
    return fs::join(cfg.data_dir.empty() ? "data" : cfg.data_dir, "hosts.json");
}

std::string command_dir(const ManagerConfig& cfg) {
    return fs::join(cfg.data_dir.empty() ? "data" : cfg.data_dir, "host_commands");
}

std::string host_metrics_dir(const ManagerConfig& cfg) {
    return fs::join(cfg.data_dir.empty() ? "data" : cfg.data_dir, "host_metrics");
}

std::string audit_summary_dir(const ManagerConfig& cfg) {
    return fs::join(cfg.data_dir.empty() ? "data" : cfg.data_dir, "audit_summaries");
}

std::string command_result_dir(const ManagerConfig& cfg) {
    return fs::join(cfg.data_dir.empty() ? "data" : cfg.data_dir, "command_results");
}

std::string operation_log_dir(const ManagerConfig& cfg) {
    return fs::join(cfg.data_dir.empty() ? "data" : cfg.data_dir, "operation_logs");
}

std::string alert_dir(const ManagerConfig& cfg) {
    return fs::join(cfg.data_dir.empty() ? "data" : cfg.data_dir, "alerts");
}

std::string policy_dir(const ManagerConfig& cfg) {
    return fs::join(cfg.data_dir.empty() ? "data" : cfg.data_dir, "policies");
}

std::string thresholds_path(const ManagerConfig& cfg) {
    return fs::join(policy_dir(cfg), "status_thresholds.json");
}

std::string violation_rules_path(const ManagerConfig& cfg) {
    return fs::join(policy_dir(cfg), "violation_rules.json");
}

std::string rbac_policy_path(const ManagerConfig& cfg) {
    return fs::join(policy_dir(cfg), "rbac_policy.json");
}

std::string default_thresholds_json() {
    return "{\n"
           "  \"cpu_usage_percent\": { \"warning\": 80, \"critical\": 95 },\n"
           "  \"memory_usage_percent\": { \"warning\": 80, \"critical\": 95 },\n"
           "  \"disk_usage_percent\": { \"warning\": 85, \"critical\": 95 },\n"
           "  \"network_rx_bytes\": { \"warning\": 1073741824, \"critical\": 10737418240 },\n"
           "  \"network_tx_bytes\": { \"warning\": 1073741824, \"critical\": 10737418240 },\n"
           "  \"process_status\": { \"required\": [\"auditforwarder-client\"] }\n"
           "}";
}

std::string default_violation_rules_json() {
    return "{\n"
           "  \"rules\": [\n"
           "    { \"id\": \"danger-command\", \"enabled\": true, \"operation_type\": \"execute\", \"keyword\": \"rm -rf\", \"severity\": \"critical\", \"message\": \"检测到危险删除命令\" },\n"
           "    { \"id\": \"credential-access\", \"enabled\": true, \"operation_type\": \"file\", \"keyword\": \"password\", \"severity\": \"high\", \"message\": \"检测到疑似凭据文件访问\" },\n"
           "    { \"id\": \"permission-change\", \"enabled\": true, \"operation_type\": \"permission\", \"keyword\": \"grant\", \"severity\": \"medium\", \"message\": \"检测到权限变更操作\" }\n"
           "  ]\n"
           "}";
}

std::string default_rbac_policy_json() {
    return "{\n"
           "  \"roles\": {\n"
           "    \"admin\": [\"hosts:read\", \"hosts:write\", \"logs:read\", \"alerts:read\", \"policy:write\", \"remote:control\"],\n"
           "    \"operator\": [\"hosts:read\", \"logs:read\", \"alerts:read\", \"remote:control\"],\n"
           "    \"auditor\": [\"hosts:read\", \"logs:read\", \"alerts:read\"]\n"
           "  },\n"
           "  \"default_role\": \"admin\",\n"
           "  \"note\": \"当前内置 RBAC 使用 Bearer Token 认证后分配 admin 角色；生产环境可扩展为用户表和角色绑定。\"\n"
           "}";
}

Result<void> write_text_file(const std::string& path, const std::string& text) {
    auto dir = fs::dirname(path);
    if (!dir.empty()) {
        auto cr = fs::create_directories(dir);
        if (cr.is_err()) return cr;
    }
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return Result<void>(Error::Code::IoError, "无法写入文件：" + path);
    out << text;
    return Result<void>::ok();
}

Result<std::string> load_or_create_text(const std::string& path, const std::string& fallback) {
    if (fs::exists(path)) {
        auto content = read_text_file(path);
        if (content.is_ok()) return content.value();
        return Result<std::string>(content.error());
    }
    auto saved = write_text_file(path, fallback);
    if (saved.is_err()) return Result<std::string>(saved.error());
    return fallback;
}

Result<void> append_jsonl_retained(const std::string& dir,
                                   const std::string& file_name,
                                   const std::string& line,
                                   std::size_t max_lines) {
    auto cr = fs::create_directories(dir);
    if (cr.is_err()) return cr;
    auto path = fs::join(dir, file_name);

    // 快速追加（O(1)）：不再每次全量读入+截断重写
    {
        std::ofstream out(path, std::ios::binary | std::ios::app);
        if (!out) return Result<void>(Error::Code::IoError, "cannot append central store");
        out << line << "\n";
    }

    // 定期裁剪：仅当文件体积明显超过保留上限时才做一次全量重写
    // 用文件大小粗估行数（日志行通常 200~1024 字节），避免每次追加都读文件
    if (max_lines > 0) {
        constexpr std::uint64_t kAvgLineBytes = 1024;
        std::uint64_t size = fs::file_size(path);
        if (size > static_cast<std::uint64_t>(max_lines) * kAvgLineBytes * 2) {
            auto old = read_text_file(path);
            if (old.is_ok()) {
                std::vector<std::string> lines;
                std::istringstream in(old.value());
                std::string item;
                while (std::getline(in, item)) {
                    if (!item.empty()) lines.push_back(item);
                }
                if (lines.size() > max_lines) {
                    lines.erase(lines.begin(),
                                lines.begin() + static_cast<std::ptrdiff_t>(lines.size() - max_lines));
                    std::ofstream out(path, std::ios::binary | std::ios::trunc);
                    if (out) {
                        for (const auto& item : lines) out << item << "\n";
                    }
                }
            }
        }
    }
    return Result<void>::ok();
}

bool constant_time_equal(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    }
    return diff == 0;
}

std::string effective_login_hash(const ManagerConfig& cfg) {
    if (!cfg.login_password_sha256.empty()) return cfg.login_password_sha256;
    if (!cfg.auth_token.empty()) return crypto::sha256_hex(cfg.auth_token);
    return crypto::sha256_hex("admin123");
}

void append_login_audit(const ManagerConfig& cfg,
                        const std::string& username,
                        const std::string& client_ip,
                        const std::string& result,
                        const std::string& message) {
    std::ostringstream line;
    line << "{"
         << "\"timestamp\":\"" << iso_time(epoch_seconds()) << "\","
         << "\"username\":\"" << json_escape(username) << "\","
         << "\"client_ip\":\"" << json_escape(client_ip) << "\","
         << "\"event_type\":\"login\","
         << "\"result\":\"" << json_escape(result) << "\","
         << "\"message\":\"" << json_escape(message) << "\""
         << "}";
    (void)append_jsonl_retained(cfg.data_dir, "login_audit.jsonl", line.str(), 20000);
}

std::string alert_json(const std::string& host_id,
                       const std::string& source,
                       const std::string& severity,
                       const std::string& rule_id,
                       const std::string& message,
                       const std::string& evidence) {
    std::ostringstream o;
    o << "{"
      << "\"alert_id\":\"alert-" << crypto::random_hex(8) << "\","
      << "\"timestamp\":\"" << iso_time(epoch_seconds()) << "\","
      << "\"host_id\":\"" << json_escape(host_id) << "\","
      << "\"source\":\"" << json_escape(source) << "\","
      << "\"severity\":\"" << json_escape(severity) << "\","
      << "\"rule_id\":\"" << json_escape(rule_id) << "\","
      << "\"message\":\"" << json_escape(message) << "\","
      << "\"evidence\":\"" << json_escape(evidence) << "\","
      << "\"status\":\"open\""
      << "}";
    return o.str();
}

// ---- 远端客户端上报聚合计数器（进程内原子计数 + 落盘持久化） ----
std::atomic<u64> g_remote_events_collected{0};
std::atomic<u64> g_remote_events_uploaded{0};
std::atomic<u64> g_remote_bytes_uploaded{0};
std::atomic<u64> g_remote_alerts{0};

// alerts 写入独立锁：规则复查可在 host_store_mutex 之外并发执行
std::mutex& alert_store_mutex() {
    static std::mutex m;
    return m;
}

Result<void> append_alert(const ManagerConfig& cfg,
                          const std::string& host_id,
                          const std::string& source,
                          const std::string& severity,
                          const std::string& rule_id,
                          const std::string& message,
                          const std::string& evidence) {
    auto line = alert_json(host_id, source, severity, rule_id, message, evidence);
    std::lock_guard<std::mutex> lk(alert_store_mutex());
    auto r = append_jsonl_retained(alert_dir(cfg), host_id + ".jsonl", line, 20000);
    if (r.is_ok()) g_remote_alerts.fetch_add(1, std::memory_order_relaxed);
    return r;
}

std::string counters_path(const ManagerConfig& cfg) {
    return fs::join(cfg.data_dir.empty() ? "data" : cfg.data_dir, "manager_counters.json");
}

void load_remote_counters(const ManagerConfig& cfg) {
    auto c = read_text_file(counters_path(cfg));
    if (c.is_err() || c.value().empty()) return;
    const auto& j = c.value();
    auto load_u64 = [&](const std::string& key) -> u64 {
        auto pos = j.find("\"" + key + "\"");
        if (pos == std::string::npos) return 0;
        auto colon = j.find(':', pos);
        if (colon == std::string::npos) return 0;
        std::size_t i = colon + 1;
        while (i < j.size() && (j[i] == ' ' || j[i] == '\t')) ++i;
        u64 v = 0;
        while (i < j.size() && j[i] >= '0' && j[i] <= '9') { v = v * 10 + static_cast<u64>(j[i] - '0'); ++i; }
        return v;
    };
    g_remote_events_collected.store(load_u64("events_collected"), std::memory_order_relaxed);
    g_remote_events_uploaded.store(load_u64("events_uploaded"), std::memory_order_relaxed);
    g_remote_bytes_uploaded.store(load_u64("bytes_uploaded"), std::memory_order_relaxed);
    g_remote_alerts.store(load_u64("alerts"), std::memory_order_relaxed);
}

void save_remote_counters(const ManagerConfig& cfg) {
    std::ostringstream o;
    o << "{\n"
      << "  \"events_collected\": " << g_remote_events_collected.load(std::memory_order_relaxed) << ",\n"
      << "  \"events_uploaded\": " << g_remote_events_uploaded.load(std::memory_order_relaxed) << ",\n"
      << "  \"bytes_uploaded\": " << g_remote_bytes_uploaded.load(std::memory_order_relaxed) << ",\n"
      << "  \"alerts\": " << g_remote_alerts.load(std::memory_order_relaxed) << "\n"
      << "}\n";
    (void)write_text_file(counters_path(cfg), o.str());
}

std::string threshold_severity(double value, double warning, double critical) {
    if (critical > 0.0 && value >= critical) return "critical";
    if (warning > 0.0 && value >= warning) return "warning";
    return {};
}

void evaluate_metric_thresholds(const ManagerConfig& cfg,
                                const std::string& host_id,
                                const std::string& body) {
    auto thresholds = load_or_create_text(thresholds_path(cfg), default_thresholds_json());
    if (thresholds.is_err()) return;
    const auto& policy = thresholds.value();
    struct MetricCheck {
        std::string name;
        double value;
    };
    std::vector<MetricCheck> checks = {
        {"cpu_usage_percent", json_nested_number_field(body, "cpu", "usage_percent", json_number_field(body, "cpu_usage_percent", 0.0))},
        {"memory_usage_percent", json_nested_number_field(body, "memory", "usage_percent", json_number_field(body, "memory_usage_percent", 0.0))},
        {"disk_usage_percent", json_nested_number_field(body, "disk", "usage_percent", json_number_field(body, "disk_usage_percent", 0.0))},
        {"network_rx_bytes", json_nested_number_field(body, "network", "rx_bytes", 0.0)},
        {"network_tx_bytes", json_nested_number_field(body, "network", "tx_bytes", 0.0)}
    };
    for (const auto& check : checks) {
        auto p = policy.find("\"" + check.name + "\"");
        if (p == std::string::npos) continue;
        auto block_start = policy.find('{', p);
        auto block_end = policy.find('}', block_start == std::string::npos ? p : block_start);
        if (block_start == std::string::npos || block_end == std::string::npos) continue;
        auto block = policy.substr(block_start, block_end - block_start + 1);
        auto warning = json_number_field(block, "warning", 0.0);
        auto critical = json_number_field(block, "critical", 0.0);
        auto severity = threshold_severity(check.value, warning, critical);
        if (!severity.empty()) {
            std::ostringstream msg;
            msg << check.name << " 当前值 " << check.value << " 超过 " << severity << " 阈值";
            (void)append_alert(cfg, host_id, "metric_threshold", severity, check.name, msg.str(), body);
        }
    }
}

bool string_contains_ci(std::string text, std::string needle) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    std::transform(needle.begin(), needle.end(), needle.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return !needle.empty() && text.find(needle) != std::string::npos;
}

void evaluate_operation_log_rules(const ManagerConfig& cfg,
                                  const std::string& host_id,
                                  const std::string& body) {
    auto rules = load_or_create_text(violation_rules_path(cfg), default_violation_rules_json());
    if (rules.is_err()) return;
    auto records = json_object_array_field(rules.value(), "rules");
    auto op_type = json_string_field(body, "operation_type");
    auto event_type = json_string_field(body, "event_type");
    auto command = json_string_field(body, "command");
    auto message = json_string_field(body, "message");
    auto details = json_string_field(body, "operation_details");
    auto searchable = op_type + " " + event_type + " " + command + " " + message + " " + details + " " + body;
    for (const auto& rule : records) {
        if (!json_bool_field(rule, "enabled", true)) continue;
        auto expected_type = json_string_field(rule, "operation_type");
        if (!expected_type.empty() &&
            op_type != expected_type &&
            event_type != expected_type &&
            !string_contains_ci(searchable, expected_type)) {
            continue;
        }
        auto keyword = json_string_field(rule, "keyword");
        if (!keyword.empty() && !string_contains_ci(searchable, keyword)) continue;
        auto severity = json_string_field(rule, "severity");
        if (severity.empty()) severity = "medium";
        auto id = json_string_field(rule, "id");
        if (id.empty()) id = "dynamic-rule";
        auto rule_message = json_string_field(rule, "message");
        if (rule_message.empty()) rule_message = "检测到疑似违规操作";
        (void)append_alert(cfg, host_id, "violation_rule", severity, id, rule_message, body);
    }
}

std::vector<std::string> read_jsonl_filtered(const std::string& path,
                                             const std::string& host_id,
                                             const std::string& operation_type,
                                             const std::string& from,
                                             const std::string& to,
                                             std::size_t limit) {
    std::vector<std::string> lines;
    auto content = read_text_file(path);
    if (content.is_err()) return lines;
    std::istringstream in(content.value());
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        if (!host_id.empty() && json_string_field(line, "host_id") != host_id) continue;
        if (!operation_type.empty()) {
            auto op = json_string_field(line, "operation_type");
            auto ev = json_string_field(line, "event_type");
            if (op != operation_type && ev != operation_type) continue;
        }
        auto ts = json_string_field(line, "timestamp");
        if (!from.empty() && !ts.empty() && ts < from) continue;
        if (!to.empty() && !ts.empty() && ts > to) continue;
        lines.push_back(line);
        if (limit > 0 && lines.size() > limit) {
            lines.erase(lines.begin());
        }
    }
    return lines;
}

// 流式统计单个 jsonl 文件中匹配条件的行数（不存储数据）。
std::size_t count_jsonl_filtered(const std::string& path,
                                  const std::string& host_id,
                                  const std::string& operation_type,
                                  const std::string& from,
                                  const std::string& to) {
    std::size_t count = 0;
    auto fc = read_text_file(path);
    if (fc.is_err()) return 0;
    std::istringstream in(fc.value());
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        if (!host_id.empty() && json_string_field(line, "host_id") != host_id) continue;
        if (!operation_type.empty()) {
            auto op = json_string_field(line, "operation_type");
            auto ev = json_string_field(line, "event_type");
            if (op != operation_type && ev != operation_type) continue;
        }
        auto ts = json_string_field(line, "timestamp");
        if (!from.empty() && !ts.empty() && ts < from) continue;
        if (!to.empty() && !ts.empty() && ts > to) continue;
        ++count;
    }
    return count;
}

std::vector<std::string> read_jsonl_dir_filtered(const std::string& dir,
                                                 const std::string& host_id,
                                                 const std::string& operation_type,
                                                 const std::string& from,
                                                 const std::string& to,
                                                 std::size_t limit) {
    std::vector<std::string> lines;
    if (!host_id.empty()) {
        return read_jsonl_filtered(fs::join(dir, host_id + ".jsonl"), host_id, operation_type, from, to, limit);
    }
    auto listed = fs::list_directory(dir);
    if (listed.is_err()) return lines;
    for (const auto& item : listed.value()) {
        if (fs::extension(item) != ".jsonl") continue;
        // list_directory 返回的已是完整路径，直接读取（is_absolute 兼容相对/绝对两种返回）
        auto path_to_read = fs::is_absolute(item) || item.find('/') != std::string::npos || item.find('\\') != std::string::npos
                            ? item : fs::join(dir, item);
        auto part = read_jsonl_filtered(path_to_read, "", operation_type, from, to, limit);
        lines.insert(lines.end(), part.begin(), part.end());
        if (limit > 0 && lines.size() > limit) {
            lines.erase(lines.begin(), lines.begin() + static_cast<std::ptrdiff_t>(lines.size() - limit));
        }
    }
    return lines;
}

// 流式统计目录下所有 jsonl 文件中匹配条件的总行数。
std::size_t count_jsonl_dir_filtered(const std::string& dir,
                                      const std::string& host_id,
                                      const std::string& operation_type,
                                      const std::string& from,
                                      const std::string& to) {
    if (!host_id.empty()) {
        return count_jsonl_filtered(fs::join(dir, host_id + ".jsonl"), host_id, operation_type, from, to);
    }
    std::size_t total = 0;
    auto listed = fs::list_directory(dir);
    if (listed.is_err()) return 0;
    for (const auto& item : listed.value()) {
        if (fs::extension(item) != ".jsonl") continue;
        auto p = fs::is_absolute(item) || item.find('/') != std::string::npos || item.find('\\') != std::string::npos
                 ? item : fs::join(dir, item);
        total += count_jsonl_filtered(p, "", operation_type, from, to);
    }
    return total;
}

// ================= 两级存储：operation_logs/<host_id>/<collector>.jsonl =================

std::string host_operation_log_dir(const ManagerConfig& cfg, const std::string& host_id) {
    return fs::join(operation_log_dir(cfg), host_id);
}

// 在 JSON 对象的起始 '{' 之后注入一个字段（numeric=true 时值不加引号）。
std::string json_inject_field(const std::string& obj,
                              const std::string& key,
                              const std::string& value,
                              bool numeric = false) {
    auto p = obj.find('{');
    if (p == std::string::npos) return obj;
    std::string frag = "\"" + json_escape(key) + "\":";
    frag += numeric ? value : ("\"" + json_escape(value) + "\"");
    frag += ",";
    return obj.substr(0, p + 1) + frag + obj.substr(p + 1);
}

// 读取未加引号的数值字段原始 token（如 "client_ts":1735689600000），失败返回空串。
std::string json_numeric_token(const std::string& json, const std::string& key) {
    const std::string marker = "\"" + key + "\"";
    auto p = json.find(marker);
    if (p == std::string::npos) return {};
    p = json.find(':', p + marker.size());
    if (p == std::string::npos) return {};
    ++p;
    while (p < json.size() && (json[p] == ' ' || json[p] == '\t')) ++p;
    std::size_t end = p;
    while (end < json.size() && std::isdigit(static_cast<unsigned char>(json[end]))) ++end;
    return json.substr(p, end - p);
}

// 旧扁平结构 data/operation_logs/<host>.jsonl → <host>/legacy.jsonl（启动时一次性、幂等）。
void migrate_flat_operation_logs(const ManagerConfig& cfg) {
    const std::string root = operation_log_dir(cfg);
    if (!fs::exists(root)) return;
    auto listed = fs::list_directory(root);
    if (listed.is_err()) return;
    for (const auto& entry : listed.value()) {
        if (!fs::is_regular(entry)) continue;
        if (fs::extension(entry) != ".jsonl") continue;
        std::string host = fs::basename(entry);
        host.resize(host.size() - 6);  // 去掉 ".jsonl"
        if (!is_valid_host_id(host)) continue;  // 只迁移合法主机名扁平文件
        const std::string dest_dir = fs::join(root, host);
        const std::string dest = fs::join(dest_dir, "legacy.jsonl");
        auto cr = fs::create_directories(dest_dir);
        if (cr.is_err()) {
            AF_LOG_ERROR("operation_logs migrate: cannot create " << dest_dir);
            continue;
        }
        if (!fs::exists(dest)) {
            bool copied = false;
            std::size_t n = 0;
            {
                std::ifstream in(entry, std::ios::binary);
                std::ofstream out(dest, std::ios::binary | std::ios::trunc);
                if (!in || !out) {
                    AF_LOG_ERROR("operation_logs migrate: cannot open " << entry << " / " << dest);
                    continue;
                }
                std::string line;
                while (std::getline(in, line)) {
                    if (!line.empty()) { out << line << "\n"; ++n; }
                }
                out.flush();
                copied = true;
            }  // 此处析构关闭文件句柄（不能显式 .close()，Windows 头文件把 close 定义为 closesocket）
            if (copied) {
                AF_LOG_INFO("operation_logs migrate: " << host << ".jsonl -> " << host
                            << "/legacy.jsonl (" << n << " lines)");
            }
        } else {
            AF_LOG_INFO("operation_logs migrate: legacy.jsonl exists for host " << host
                        << ", drop flat source only");
        }
        auto rm = fs::remove(entry);
        if (rm.is_err()) AF_LOG_WARN("operation_logs migrate: cannot remove " << entry);
    }
}

// 分层操作日志读取：host_id 目录 → 按 collector 文件 → priority/operation/时间窗过滤。
std::vector<std::string> read_operation_logs_filtered(const ManagerConfig& cfg,
                                                      const std::string& host_id,
                                                      const std::string& collector,
                                                      const std::string& priority,
                                                      const std::string& operation_type,
                                                      const std::string& from,
                                                      const std::string& to,
                                                      std::size_t limit) {
    std::vector<std::string> result;
    const std::string root = operation_log_dir(cfg);

    // 收集要扫描的主机目录
    std::vector<std::string> host_dirs;
    if (!host_id.empty()) {
        host_dirs.push_back(fs::join(root, host_id));
    } else if (fs::exists(root)) {
        auto hosts = fs::list_directory(root);
        if (hosts.is_ok()) {
            for (const auto& h : hosts.value()) {
                if (fs::is_directory(h)) host_dirs.push_back(h);
            }
        }
    }

    const std::string want_collector = logmeta::sanitize_collector_id(collector);

    for (const auto& hdir : host_dirs) {
        if (!fs::exists(hdir)) continue;
        const std::string dir_host = fs::basename(hdir);
        auto files = fs::list_directory(hdir);
        if (files.is_err()) continue;
        for (const auto& f : files.value()) {
            if (!fs::is_regular(f) || fs::extension(f) != ".jsonl") continue;
            std::string base = fs::basename(f);
            base.resize(base.size() - 6);  // 去掉 ".jsonl"
            // 高优先级过滤只查 privileged.jsonl 镜像；否则排除镜像避免重复
            if (priority == logmeta::priority::kHigh) {
                if (base != "privileged") continue;
            } else {
                if (base == "privileged") continue;
                if (!collector.empty() && base != want_collector) continue;
            }
            auto content = read_text_file(f);
            if (content.is_err()) continue;
            std::istringstream in(content.value());
            std::string line;
            while (std::getline(in, line)) {
                if (line.empty()) continue;
                if (host_id.empty()) {
                    if (json_string_field(line, "host_id") != dir_host) continue;
                } else if (json_string_field(line, "host_id") != host_id) {
                    continue;
                }
                if (!collector.empty() && priority != logmeta::priority::kHigh &&
                    json_string_field(line, "collector") != collector
                    && !(base == "legacy")) {
                    continue;
                }
                if (!priority.empty() && priority != logmeta::priority::kHigh &&
                    json_string_field(line, "priority") != priority) {
                    continue;
                }
                if (!operation_type.empty()) {
                    auto op = json_string_field(line, "operation_type");
                    auto ev = json_string_field(line, "event_type");
                    if (op != operation_type && ev != operation_type) continue;
                }
                auto ts = json_string_field(line, "timestamp");
                if (!from.empty() && !ts.empty() && ts < from) continue;
                if (!to.empty() && !ts.empty() && ts > to) continue;
                result.push_back(line);
            }
        }
    }

    // 跨采集器文件合并后按 (timestamp, client_ts) 排序，再截断 limit
    std::sort(result.begin(), result.end(), [](const std::string& a, const std::string& b) {
        auto ta = json_string_field(a, "timestamp");
        auto tb = json_string_field(b, "timestamp");
        if (ta != tb) return ta < tb;
        auto ca = std::strtoull(json_numeric_token(a, "client_ts").c_str(), nullptr, 10);
        auto cb = std::strtoull(json_numeric_token(b, "client_ts").c_str(), nullptr, 10);
        return ca < cb;
    });
    if (limit > 0 && result.size() > limit) {
        result.erase(result.begin(),
                     result.begin() + static_cast<std::ptrdiff_t>(result.size() - limit));
    }
    return result;
}

// 流式统计操作日志中匹配条件的总行数（不存储、不排序）。
std::size_t count_operation_logs_filtered(const ManagerConfig& cfg,
                                           const std::string& host_id,
                                           const std::string& collector,
                                           const std::string& priority,
                                           const std::string& operation_type,
                                           const std::string& from,
                                           const std::string& to) {
    std::size_t count = 0;
    const std::string root = operation_log_dir(cfg);
    std::vector<std::string> host_dirs;
    if (!host_id.empty()) {
        host_dirs.push_back(fs::join(root, host_id));
    } else if (fs::exists(root)) {
        auto hosts = fs::list_directory(root);
        if (hosts.is_ok())
            for (const auto& h : hosts.value())
                if (fs::is_directory(h)) host_dirs.push_back(h);
    }
    const std::string want_collector = logmeta::sanitize_collector_id(collector);
    for (const auto& hdir : host_dirs) {
        if (!fs::exists(hdir)) continue;
        const std::string dir_host = fs::basename(hdir);
        auto files = fs::list_directory(hdir);
        if (files.is_err()) continue;
        for (const auto& f : files.value()) {
            if (!fs::is_regular(f) || fs::extension(f) != ".jsonl") continue;
            std::string base = fs::basename(f);
            base.resize(base.size() - 6);
            if (priority == logmeta::priority::kHigh) {
                if (base != "privileged") continue;
            } else {
                if (base == "privileged") continue;
                if (!collector.empty() && base != want_collector) continue;
            }
            auto fc = read_text_file(f);
            if (fc.is_err()) continue;
            std::istringstream in(fc.value());
            std::string line;
            while (std::getline(in, line)) {
                if (line.empty()) continue;
                if (host_id.empty()) {
                    if (json_string_field(line, "host_id") != dir_host) continue;
                } else if (json_string_field(line, "host_id") != host_id) {
                    continue;
                }
                if (!collector.empty() && priority != logmeta::priority::kHigh &&
                    json_string_field(line, "collector") != collector
                    && !(base == "legacy")) {
                    continue;
                }
                if (!priority.empty() && priority != logmeta::priority::kHigh &&
                    json_string_field(line, "priority") != priority) {
                    continue;
                }
                if (!operation_type.empty()) {
                    auto op = json_string_field(line, "operation_type");
                    auto ev = json_string_field(line, "event_type");
                    if (op != operation_type && ev != operation_type) continue;
                }
                auto ts = json_string_field(line, "timestamp");
                if (!from.empty() && !ts.empty() && ts < from) continue;
                if (!to.empty() && !ts.empty() && ts > to) continue;
                ++count;
            }
        }
    }
    return count;
}

// ================= 日志过滤策略档（strict / lenient，按采集器配置）=================

using LogFilterProfile = logpolicy::Profile;

std::string log_filter_profiles_path(const ManagerConfig& cfg) {
    return fs::join(policy_dir(cfg), "log_filter_profiles.json");
}

std::string default_log_filter_profiles_json() {
    return logpolicy::default_profiles_json();
}

LogFilterProfile resolve_log_filter_profile(const ManagerConfig& cfg, const std::string& collector) {
    auto raw = load_or_create_text(log_filter_profiles_path(cfg),
                                   logpolicy::default_profiles_json());
    if (raw.is_err()) return logpolicy::resolve_profile_json(std::string{}, collector);
    return logpolicy::resolve_profile_json(raw.value(), collector);
}

std::string apply_log_filter_profile(const std::string& item, const LogFilterProfile& prof) {
    return logpolicy::apply_profile(item, prof);
}

std::string count_map_json(const std::map<std::string, std::size_t>& counts) {
    std::ostringstream o;
    o << "{";
    std::size_t i = 0;
    for (const auto& kv : counts) {
        if (i) o << ", ";
        o << "\"" << json_escape(kv.first) << "\": " << kv.second;
        ++i;
    }
    o << "}";
    return o.str();
}

std::string logs_analytics_json(const ManagerConfig& cfg,
                                const std::string& host_id,
                                const std::string& collector,
                                const std::string& priority,
                                const std::string& from,
                                const std::string& to,
                                std::size_t limit) {
    std::size_t total_logs = count_operation_logs_filtered(cfg, host_id, collector, priority, "", from, to);
    std::size_t total_alerts = count_jsonl_dir_filtered(alert_dir(cfg), host_id, "", from, to);
    auto logs = read_operation_logs_filtered(cfg, host_id, collector, priority, "", from, to, limit);
    auto alerts = read_jsonl_dir_filtered(alert_dir(cfg), host_id, "", from, to, limit);
    std::map<std::string, std::size_t> operation_types;
    std::map<std::string, std::size_t> alert_severities;
    std::map<std::string, std::size_t> host_counts;
    for (const auto& line : logs) {
        auto type = json_string_field(line, "operation_type");
        if (type.empty()) type = json_string_field(line, "event_type");
        if (type.empty()) type = "unknown";
        ++operation_types[type];
        auto h = json_string_field(line, "host_id");
        if (!h.empty()) ++host_counts[h];
    }
    for (const auto& line : alerts) {
        auto severity = json_string_field(line, "severity");
        if (severity.empty()) severity = "info";
        ++alert_severities[severity];
        auto h = json_string_field(line, "host_id");
        if (!h.empty()) ++host_counts[h];
    }
    std::ostringstream o;
    o << "{\n"
      << "  \"host_id\": \"" << json_escape(host_id) << "\",\n"
      << "  \"log_count\": " << total_logs << ",\n"
      << "  \"alert_count\": " << total_alerts << ",\n"
      << "  \"operation_types\": " << count_map_json(operation_types) << ",\n"
      << "  \"alert_severities\": " << count_map_json(alert_severities) << ",\n"
      << "  \"host_counts\": " << count_map_json(host_counts) << "\n"
      << "}";
    return o.str();
}

// 按主机/采集器统计日志行数（直接以 <host>/<collector>.jsonl 为粒度）。
std::string collector_counts_json(const ManagerConfig& cfg, const std::string& host_filter) {
    std::map<std::string, std::map<std::string, std::size_t>> per_host;
    std::map<std::string, std::size_t> totals;
    std::size_t grand = 0;
    const std::string root = operation_log_dir(cfg);
    std::vector<std::string> host_dirs;
    if (!host_filter.empty()) {
        host_dirs.push_back(fs::join(root, host_filter));
    } else if (fs::exists(root)) {
        auto hosts = fs::list_directory(root);
        if (hosts.is_ok())
            for (const auto& h : hosts.value())
                if (fs::is_directory(h)) host_dirs.push_back(h);
    }
    for (const auto& hdir : host_dirs) {
        if (!fs::exists(hdir)) continue;
        const std::string host = fs::basename(hdir);
        auto files = fs::list_directory(hdir);
        if (files.is_err()) continue;
        for (const auto& f : files.value()) {
            if (!fs::is_regular(f) || fs::extension(f) != ".jsonl") continue;
            std::string collector = fs::basename(f);
            collector.resize(collector.size() - 6);  // 去掉 ".jsonl"
            if (collector == "privileged") continue;  // 镜像不重复计数
            auto content = read_text_file(f);
            if (content.is_err()) continue;
            std::size_t n = 0;
            std::istringstream in(content.value());
            std::string line;
            while (std::getline(in, line)) if (!line.empty()) ++n;
            per_host[host][collector] += n;
            totals[collector] += n;
            grand += n;
        }
    }
    std::ostringstream o;
    o << "{\n  \"host_id\": \"" << json_escape(host_filter) << "\",\n"
      << "  \"total\": " << grand << ",\n"
      << "  \"collector_totals\": " << count_map_json(totals) << ",\n"
      << "  \"hosts\": {";
    std::size_t hi = 0;
    for (const auto& host_kv : per_host) {
        if (hi++) o << ", ";
        o << "\"" << json_escape(host_kv.first) << "\": " << count_map_json(host_kv.second);
    }
    o << "}\n}";
    return o.str();
}

// 用 client_ts/server_ts 计算 high / normal 两级传输延迟（毫秒）的均值与 P95。
std::string transfer_latency_json(const ManagerConfig& cfg,
                                  const std::string& host_id,
                                  std::size_t scan_limit) {
    auto lines = read_operation_logs_filtered(cfg, host_id, "", "", "", "", "", scan_limit);
    std::vector<double> hi_ms, nm_ms;
    for (const auto& line : lines) {
        auto ct = json_numeric_token(line, logmeta::attr::kClientTs);
        auto st = json_numeric_token(line, logmeta::attr::kServerTs);
        if (ct.empty() || st.empty() || ct == "0") continue;
        long long c = std::strtoll(ct.c_str(), nullptr, 10);
        long long s = std::strtoll(st.c_str(), nullptr, 10);
        if (s < c) continue;  // 时钟异常数据剔除
        double ms = static_cast<double>(s - c);
        if (json_string_field(line, "priority") == logmeta::priority::kHigh) hi_ms.push_back(ms);
        else nm_ms.push_back(ms);
    }
    auto stats = [](std::vector<double>& v) {
        double avg = 0, p95 = 0;
        if (!v.empty()) {
            std::sort(v.begin(), v.end());
            double sum = 0;
            for (double x : v) sum += x;
            avg = sum / static_cast<double>(v.size());
            std::size_t idx = static_cast<std::size_t>(0.95 * static_cast<double>(v.size() - 1));
            p95 = v[idx];
        }
        return std::make_pair(avg, p95);
    };
    auto hs = stats(hi_ms);
    auto ns = stats(nm_ms);
    double ratio = (ns.first > 0.0) ? (hs.first / ns.first) : 0.0;
    std::ostringstream o;
    o << std::fixed;
    o.precision(2);
    o << "{\n  \"host_id\": \"" << json_escape(host_id) << "\",\n"
      << "  \"high\":   { \"count\": " << hi_ms.size() << ", \"avg_ms\": " << hs.first
      << ", \"p95_ms\": " << hs.second << " },\n"
      << "  \"normal\": { \"count\": " << nm_ms.size() << ", \"avg_ms\": " << ns.first
      << ", \"p95_ms\": " << ns.second << " },\n"
      << "  \"avg_latency_ratio\": " << ratio << ",\n"
      << "  \"target_ratio_le\": 0.5,\n"
      << "  \"target_met\": " << (ratio > 0.0 && ratio <= 0.5 ? "true" : "false") << "\n"
      << "}";
    return o.str();
}

Result<void> remove_command_from_queue(const ManagerConfig& cfg,
                                       const std::string& host_id,
                                       const std::string& command_id) {
    auto path = fs::join(command_dir(cfg), host_id + ".jsonl");
    if (!fs::exists(path)) return Result<void>::ok();
    auto content = read_text_file(path);
    if (content.is_err()) return Result<void>(content.error());
    std::istringstream in(content.value());
    std::vector<std::string> kept;
    std::string line;
    while (std::getline(in, line)) {
        if (line.find("\"command_id\":\"" + command_id + "\"") == std::string::npos) {
            if (!line.empty()) kept.push_back(line);
        }
    }
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return Result<void>(Error::Code::IoError, "cannot rewrite command queue");
    for (const auto& item : kept) out << item << "\n";
    return Result<void>::ok();
}

Result<std::vector<HostRecord>> load_hosts(const ManagerConfig& cfg) {
    std::vector<HostRecord> hosts;
    auto path = hosts_path(cfg);
    if (!fs::exists(path)) return hosts;
    auto content = read_text_file(path);
    if (content.is_err()) return Result<std::vector<HostRecord>>(content.error());
    for (const auto& obj : json_object_array_field(content.value(), "hosts")) {
        hosts.push_back(host_from_json(obj));
    }
    return hosts;
}

Result<void> save_hosts(const ManagerConfig& cfg, const std::vector<HostRecord>& hosts) {
    auto dir = cfg.data_dir.empty() ? "data" : cfg.data_dir;
    auto cr = fs::create_directories(dir);
    if (cr.is_err()) return cr;
    std::ofstream out(hosts_path(cfg), std::ios::binary | std::ios::trunc);
    if (!out) return Result<void>(Error::Code::IoError, "无法写入主机存储文件");
    auto now = epoch_seconds();
    out << "{\n"
        << "  \"version\": 1,\n"
        << "  \"updated_at\": \"" << iso_time(now) << "\",\n"
        << "  \"hosts\": [\n";
    for (std::size_t i = 0; i < hosts.size(); ++i) {
        out << host_to_json(hosts[i], i + 1 < hosts.size(), now, cfg.status_timeout_seconds);
    }
    out << "  ]\n"
        << "}\n";
    return Result<void>::ok();
}

std::string hosts_response_json(const std::vector<HostRecord>& hosts, const ManagerConfig& cfg) {
    auto now = epoch_seconds();
    std::ostringstream o;
    o << "{\n"
      << "  \"storage_path\": \"" << json_escape(hosts_path(cfg)) << "\",\n"
      << "  \"unique_id_strategy\": \"host_id = SHA-256(host_name + ip + hardware + os_version) prefix\",\n"
      << "  \"status_timeout_seconds\": " << cfg.status_timeout_seconds << ",\n"
      << "  \"transport_security\": {\n"
      << "    \"authenticated\": " << (!cfg.auth_token.empty() ? "true" : "false") << ",\n"
      << "    \"tls_configured\": " << (cfg.use_tls ? "true" : "false") << ",\n"
      << "    \"command_queue_encryption\": \"AES-256-GCM\"\n"
      << "  },\n"
      << "  \"hosts\": [\n";
    for (std::size_t i = 0; i < hosts.size(); ++i) {
        o << host_to_json(hosts[i], i + 1 < hosts.size(), now, cfg.status_timeout_seconds);
    }
    o << "  ]\n"
      << "}";
    return o.str();
}

ByteBuffer command_key(const ManagerConfig& cfg, const std::string& host_id) {
    std::string secret = cfg.auth_token.empty() ? "auditforwarder-local-command-key" : cfg.auth_token;
    return crypto::sha256(secret + "|" + host_id);
}

Result<std::string> enqueue_host_command(const ManagerConfig& cfg,
                                         const HostRecord& host,
                                         const std::string& command_type,
                                         const std::string& payload) {
    auto cr = fs::create_directories(command_dir(cfg));
    if (cr.is_err()) return Result<std::string>(cr.error());

    std::string command_id = "cmd-" + crypto::random_hex(8);
    std::string queued_at = iso_time(epoch_seconds());
    std::ostringstream plain;
    plain << "{"
          << "\"command_id\":\"" << json_escape(command_id) << "\","
          << "\"target_host_id\":\"" << json_escape(host.id) << "\","
          << "\"command_type\":\"" << json_escape(command_type) << "\","
          << "\"payload\":\"" << json_escape(payload) << "\","
          << "\"queued_at\":\"" << queued_at << "\""
          << "}";
    auto key = command_key(cfg, host.id);
    auto plain_text = plain.str();
    auto encrypted = crypto::aes_gcm_encrypt(key, ByteBuffer(plain_text.begin(), plain_text.end()),
                                             ByteBuffer(host.id.begin(), host.id.end()));
    if (encrypted.error != 0) {
        return Result<std::string>(Error::Code::IoError, "command encryption failed");
    }
    auto path = fs::join(command_dir(cfg), host.id + ".jsonl");
    std::ofstream out(path, std::ios::binary | std::ios::app);
    if (!out) return Result<std::string>(Error::Code::IoError, "无法写入命令队列");
    out << "{"
        << "\"command_id\":\"" << json_escape(command_id) << "\","
        << "\"target_host_id\":\"" << json_escape(host.id) << "\","
        << "\"command_type\":\"" << json_escape(command_type) << "\","
        << "\"queued_at\":\"" << queued_at << "\","
        << "\"encryption\":\"AES-256-GCM\","
        << "\"iv\":\"" << crypto::to_hex(encrypted.iv) << "\","
        << "\"ciphertext\":\"" << crypto::to_hex(encrypted.ciphertext) << "\""
        << "}\n";
    return command_id;
}

}  // namespace

SimpleHttpManager::SimpleHttpManager(ManagerConfig cfg) : cfg_(std::move(cfg)) {}
SimpleHttpManager::~SimpleHttpManager() { stop(); }

bool SimpleHttpManager::is_session_token_valid(const std::string& token) {
    if (token.empty()) return false;
    auto now = epoch_seconds();
    std::lock_guard<std::mutex> lk(auth_mutex_);
    auto it = session_tokens_.find(token);
    if (it == session_tokens_.end()) return false;
    if (it->second.second <= now) {
        session_tokens_.erase(it);
        return false;
    }
    return true;
}

std::string SimpleHttpManager::create_session_token(const std::string& username, const std::string& client_ip) {
    auto token = "af-" + crypto::random_hex(32);
    auto expires = epoch_seconds() + 8 * 60 * 60;
    std::lock_guard<std::mutex> lk(auth_mutex_);
    session_tokens_[token] = { username + "@" + client_ip, expires };
    return token;
}

Result<void> SimpleHttpManager::start(Agent& agent) {
    agent_ = &agent;
#ifdef AF_PLATFORM_WINDOWS
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    auto colon = cfg_.listen.find(':');
    if (colon == std::string::npos)
        return Result<void>(Error::Code::InvalidArgument, "bad listen address");
    std::string host = cfg_.listen.substr(0, colon);
    int port = std::stoi(cfg_.listen.substr(colon + 1));

    if (cfg_.use_tls) {
        if (cfg_.tls_cert.empty() || cfg_.tls_key.empty()) {
            return Result<void>(Error::Code::InvalidArgument, "TLS enabled but certificate/key path is empty");
        }
        SSL_library_init();
        SSL_load_error_strings();
        const SSL_METHOD* method = TLS_server_method();
        SSL_CTX* ctx = SSL_CTX_new(method);
        if (!ctx) return Result<void>(Error::Code::IoError, "TLS context create failed");
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!MD5:!RC4:!3DES");
        if (SSL_CTX_use_certificate_file(ctx, cfg_.tls_cert.c_str(), SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_use_PrivateKey_file(ctx, cfg_.tls_key.c_str(), SSL_FILETYPE_PEM) != 1 ||
            SSL_CTX_check_private_key(ctx) != 1) {
            SSL_CTX_free(ctx);
            return Result<void>(Error::Code::IoError, "TLS certificate/key load failed");
        }
        if (cfg_.require_client_cert) {
            if (cfg_.tls_ca_cert.empty() ||
                SSL_CTX_load_verify_locations(ctx, cfg_.tls_ca_cert.c_str(), nullptr) != 1) {
                SSL_CTX_free(ctx);
                return Result<void>(Error::Code::IoError, "TLS client CA load failed");
            }
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
            if (cfg_.tls_crl_check) {
                auto* param = SSL_CTX_get0_param(ctx);
                X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
            }
        }
        tls_ctx_ = ctx;
    }

    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) return Result<void>(Error::Code::IoError, "socket");
    int one = 1;
    setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&one), sizeof(one));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(static_cast<u16>(port));
    if (host.empty() || host == "0.0.0.0") addr.sin_addr.s_addr = htonl(INADDR_ANY);
    else if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        // 尝试 DNS
        addrinfo hints{}; hints.ai_family = AF_INET;
        addrinfo* res = nullptr;
        if (::getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) {
            return Result<void>(Error::Code::NotFound, "bad host: " + host);
        }
        std::memcpy(&addr.sin_addr, &reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr, sizeof(in_addr));
        freeaddrinfo(res);
    }
    if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        return Result<void>(Error::Code::IoError, std::string("bind: ") + strerror(errno));
    }
    if (::listen(listen_fd_, 32) < 0) {
        return Result<void>(Error::Code::IoError, std::string("listen: ") + strerror(errno));
    }
    running_.store(true);
    // 旧扁平 operation_logs/<host>.jsonl → <host>/legacy.jsonl（幂等）
    migrate_flat_operation_logs(cfg_);
    // 确保过滤策略文件存在（首次启动写入默认 strict/lenient 档）
    (void)load_or_create_text(log_filter_profiles_path(cfg_), default_log_filter_profiles_json());
    load_remote_counters(cfg_);
    thr_ = std::thread([this] { accept_loop(); });

    // 启动后台 monitor：周期性扫描主机心跳，主动记录 online↔offline 状态迁移
    monitor_running_.store(true);
    monitor_thr_ = std::thread([this] {
        std::map<std::string, bool> prev_online;   // host_id → 上轮判定
        while (monitor_running_.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            if (!monitor_running_.load()) break;
            auto hosts_r = load_hosts(cfg_);
            if (hosts_r.is_err()) continue;
            auto hosts = hosts_r.value();
            auto now   = epoch_seconds();
            for (const auto& h : hosts) {
                bool online = host_online(h, now, cfg_.status_timeout_seconds);
                auto it = prev_online.find(h.id);
                if (it != prev_online.end()) {
                    if (it->second && !online) {
                        u64 gap = now - h.last_seen_epoch;
                        AF_LOG_WARN("monitor: host OFFLINE  id=" << h.id
                                    << " name=" << h.name
                                    << " last_seen=" << iso_time(h.last_seen_epoch)
                                    << " gap=" << gap << "s (timeout=" << cfg_.status_timeout_seconds << "s)");
                    } else if (!it->second && online) {
                        AF_LOG_INFO("monitor: host ONLINE   id=" << h.id
                                   << " name=" << h.name);
                    }
                }
                prev_online[h.id] = online;
            }
            // 清理已从 hosts.json 移除的旧记录
            std::set<std::string> live_ids;
            for (const auto& h : hosts) live_ids.insert(h.id);
            for (auto it = prev_online.begin(); it != prev_online.end(); ) {
                if (!live_ids.count(it->first)) it = prev_online.erase(it);
                else ++it;
            }
            // 周期持久化聚合计数器
            save_remote_counters(cfg_);
        }
    });

    AF_LOG_INFO("manager: listening on " << cfg_.listen
                << "  (status_timeout=" << cfg_.status_timeout_seconds << "s)");
    return Result<void>::ok();
}

void SimpleHttpManager::stop() {
    if (!running_.exchange(false)) return;
    monitor_running_.store(false);
    if (listen_fd_ >= 0) {
        ::shutdown(listen_fd_, 2);
        ::close(listen_fd_);
        listen_fd_ = -1;
    }
    if (monitor_thr_.joinable()) monitor_thr_.join();
    if (thr_.joinable()) thr_.join();
    if (tls_ctx_) {
        SSL_CTX_free(static_cast<SSL_CTX*>(tls_ctx_));
        tls_ctx_ = nullptr;
    }
#ifdef AF_PLATFORM_WINDOWS
    WSACleanup();
#endif
}

void SimpleHttpManager::accept_loop() {
    while (running_.load()) {
        sockaddr_in cli{}; socklen_t cl = sizeof(cli);
        int cfd = ::accept(listen_fd_, reinterpret_cast<sockaddr*>(&cli), &cl);
        if (cfd < 0) {
            if (!running_.load()) return;
            continue;
        }
        // 为简化，每个线程处理一个客户端（此处无线程池依赖）
        std::thread([this, cfd] {
            SSL* ssl = nullptr;
            if (tls_ctx_) {
                ssl = SSL_new(static_cast<SSL_CTX*>(tls_ctx_));
                if (!ssl) { ::close(cfd); return; }
                SSL_set_fd(ssl, cfd);
                if (SSL_accept(ssl) <= 0) {
                    SSL_free(ssl);
                    ::close(cfd);
                    return;
                }
            }
            handle_client(cfd, ssl);
            if (ssl) {
                SSL_shutdown(ssl);
                SSL_free(ssl);
            }
            ::close(cfd);
        }).detach();
    }
}

void SimpleHttpManager::handle_client(int fd, void* tls) {
    std::string req;
    char buf[4096];
    int n;
    while ((n = conn_recv(fd, tls, buf, sizeof(buf))) > 0) {
        req.append(buf, n);
        if (req.find("\r\n\r\n") != std::string::npos) break;
    }
    if (req.empty()) return;

    // 解析请求行
    std::istringstream iss(req);
    std::string method, target, version;
    iss >> method >> target >> version;

    // Body (after \r\n\r\n)
    std::string body;
    auto bp = req.find("\r\n\r\n");
    if (bp != std::string::npos) body = req.substr(bp + 4);

    std::size_t content_length = 0;
    {
        std::istringstream hl(req.substr(0, bp == std::string::npos ? req.size() : bp));
        std::string line;
        std::getline(hl, line);
        while (std::getline(hl, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            auto colon = line.find(':');
            if (colon != std::string::npos) {
                std::string key = line.substr(0, colon);
                std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) {
                    return static_cast<char>(std::tolower(c));
                });
                if (key == "content-length") {
                    try {
                        content_length = static_cast<std::size_t>(std::stoull(line.substr(colon + 1)));
                    } catch (...) {
                        content_length = 0;
                    }
                }
            }
        }
    }
    while (content_length > 0 && body.size() < content_length &&
           (n = conn_recv(fd, tls, buf, sizeof(buf))) > 0) {
        body.append(buf, n);
    }

    std::string path = target;
    std::string query;
    auto q = path.find('?');
    if (q != std::string::npos) { query = path.substr(q + 1); path = path.substr(0, q); }
    auto client_ip = peer_ip(fd);

    // 头部（认证检查）。前端静态页面和登录接口允许直接访问，页面内的 API 请求仍按 Token 认证。
    bool auth_ok = cfg_.auth_token.empty() || is_public_path(path);
    {
        std::istringstream hl(req.substr(0, bp == std::string::npos ? req.size() : bp));
        std::string line;
        std::getline(hl, line);
        while (std::getline(hl, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            auto colon = line.find(':');
            if (colon != std::string::npos) {
                std::string key = line.substr(0, colon);
                std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) {
                    return static_cast<char>(std::tolower(c));
                });
                if (key == "authorization") {
                    std::string v = line.substr(colon + 1);
                    // 去除空格
                    while (!v.empty() && v.front() == ' ') v.erase(0, 1);
                    if (v.size() > 7 && v.substr(0, 7) == "Bearer ") v = v.substr(7);
                    if (v == cfg_.auth_token || is_session_token_valid(v)) auth_ok = true;
                }
            }
            if (line.empty()) break;
        }
    }

    std::string content_type = "application/json";
    int status = 200;
    std::string resp_body;
    if (!auth_ok) {
        status = 401;
        resp_body = "{\"error\":\"unauthorized\"}";
    } else {
        resp_body = route(method, path, query, body, content_type, status, client_ip);
    }

    std::ostringstream resp;
    resp << "HTTP/1.1 " << status << " " << status_text(status) << "\r\n"
         << "Content-Type: " << content_type << "\r\n"
         << "Content-Length: " << resp_body.size() << "\r\n"
         << "Connection: close\r\n"
         << "Server: AuditForwarder/1.0\r\n"
         << "X-Content-Type-Options: nosniff\r\n"
         << "X-Frame-Options: DENY\r\n"
         << "Referrer-Policy: no-referrer\r\n"
         << "Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'\r\n"
         << "Cache-Control: " << (is_ui_path(path) && path.rfind("/assets/", 0) == 0
                                  ? "public, max-age=300"
                                  : "no-store") << "\r\n"
         << "\r\n"
         << resp_body;
    auto s = resp.str();
    conn_send(fd, tls, s.data(), static_cast<int>(s.size()));
}

std::string SimpleHttpManager::route(const std::string& method, const std::string& path,
                                     const std::string& query, const std::string& body,
                                     std::string& content_type, int& status,
                                     const std::string& client_ip) {
    if (method == "GET" && is_ui_path(path)) {
        content_type = content_type_for(path);
        auto asset = read_ui_asset(path);
        if (asset.is_err()) {
            status = 404;
            content_type = "application/json";
            return "{\n  \"error\": \"ui asset not found\"\n}";
        }
        return asset.value();
    }
    if (path == "/auth/login" && method == "POST") {
        content_type = "application/json; charset=utf-8";
        auto username = json_string_field(body, "username");
        auto password_hash = json_string_field(body, "password_sha256");
        auto key = username + "|" + client_ip;
        auto now = epoch_seconds();
        {
            std::lock_guard<std::mutex> lk(auth_mutex_);
            auto it = login_failures_.find(key);
            if (it != login_failures_.end() && it->second.first >= 3 && it->second.second > now) {
                status = 429;
                append_login_audit(cfg_, username, client_ip, "locked", "连续登录失败次数过多，账号临时锁定");
                std::ostringstream o;
                o << "{\n"
                  << "  \"error\": \"login_locked\",\n"
                  << "  \"message\": \"登录失败次数过多，请 15 分钟后再试。\",\n"
                  << "  \"locked_until\": \"" << iso_time(it->second.second) << "\"\n"
                  << "}";
                return o.str();
            }
        }

        auto expected_user = cfg_.login_username.empty() ? std::string("admin") : cfg_.login_username;
        bool user_ok = constant_time_equal(username, expected_user);
        bool password_ok = constant_time_equal(password_hash, effective_login_hash(cfg_));
        if (!user_ok || !password_ok) {
            std::uint64_t locked_until = 0;
            int attempts = 0;
            {
                std::lock_guard<std::mutex> lk(auth_mutex_);
                auto& failure = login_failures_[key];
                attempts = ++failure.first;
                if (attempts >= 3) {
                    failure.second = now + 15 * 60;
                    locked_until = failure.second;
                }
            }
            append_login_audit(cfg_, username, client_ip, "failure", "账号或密码验证失败");
            status = attempts >= 3 ? 429 : 401;
            std::ostringstream o;
            o << "{\n"
              << "  \"error\": \"" << (attempts >= 3 ? "login_locked" : "invalid_credentials") << "\",\n"
              << "  \"message\": \"" << (attempts >= 3 ? "登录失败次数过多，请 15 分钟后再试。" : "账号或密码不正确。") << "\",\n"
              << "  \"remaining_attempts\": " << (attempts >= 3 ? 0 : 3 - attempts);
            if (locked_until > 0) {
                o << ",\n  \"locked_until\": \"" << iso_time(locked_until) << "\"";
            }
            o << "\n}";
            return o.str();
        }

        {
            std::lock_guard<std::mutex> lk(auth_mutex_);
            login_failures_.erase(key);
        }
        auto token = create_session_token(username, client_ip);
        append_login_audit(cfg_, username, client_ip, "success", "登录成功并签发会话 Token");
        std::ostringstream o;
        o << "{\n"
          << "  \"token\": \"" << json_escape(token) << "\",\n"
          << "  \"token_type\": \"Bearer\",\n"
          << "  \"expires_in\": " << (8 * 60 * 60) << ",\n"
          << "  \"username\": \"" << json_escape(username) << "\",\n"
          << "  \"redirect\": \"/\"\n"
          << "}";
        return o.str();
    }
    if (path == "/health" || path == "/status") {
        if (!agent_) { status = 503; return "{\n}"; }
        auto s = agent_->stats();
        // 叠加远端客户端上报的聚合计数
        u64 remote_collected = g_remote_events_collected.load(std::memory_order_relaxed);
        u64 remote_uploaded  = g_remote_events_uploaded.load(std::memory_order_relaxed);
        u64 remote_bytes     = g_remote_bytes_uploaded.load(std::memory_order_relaxed);
        u64 remote_alerts    = g_remote_alerts.load(std::memory_order_relaxed);
        std::ostringstream o;
        o << "{\n"
          << "  \"running\": " << (agent_->is_running() ? "true" : "false") << ",\n"
          << "  \"events_collected\": " << (s.events_collected + remote_collected) << ",\n"
          << "  \"events_uploaded\": " << (s.events_uploaded + remote_uploaded) << ",\n"
          << "  \"events_failed\": " << s.events_failed << ",\n"
          << "  \"events_dropped\": " << s.events_dropped << ",\n"
          << "  \"alerts\": " << (s.alerts + remote_alerts) << ",\n"
          << "  \"bytes_uploaded\": " << (s.bytes_uploaded + remote_bytes) << ",\n"
          << "  \"uptime_seconds\": " << s.uptime_seconds << "\n"
          << "}";
        return o.str();
    }
    if (path == "/config" && method == "GET") {
        content_type = "text/plain";
        return af::Config::instance().dump_json();
    }
    if (path == "/config/reload" && method == "POST") {
        auto r = agent_->reload_config();
        if (r.is_err()) {
            status = 500;
            std::ostringstream o;
            o << "{\n"
              << "  \"error\": \"" << r.error().message() << "\"\n"
              << "}";
            return o.str();
        }
        return "{\n  \"status\": \"reloaded\"\n}";
    }
    if (path == "/validation/rules" && method == "GET") {
        content_type = "application/json; charset=utf-8";
        return validation_rules_json();
    }
    if (path == "/status/thresholds" && method == "GET") {
        content_type = "application/json; charset=utf-8";
        auto policy = load_or_create_text(thresholds_path(cfg_), default_thresholds_json());
        if (policy.is_err()) {
            status = 500;
            return "{\n  \"error\": \"cannot load thresholds\"\n}";
        }
        return policy.value();
    }
    if (path == "/status/thresholds" && method == "PUT") {
        content_type = "application/json; charset=utf-8";
        if (body.find('{') == std::string::npos) {
            status = 422;
            return validation_error_json({{"thresholds", "format", "阈值配置必须是 JSON 对象"}});
        }
        auto saved = write_text_file(thresholds_path(cfg_), body);
        if (saved.is_err()) {
            status = 500;
            return "{\n  \"error\": \"cannot save thresholds\"\n}";
        }
        return "{\n  \"saved\": true,\n  \"policy\": \"status_thresholds\"\n}";
    }
    if (path == "/violation/rules" && method == "GET") {
        content_type = "application/json; charset=utf-8";
        auto rules = load_or_create_text(violation_rules_path(cfg_), default_violation_rules_json());
        if (rules.is_err()) {
            status = 500;
            return "{\n  \"error\": \"cannot load violation rules\"\n}";
        }
        return rules.value();
    }
    if (path == "/violation/rules" && method == "PUT") {
        content_type = "application/json; charset=utf-8";
        if (body.find("\"rules\"") == std::string::npos) {
            status = 422;
            return validation_error_json({{"rules", "format", "违规规则配置必须包含 rules 数组"}});
        }
        auto saved = write_text_file(violation_rules_path(cfg_), body);
        if (saved.is_err()) {
            status = 500;
            return "{\n  \"error\": \"cannot save violation rules\"\n}";
        }
        return "{\n  \"saved\": true,\n  \"policy\": \"violation_rules\"\n}";
    }
    // 违规规则统一下发：把当前 violation_rules.json 通过远程命令通道（load_rules）
    // 热加载到指定主机或全部已注册主机，消除“双份规则双份维护”。
    if (path == "/violation/rules/push" && method == "POST") {
        content_type = "application/json; charset=utf-8";
        auto target_host = json_string_field(body, "host_id");
        if (!target_host.empty() && !is_valid_host_id(target_host)) {
            status = 422;
            return validation_error_json({{"host_id", "format", "目标主机 ID 格式不正确"}});
        }
        auto rules = read_text_file(violation_rules_path(cfg_));
        if (rules.is_err() || rules.value().empty()) {
            status = 500;
            return "{\n  \"error\": \"cannot load violation rules for push\"\n}";
        }
        // 规则 JSON 作为命令 payload，需要大于普通指令的长度配额（约 60KB 上限）。
        if (rules.value().size() > 60000) {
            status = 413;
            return "{\n  \"error\": \"violation rules too large for remote push (limit 60KB)\"\n}";
        }

        std::vector<HostRecord> targets;
        if (target_host.empty()) {
            auto hosts = load_hosts(cfg_);
            if (hosts.is_err()) {
                status = 500;
                return "{\n  \"error\": \"cannot load hosts\"\n}";
            }
            targets = hosts.value();
        } else {
            auto hosts = load_hosts(cfg_);
            if (hosts.is_err()) {
                status = 500;
                return "{\n  \"error\": \"cannot load hosts\"\n}";
            }
            bool found = false;
            for (const auto& h : hosts.value()) {
                if (h.id == target_host) { targets.push_back(h); found = true; break; }
            }
            if (!found) {
                status = 404;
                return "{\n  \"error\": \"target host not registered\"\n}";
            }
        }

        std::vector<std::string> command_ids;
        int queued_count = 0;
        {
            std::lock_guard<std::mutex> lk(host_store_mutex());
            for (const auto& h : targets) {
                auto qid = enqueue_host_command(cfg_, h, "load_rules", rules.value());
                if (qid.is_err()) {
                    AF_LOG_WARN("规则下发: 主机 " << h.id << " 入队失败: " << qid.error().message());
                    continue;
                }
                command_ids.push_back(qid.value());
                ++queued_count;
            }
        }
        AF_LOG_INFO("violation rules pushed to " << queued_count << " host(s)"
                    << (target_host.empty() ? "（全部主机）" : "（指定主机）"));
        std::ostringstream o;
        o << "{\n"
          << "  \"accepted\": true,\n"
          << "  \"command_type\": \"load_rules\",\n"
          << "  \"target\": \"" << json_escape(target_host.empty() ? "*" : target_host) << "\",\n"
          << "  \"queued_count\": " << queued_count << ",\n"
          << "  \"command_ids\": [";
        for (std::size_t i = 0; i < command_ids.size(); ++i) {
            if (i) o << ",";
            o << "\"" << json_escape(command_ids[i]) << "\"";
        }
        o << "]\n}";
        return o.str();
    }
    if (path == "/log-filter/profiles" && method == "GET") {
        content_type = "application/json; charset=utf-8";
        auto profiles = load_or_create_text(log_filter_profiles_path(cfg_),
                                            default_log_filter_profiles_json());
        if (profiles.is_err()) {
            status = 500;
            return "{\n  \"error\": \"cannot load log filter profiles\"\n}";
        }
        return profiles.value();
    }
    if (path == "/log-filter/profiles" && method == "PUT") {
        content_type = "application/json; charset=utf-8";
        if (body.find("\"profiles\"") == std::string::npos) {
            status = 422;
            return validation_error_json({{"profiles", "format", "过滤策略必须包含 profiles 数组"}});
        }
        auto saved = write_text_file(log_filter_profiles_path(cfg_), body);
        if (saved.is_err()) {
            status = 500;
            return "{\n  \"error\": \"cannot save log filter profiles\"\n}";
        }
        return "{\n  \"saved\": true,\n  \"policy\": \"log_filter_profiles\"\n}";
    }
    if (path == "/rbac/policy" && method == "GET") {
        content_type = "application/json; charset=utf-8";
        auto policy = load_or_create_text(rbac_policy_path(cfg_), default_rbac_policy_json());
        if (policy.is_err()) {
            status = 500;
            return "{\n  \"error\": \"cannot load rbac policy\"\n}";
        }
        return policy.value();
    }
    if (path == "/batches" && method == "GET") {
        auto lst = agent_->chain_module().recent_batches(50);
        if (lst.is_err()) {
            status = 500;
            return "{\n  \"batches\": []\n}";
        }
        std::ostringstream o;
        o << "{\n"
          << "  \"batches\": [";
        bool first = true;
        for (const auto& b : lst.value()) {
            if (!first) o << ",";
            first = false;
            o << "\n    {\n"
              << "      \"id\": \"" << b.id << "\",\n"
              << "      \"merkle_root\": \"" << b.merkle_root << "\",\n"
              << "      \"signature\": \"" << b.signature << "\"\n"
              << "    }";
        }
        o << "\n  ]\n"
          << "}";
        return o.str();
    }
    if (path == "/hosts" && method == "GET") {
        content_type = "application/json; charset=utf-8";
        std::lock_guard<std::mutex> lk(host_store_mutex());
        auto hosts = load_hosts(cfg_);
        if (hosts.is_err()) {
            status = 500;
            return "{\n  \"error\": \"cannot load hosts\"\n}";
        }
        return hosts_response_json(hosts.value(), cfg_);
    }
    if (path == "/hosts" && method == "POST") {
        content_type = "application/json; charset=utf-8";
        auto incoming = host_from_json(body);
        auto issues = validate_host_record(incoming, true);
        if (!issues.empty()) {
            status = 422;
            return validation_error_json(issues);
        }
        std::lock_guard<std::mutex> lk(host_store_mutex());
        auto hosts = load_hosts(cfg_);
        if (hosts.is_err()) {
            status = 500;
            return "{\n  \"error\": \"cannot load hosts\"\n}";
        }
        auto list = hosts.value();
        if (cfg_.max_host_count > 0 && list.size() >= cfg_.max_host_count) {
            status = 409;
            return "{\n  \"error\": \"max_host_count reached\"\n}";
        }
        for (const auto& h : list) {
            if (h.id == incoming.id) {
                status = 409;
                return "{\n  \"error\": \"host id already exists\"\n}";
            }
        }
        list.push_back(std::move(incoming));
        auto saved = save_hosts(cfg_, list);
        if (saved.is_err()) {
            status = 500;
            return "{\n  \"error\": \"cannot save hosts\"\n}";
        }
        return hosts_response_json(list, cfg_);
    }
    if (path == "/hosts" && method == "PUT") {
        content_type = "application/json; charset=utf-8";
        auto id = query_param(query, "id");
        auto incoming = host_from_json(body);
        if (id.empty()) id = incoming.id;
        if (id.empty()) {
            status = 422;
            return validation_error_json({{"id", "required", "主机 ID 不能为空"}});
        }
        incoming.id = id;
        std::lock_guard<std::mutex> lk(host_store_mutex());
        auto hosts = load_hosts(cfg_);
        if (hosts.is_err()) {
            status = 500;
            return "{\n  \"error\": \"cannot load hosts\"\n}";
        }
        auto list = hosts.value();
        bool updated = false;
        for (auto& h : list) {
            if (h.id == id) {
                if (incoming.name.empty()) incoming.name = h.name;
                if (incoming.ip_address.empty()) incoming.ip_address = h.ip_address;
                if (incoming.hardware.empty()) incoming.hardware = h.hardware;
                if (incoming.os_version.empty()) incoming.os_version = h.os_version;
                if (incoming.network_status.empty()) incoming.network_status = h.network_status;
                if (incoming.note.empty()) incoming.note = h.note;
                if (incoming.last_seen_epoch == 0) incoming.last_seen_epoch = h.last_seen_epoch;
                if (incoming.permissions.empty()) incoming.permissions = h.permissions;
                auto issues = validate_host_record(incoming, true);
                if (!issues.empty()) {
                    status = 422;
                    return validation_error_json(issues);
                }
                h = std::move(incoming);
                updated = true;
                break;
            }
        }
        if (!updated) {
            status = 404;
            return "{\n  \"error\": \"host not found\"\n}";
        }
        auto saved = save_hosts(cfg_, list);
        if (saved.is_err()) {
            status = 500;
            return "{\n  \"error\": \"cannot save hosts\"\n}";
        }
        return hosts_response_json(list, cfg_);
    }
    if (path == "/hosts" && method == "DELETE") {
        content_type = "application/json; charset=utf-8";
        auto id = query_param(query, "id");
        if (id.empty()) id = json_string_field(body, "id");
        if (id.empty()) id = json_string_field(body, "host_id");
        if (id.empty()) {
            status = 422;
            return validation_error_json({{"id", "required", "主机 ID 不能为空"}});
        }
        if (!is_valid_host_id(id)) {
            status = 422;
            return validation_error_json({{"id", "format", "主机 ID 格式不正确"}});
        }
        std::lock_guard<std::mutex> lk(host_store_mutex());
        auto hosts = load_hosts(cfg_);
        if (hosts.is_err()) {
            status = 500;
            return "{\n  \"error\": \"cannot load hosts\"\n}";
        }
        auto list = hosts.value();
        auto old_size = list.size();
        list.erase(std::remove_if(list.begin(), list.end(),
                                  [&](const HostRecord& h) { return h.id == id; }),
                   list.end());
        if (list.size() == old_size) {
            status = 404;
            return "{\n  \"error\": \"host not found\"\n}";
        }
        auto saved = save_hosts(cfg_, list);
        if (saved.is_err()) {
            status = 500;
            return "{\n  \"error\": \"cannot save hosts\"\n}";
        }
        return hosts_response_json(list, cfg_);
    }
    // 一键生成客户端接入包：Web 控制台填写主机名即可下载预填好的 client_windows.yaml，
    // 新电脑放置该配置后启动客户端即自动注册上线，无需手工修改配置文件。
    // 请求体：{"host_name":"...","server_addr":"ip:port","use_tls":false}
    // server_addr 由前端取当前浏览器访问地址（服务端自身无法得知对外 IP）。
    if (path == "/hosts/enrollment-package" && method == "POST") {
        content_type = "application/json; charset=utf-8";
        auto host_name = json_string_field(body, "host_name");
        auto server_addr = json_string_field(body, "server_addr");
        bool use_tls = json_bool_field(body, "use_tls", false);
        if (host_name.empty()) {
            status = 422;
            return "{\n  \"error\": \"host_name required\"\n}";
        }
        if (host_name.size() > 80) host_name.resize(80);
        if (server_addr.empty()) server_addr = cfg_.listen;  // 兜底：前端未传时用监听地址
        // 生成唯一 host_id：前缀 + 随机十六进制，避免与已注册主机冲突
        auto host_id = "agent-" + crypto::random_hex(4);
        const std::string scheme = use_tls ? "https" : "http";

        std::ostringstream yaml;
        yaml << "# AuditForwarder - 客户端接入配置（由服务端 Web 控制台一键生成）\n"
             << "# 主机名称: " << host_name << "\n"
             << "# 生成时间: " << iso_time(epoch_seconds()) << "\n"
             << "# 使用方法: 将本文件放到客户端目录 config/client_windows.yaml 后启动客户端\n\n"
             << "agent:\n"
             << "  id: \"" << host_id << "\"\n"
             << "  data_dir: data/client\n"
             << "  config_path: config/client_windows.yaml\n\n"
             << "log:\n"
             << "  level: info\n"
             << "  file: data/client/client.log\n"
             << "  max_bytes: 52428800\n"
             << "  max_backups: 5\n\n"
             << "chain:\n"
             << "  batch_size: 10\n"
             << "  sign_batches: false\n"
             << "  auto_persist: true\n"
             << "  hmac_key: \"" << cfg_.chain_hmac_key << "\"\n\n"
             << "transport:\n"
             << "  servers:\n"
             << "    - \"" << scheme << "://" << server_addr << "/ingest?agent=" << host_id << "\"\n"
             << "  mode: realtime\n"
             << "  interval_sec: 5\n"
             << "  compress: true\n"
             << "  encrypt_payload: false\n"
             << "  auth_token: \"" << cfg_.auth_token << "\"\n"
             << "  verify_tls: false\n\n"
             << "remote:\n"
             << "  enabled: true\n"
             << "  servers:\n"
             << "    - \"" << scheme << "://" << server_addr << "\"\n"
             << "  host_id: \"" << host_id << "\"\n"
             << "  heartbeat_interval_sec: 5\n"
             << "  command_poll_interval_sec: 3\n"
             << "  audit_summary_interval_sec: 5\n"
             << "  production_mode: false\n"
             << "  require_tls: " << (use_tls ? "true" : "false") << "\n"
             << "  crl_check: false\n"
             << "  enrollment_key: \"" << cfg_.enrollment_key << "\"\n"
             << "  allowed_commands:\n"
             << "    - collect_status\n"
             << "    - echo\n"
             << "    - set_collector\n"
             << "    - set_collectors\n"
             << "    - load_rules\n\n"
             << "detector:\n"
             << "  rules_path: config/rules.yaml\n"
             << "  enable_behavior_baseline: true\n\n"
             << "self_protect:\n"
             << "  enabled: false\n\n"
             << "manager:\n"
             << "  enabled: false\n"
             << "  auth_token: \"" << cfg_.auth_token << "\"\n\n"
             << "collectors:\n"
             << "  enabled: true\n\n"
             << "privilege_detect:\n"
             << "  enabled: true\n\n"
             << "test_injection:\n"
             << "  enabled: false\n"
             << "  interval_ms: 1000\n\n"
             << "processors:\n"
             << "  - type: enricher\n"
             << "  - type: pii_masker\n"
             << "  - type: deduper\n"
             << "    window_ms: 50\n";

        // 预登记主机（离线状态）：管理员生成后即可在主机列表看到，客户端首次心跳自动转在线
        bool pre_registered = false;
        {
            std::lock_guard<std::mutex> lk(host_store_mutex());
            auto hosts_r = load_hosts(cfg_);
            if (hosts_r.is_ok()) {
                auto list = hosts_r.value();
                bool exists = false;
                for (const auto& h : list) {
                    if (h.id == host_id) { exists = true; break; }
                }
                if (!exists && (cfg_.max_host_count == 0 || list.size() < cfg_.max_host_count)) {
                    HostRecord rec;
                    rec.id = host_id;
                    rec.name = host_name;
                    rec.network_status = "offline";
                    rec.permissions = {"status_view"};
                    auto issues = validate_host_record(rec, false);
                    if (issues.empty()) {
                        list.push_back(std::move(rec));
                        pre_registered = save_hosts(cfg_, list).is_ok();
                    }
                }
            }
        }

        std::ostringstream o;
        o << "{\n"
          << "  \"host_id\": \"" << json_escape(host_id) << "\",\n"
          << "  \"host_name\": \"" << json_escape(host_name) << "\",\n"
          << "  \"file_name\": \"client_windows_" << json_escape(host_id) << ".yaml\",\n"
          << "  \"pre_registered\": " << (pre_registered ? "true" : "false") << ",\n"
          << "  \"yaml\": \"" << json_escape(yaml.str()) << "\"\n"
          << "}";
        return o.str();
    }
    if ((path == "/hosts/heartbeat" || path == "/hosts/register") && method == "POST") {
        content_type = "application/json; charset=utf-8";
        if (!enrollment_key_valid(cfg_, body)) {
            status = 401;
            return "{\n"
                   "  \"error\": \"invalid_enrollment_key\",\n"
                   "  \"message\": \"客户端注册密钥验证失败，主机未加入监管系统\"\n"
                   "}";
        }
        auto incoming = host_from_json(body);
        incoming.last_seen_epoch = epoch_seconds();
        incoming.network_status = "online";
        if (incoming.name.empty()) incoming.name = incoming.id;
        auto issues = validate_host_record(incoming, false);
        if (!issues.empty()) {
            status = 422;
            return validation_error_json(issues);
        }
        std::lock_guard<std::mutex> lk(host_store_mutex());
        auto hosts = load_hosts(cfg_);
        if (hosts.is_err()) {
            status = 500;
            return "{\n  \"error\": \"cannot load hosts\"\n}";
        }
        auto list = hosts.value();
        bool updated = false;
        for (auto& h : list) {
            if (h.id == incoming.id) {
                if (!incoming.name.empty()) h.name = incoming.name;
                if (!incoming.ip_address.empty()) h.ip_address = incoming.ip_address;
                if (!incoming.hardware.empty()) h.hardware = incoming.hardware;
                if (!incoming.os_version.empty()) h.os_version = incoming.os_version;
                h.network_status = incoming.network_status;
                h.last_seen_epoch = incoming.last_seen_epoch;
                h.cpu_usage_percent = incoming.cpu_usage_percent;
                h.memory_usage_percent = incoming.memory_usage_percent;
                if (!incoming.permissions.empty()) h.permissions = incoming.permissions;
                // 透传采集器运行状态（心跳携带），供 Web 面板开关展示。
                if (!incoming.collectors_state.empty()) h.collectors_state = incoming.collectors_state;
                updated = true;
                break;
            }
        }
        if (!updated) {
            if (cfg_.max_host_count > 0 && list.size() >= cfg_.max_host_count) {
                status = 409;
                return "{\n  \"error\": \"max_host_count reached\"\n}";
            }
            list.push_back(std::move(incoming));
        }
        auto saved = save_hosts(cfg_, list);
        if (saved.is_err()) {
            status = 500;
            return "{\n  \"error\": \"cannot save hosts\"\n}";
        }
        return hosts_response_json(list, cfg_);
    }
    if (path == "/hosts/commands" && method == "GET") {
        content_type = "application/json; charset=utf-8";
        auto id = query_param(query, "host_id");
        if (id.empty()) {
            status = 422;
            return validation_error_json({{"host_id", "required", "主机 ID 不能为空"}});
        }
        if (!is_valid_host_id(id)) {
            status = 422;
            return validation_error_json({{"host_id", "format", "主机 ID 格式不正确"}});
        }
        auto queue_path = fs::join(command_dir(cfg_), id + ".jsonl");
        auto content = read_text_file(queue_path);
        std::ostringstream o;
        o << "{\n"
          << "  \"host_id\": \"" << json_escape(id) << "\",\n"
          << "  \"encrypted\": true,\n"
          << "  \"commands_jsonl\": \"" << json_escape(content.is_ok() ? content.value() : "") << "\"\n"
          << "}";
        return o.str();
    }
    if (path == "/remote/control" && method == "POST") {
        content_type = "application/json; charset=utf-8";
        auto target_id = json_string_field(body, "target_host_id");
        if (target_id.empty()) target_id = json_string_field(body, "host_id");
        auto command_type = json_string_field(body, "command_type");
        auto payload = json_string_field(body, "payload");
        auto issues = validate_remote_command(target_id, command_type, payload);
        if (!issues.empty()) {
            status = 422;
            return validation_error_json(issues);
        }
        std::lock_guard<std::mutex> lk(host_store_mutex());
        auto hosts = load_hosts(cfg_);
        if (hosts.is_err()) {
            status = 500;
            return "{\n  \"error\": \"cannot load hosts\"\n}";
        }
        const HostRecord* target = nullptr;
        for (const auto& h : hosts.value()) {
            if (h.id == target_id) {
                target = &h;
                break;
            }
        }
        if (!target) {
            status = 404;
            return "{\n  \"error\": \"target host not found\"\n}";
        }
        if (!has_permission(*target, command_type)) {
            status = 401;
            return "{\n  \"error\": \"host permission denied for command\"\n}";
        }
        auto queued = enqueue_host_command(cfg_, *target, command_type, payload);
        if (queued.is_err()) {
            status = 500;
            return "{\n  \"error\": \"cannot queue command\"\n}";
        }
        status = 202;
        std::ostringstream o;
        o << "{\n"
          << "  \"accepted\": true,\n"
          << "  \"command_id\": \"" << queued.value() << "\",\n"
          << "  \"target_host_id\": \"" << json_escape(target_id) << "\",\n"
          << "  \"queued\": true,\n"
          << "  \"queue_encryption\": \"AES-256-GCM\"\n"
          << "}";
        return o.str();
    }
    // POST /ingest — 接收 transport 层上传的审计事件批次（原始字节流）
    if (path == "/ingest" && method == "POST") {
        content_type = "application/json; charset=utf-8";
        auto agent_id = query_param(query, "agent");
        if (agent_id.empty()) agent_id = "unknown";
        // 用 body 的 SHA-256 前 16 字符做 batch_id，保证唯一
        auto batch_id = crypto::sha256_hex(body).substr(0, 16);
        // 保存原始批次到 data/ingested_batches/<agent_id>/<batch_id>.bin
        auto dir = fs::join(cfg_.data_dir.empty() ? "data" : cfg_.data_dir, "ingested_batches");
        fs::create_directories(dir);
        auto agent_dir = fs::join(dir, agent_id);
        fs::create_directories(agent_dir);
        auto file_path = fs::join(agent_dir, batch_id + ".bin");
        std::ofstream out(file_path, std::ios::binary | std::ios::trunc);
        if (!out) {
            status = 500;
            return "{\n  \"error\": \"cannot write batch file\"\n}";
        }
        out.write(body.data(), static_cast<std::streamsize>(body.size()));
        out.flush();
        g_remote_bytes_uploaded.fetch_add(body.size(), std::memory_order_relaxed);
        AF_LOG_INFO("ingest: received batch id=" << batch_id
                    << " agent=" << agent_id
                    << " bytes=" << body.size());
        std::ostringstream o;
        o << "{\n"
          << "  \"accepted\": true,\n"
          << "  \"batch_id\": \"" << json_escape(batch_id) << "\",\n"
          << "  \"agent_id\": \"" << json_escape(agent_id) << "\",\n"
          << "  \"bytes_received\": " << body.size() << ",\n"
          << "  \"storage\": \"" << json_escape(file_path) << "\"\n"
          << "}";
        return o.str();
    }
    if (path == "/agent/metrics" && method == "POST") {
        content_type = "application/json; charset=utf-8";
        auto host_id = json_string_field(body, "host_id");
        if (host_id.empty() || !is_valid_host_id(host_id)) {
            status = 422;
            return validation_error_json({{"host_id", "format", "主机 ID 不能为空且只能包含字母、数字、短横线和下划线"}});
        }
        std::lock_guard<std::mutex> lk(host_store_mutex());
        auto saved = append_jsonl_retained(host_metrics_dir(cfg_), host_id + ".jsonl", body, 10000);
        if (saved.is_err()) {
            status = 500;
            return "{\n  \"error\": \"cannot save host metrics\"\n}";
        }
        evaluate_metric_thresholds(cfg_, host_id, body);
        std::ostringstream o;
        o << "{\n"
          << "  \"accepted\": true,\n"
          << "  \"host_id\": \"" << json_escape(host_id) << "\",\n"
          << "  \"storage\": \"" << json_escape(fs::join(host_metrics_dir(cfg_), host_id + ".jsonl")) << "\",\n"
          << "  \"retention\": \"last 10000 metric records per host\"\n"
          << "}";
        return o.str();
    }
    if (path == "/agent/operation-logs" && method == "POST") {
        content_type = "application/json; charset=utf-8";
        auto objects = json_object_array_field(body, "logs");
        if (objects.empty()) objects.push_back(body);
        std::size_t accepted = 0;
        std::string first_host;
        // 收集需在锁外做违规规则复查的条目，缩短全局锁临界区
        std::vector<std::pair<std::string, std::string>> pending_rule_eval;
        std::string response_body;
        {
            std::lock_guard<std::mutex> lk(host_store_mutex());
            for (const auto& raw_item : objects) {
            auto host_id = json_string_field(raw_item, "host_id");
            if (host_id.empty()) host_id = json_string_field(body, "host_id");
            if (host_id.empty() || !is_valid_host_id(host_id)) {
                status = 422;
                return validation_error_json({{"host_id", "format", "操作日志必须包含合法主机 ID"}});
            }
            if (first_host.empty()) first_host = host_id;
            // 补全 host_id（旧客户端只在外层信封携带）+ 服务端接收时间戳
            std::string item = raw_item;
            if (json_string_field(item, "host_id").empty())
                item = json_inject_field(item, "host_id", host_id);
            item = json_inject_field(item, logmeta::attr::kServerTs,
                                     logmeta::now_millis(), true);
            // 按采集器类型应用过滤策略（strict/lenient），见 log_filter_profiles
            const std::string collector =
                logmeta::sanitize_collector_id(json_string_field(item, "collector"));
            const LogFilterProfile prof = resolve_log_filter_profile(cfg_, collector);
            item = apply_log_filter_profile(item, prof);
            const std::string prio = json_string_field(item, "priority");
            const std::string dir = host_operation_log_dir(cfg_, host_id);
            // 主存储：<host>/<collector>.jsonl
            auto saved = append_jsonl_retained(dir, collector + ".jsonl", item, prof.retention_lines);
            if (saved.is_err()) {
                status = 500;
                return "{\n  \"error\": \"cannot save operation logs\"\n}";
            }
            // 高权限镜像：<host>/privileged.jsonl，便于优先查询与延迟统计
            if (prio == logmeta::priority::kHigh) {
                auto mirror = append_jsonl_retained(dir, "privileged.jsonl", item, 20000);
                if (mirror.is_err()) {
                    status = 500;
                    return "{\n  \"error\": \"cannot save privileged logs\"\n}";
                }
            }
            pending_rule_eval.emplace_back(host_id, item);
            ++accepted;
        }
        std::ostringstream o;
        o << "{\n"
          << "  \"accepted\": true,\n"
          << "  \"accepted_count\": " << accepted << ",\n"
          << "  \"host_id\": \"" << json_escape(first_host) << "\",\n"
          << "  \"storage_dir\": \"" << json_escape(operation_log_dir(cfg_)) << "\",\n"
          << "  \"layout\": \"operation_logs/<host_id>/<collector>.jsonl (+privileged.jsonl)\",\n"
          << "  \"indexed_fields\": [\"host_id\", \"collector\", \"priority\", \"operation_type\", \"event_type\", \"timestamp\"]\n"
          << "}";
        response_body = o.str();
        }
        // 锁外执行违规规则复查（写 alerts，不阻塞 /hosts 等接口）
        for (const auto& pr : pending_rule_eval) {
            evaluate_operation_log_rules(cfg_, pr.first, pr.second);
        }
        return response_body;
    }
    if (path == "/agent/audit-summaries" && method == "POST") {
        content_type = "application/json; charset=utf-8";
        auto host_id = json_string_field(body, "host_id");
        if (host_id.empty() || !is_valid_host_id(host_id)) {
            status = 422;
            return validation_error_json({{"host_id", "format", "主机 ID 不能为空且只能包含字母、数字、短横线和下划线"}});
        }
        std::lock_guard<std::mutex> lk(host_store_mutex());
        auto saved = append_jsonl_retained(audit_summary_dir(cfg_), host_id + ".jsonl", body, 5000);
        if (saved.is_err()) {
            status = 500;
            return "{\n  \"error\": \"cannot save audit summaries\"\n}";
        }
        // 防篡改闭环：服务端配置了 chain_hmac_key 时，对每条摘要携带的批次签名
        // 逐条验签（payload = batch_id|created_at_us|merkle_root，与客户端 Chain::build_batch 一致）。
        // 验签失败的批次：原始记录仍留盘取证，但事件数不计入统计，并产生 critical 告警。
        u64 batch_events = 0;
        int signature_failures = 0;
        std::string first_bad_batch;
        if (!cfg_.chain_hmac_key.empty()) {
            for (const auto& summary : json_object_array_field(body, "summaries")) {
                const std::string bid   = json_string_field(summary, "batch_id");
                const std::string mroot = json_string_field(summary, "merkle_root");
                const std::string sig   = json_string_field(summary, "signature");
                const std::string created = std::to_string(json_size_field(summary, "created_at_us", 0));
                const std::string payload = bid + "|" + created + "|" + mroot;
                const std::string expect = crypto::hmac_sha256_hex(cfg_.chain_hmac_key, payload);
                // 常量时间、十六进制不区分大小写比较
                bool valid = sig.size() == expect.size();
                for (std::size_t i = 0; valid && i < sig.size(); ++i) {
                    if (std::tolower(static_cast<unsigned char>(sig[i])) !=
                        std::tolower(static_cast<unsigned char>(expect[i]))) valid = false;
                }
                if (!valid) {
                    ++signature_failures;
                    if (first_bad_batch.empty()) first_bad_batch = bid;
                    AF_LOG_ERROR("验签失败: host=" << host_id << " batch=" << bid
                                       << " signature_present=" << (!sig.empty()));
                    (void)append_alert(cfg_, host_id, "auditforwarder", "critical",
                                        "signature_invalid",
                                        "批次签名校验失败 batch=" + bid,
                                        summary);
                    continue;
                }
                batch_events += static_cast<u64>(json_size_field(summary, "event_count", 0));
            }
        } else {
            // 未配置验签密钥：无法建立防篡改闭环，仅在纯测试/无签名部署允许，明确提示。
            AF_LOG_WARN("manager: chain_hmac_key 未配置，跳过 audit-summaries 验签（host=" << host_id << "）");
            for (const auto& summary : json_object_array_field(body, "summaries")) {
                batch_events += static_cast<u64>(json_size_field(summary, "event_count", 0));
            }
        }
        if (batch_events > 0) {
            g_remote_events_collected.fetch_add(batch_events, std::memory_order_relaxed);
            g_remote_events_uploaded.fetch_add(batch_events, std::memory_order_relaxed);
        }
        std::ostringstream o;
        o << "{\n"
          << "  \"accepted\": true,\n"
          << "  \"host_id\": \"" << json_escape(host_id) << "\",\n"
          << "  \"signature_verified\": " << (cfg_.chain_hmac_key.empty() ? "false" : "true") << ",\n"
          << "  \"signature_failures\": " << signature_failures << ",\n"
          << "  \"first_invalid_batch\": \"" << json_escape(first_bad_batch) << "\",\n"
          << "  \"storage\": \"" << json_escape(fs::join(audit_summary_dir(cfg_), host_id + ".jsonl")) << "\",\n"
          << "  \"retention\": \"last 5000 summary records per host\"\n"
          << "}";
        return o.str();
    }
    if (path == "/hosts/command-results" && method == "POST") {
        content_type = "application/json; charset=utf-8";
        auto host_id = json_string_field(body, "host_id");
        auto command_id = json_string_field(body, "command_id");
        if (host_id.empty() || !is_valid_host_id(host_id)) {
            status = 422;
            return validation_error_json({{"host_id", "format", "主机 ID 格式不正确"}});
        }
        if (command_id.empty() || command_id.size() > 80) {
            status = 422;
            return validation_error_json({{"command_id", "required", "命令 ID 不能为空且长度不能超过 80 个字符"}});
        }
        std::lock_guard<std::mutex> lk(host_store_mutex());
        auto saved = append_jsonl_retained(command_result_dir(cfg_), host_id + ".jsonl", body, 10000);
        if (saved.is_err()) {
            status = 500;
            return "{\n  \"error\": \"cannot save command result\"\n}";
        }
        auto removed = remove_command_from_queue(cfg_, host_id, command_id);
        if (removed.is_err()) {
            status = 500;
            return "{\n  \"error\": \"cannot acknowledge command\"\n}";
        }
        std::ostringstream o;
        o << "{\n"
          << "  \"accepted\": true,\n"
          << "  \"acknowledged\": true,\n"
          << "  \"host_id\": \"" << json_escape(host_id) << "\",\n"
          << "  \"command_id\": \"" << json_escape(command_id) << "\"\n"
          << "}";
        return o.str();
    }
    if ((path == "/logs/query" || path == "/alerts") && method == "GET") {
        content_type = "application/json; charset=utf-8";
        auto host_id = query_param(query, "host_id");
        auto operation_type = query_param(query, "operation_type");
        auto from = query_param(query, "from");
        auto to = query_param(query, "to");
        auto limit = json_size_field("{\"limit\":" + query_param(query, "limit") + "}", "limit", 100);
        if (!host_id.empty() && !is_valid_host_id(host_id)) {
            status = 422;
            return validation_error_json({{"host_id", "format", "主机 ID 格式不正确"}});
        }
        std::vector<std::string> lines;
        if (path == "/alerts") {
            lines = read_jsonl_dir_filtered(alert_dir(cfg_), host_id, operation_type, from, to, limit);
        } else {
            auto collector = query_param(query, "collector");
            auto priority  = query_param(query, "priority");
            lines = read_operation_logs_filtered(cfg_, host_id, collector, priority,
                                                 operation_type, from, to, limit);
        }
        std::ostringstream o;
        o << "{\n"
          << "  \"kind\": \"" << (path == "/alerts" ? "alerts" : "operation_logs") << "\",\n"
          << "  \"host_id\": \"" << json_escape(host_id) << "\",\n"
          << "  \"count\": " << lines.size() << ",\n"
          << "  \"jsonl\": \"";
        for (const auto& line : lines) o << json_escape(line) << "\\n";
        o << "\"\n"
          << "}";
        return o.str();
    }
    if (path == "/logs/analytics" && method == "GET") {
        content_type = "application/json; charset=utf-8";
        auto host_id = query_param(query, "host_id");
        auto collector = query_param(query, "collector");
        auto priority = query_param(query, "priority");
        auto from = query_param(query, "from");
        auto to = query_param(query, "to");
        auto limit = json_size_field("{\"limit\":" + query_param(query, "limit") + "}", "limit", 1000);
        if (!host_id.empty() && !is_valid_host_id(host_id)) {
            status = 422;
            return validation_error_json({{"host_id", "format", "主机 ID 格式不正确"}});
        }
        return logs_analytics_json(cfg_, host_id, collector, priority, from, to, limit);
    }
    if (path == "/logs/collector-counts" && method == "GET") {
        content_type = "application/json; charset=utf-8";
        auto host_id = query_param(query, "host_id");
        if (!host_id.empty() && !is_valid_host_id(host_id)) {
            status = 422;
            return validation_error_json({{"host_id", "format", "主机 ID 格式不正确"}});
        }
        return collector_counts_json(cfg_, host_id);
    }
    if (path == "/stats/transfer-latency" && method == "GET") {
        content_type = "application/json; charset=utf-8";
        auto host_id = query_param(query, "host_id");
        auto limit = json_size_field("{\"limit\":" + query_param(query, "limit") + "}", "limit", 5000);
        if (!host_id.empty() && !is_valid_host_id(host_id)) {
            status = 422;
            return validation_error_json({{"host_id", "format", "主机 ID 格式不正确"}});
        }
        return transfer_latency_json(cfg_, host_id, limit);
    }
    if (path == "/hosts/history" && method == "GET") {
        content_type = "application/json; charset=utf-8";
        auto host_id = query_param(query, "host_id");
        auto kind = query_param(query, "kind");
        if (host_id.empty() || !is_valid_host_id(host_id)) {
            status = 422;
            return validation_error_json({{"host_id", "format", "主机 ID 格式不正确"}});
        }
        std::string dir;
        bool hierarchical_logs = false;
        if (kind == "metrics" || kind.empty()) dir = host_metrics_dir(cfg_);
        else if (kind == "audit") dir = audit_summary_dir(cfg_);
        else if (kind == "commands") dir = command_result_dir(cfg_);
        else if (kind == "logs") { dir = operation_log_dir(cfg_); hierarchical_logs = true; }
        else if (kind == "alerts") dir = alert_dir(cfg_);
        else {
            status = 422;
            return validation_error_json({{"kind", "format", "历史类型只能是 metrics、audit、commands、logs 或 alerts"}});
        }
        std::string content;
        if (hierarchical_logs) {
            // 两级存储：聚合 <host>/ 下全部采集器 jsonl
            auto lines = read_operation_logs_filtered(cfg_, host_id, "", "", "", "", "", 50000);
            for (const auto& l : lines) content += l + "\n";
        } else {
            auto r = read_text_file(fs::join(dir, host_id + ".jsonl"));
            if (r.is_ok()) content = r.value();
        }
        std::ostringstream o;
        o << "{\n"
          << "  \"host_id\": \"" << json_escape(host_id) << "\",\n"
          << "  \"kind\": \"" << json_escape(kind.empty() ? "metrics" : kind) << "\",\n"
          << "  \"jsonl\": \"" << json_escape(content) << "\"\n"
          << "}";
        return o.str();
    }
    if (path == "/upgrade" && method == "POST") {
        // 主体为新二进制文件的 URL
        std::vector<ValidationIssue> issues;
        require_text(issues, "url", "升级包 URL", body, 1, 2048);
        if (!body.empty() && body.rfind("http://", 0) != 0 && body.rfind("https://", 0) != 0) {
            issues.push_back({"url", "format", "升级包 URL 必须以 http:// 或 https:// 开头"});
        }
        if (!issues.empty()) {
            status = 422;
            content_type = "application/json; charset=utf-8";
            return validation_error_json(issues);
        }
        AF_LOG_INFO("manager: remote upgrade requested: " << body);
        status = 202;
        return "{\n  \"accepted\": true\n}";
    }
    status = 404;
    return "{\n  \"error\": \"not found\"\n}";
}

}  // namespace af
