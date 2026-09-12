#include "auditforwarder/manager.h"

#include "auditforwarder/config.h"
#include "auditforwarder/crypto.h"
#include "auditforwarder/fs.h"
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

bool host_online(const HostRecord& h, u64 now) {
    return h.last_seen_epoch > 0 && now >= h.last_seen_epoch &&
           now - h.last_seen_epoch <= 90 && h.network_status != "offline";
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
    h.last_seen_epoch = json_u64_field(json, "last_seen_epoch", 0);
    h.cpu_usage_percent = json_u64_field(json, "cpu_usage_percent", 0);
    h.memory_usage_percent = json_u64_field(json, "memory_usage_percent", 0);
    if (h.permissions.empty()) h.permissions = {"status_view"};
    if (h.network_status.empty()) h.network_status = "unknown";
    if (h.id.empty()) h.id = default_host_id(h);
    return h;
}

std::string host_to_json(const HostRecord& h, bool comma, u64 now) {
    std::ostringstream o;
    bool online = host_online(h, now);
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
    o << "]\n"
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
    std::vector<std::string> lines;
    if (fs::exists(path)) {
        auto old = read_text_file(path);
        if (old.is_ok()) {
            std::istringstream in(old.value());
            std::string item;
            while (std::getline(in, item)) {
                if (!item.empty()) lines.push_back(item);
            }
        }
    }
    lines.push_back(line);
    if (lines.size() > max_lines) {
        lines.erase(lines.begin(), lines.begin() + static_cast<std::ptrdiff_t>(lines.size() - max_lines));
    }
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return Result<void>(Error::Code::IoError, "cannot append central store");
    for (const auto& item : lines) out << item << "\n";
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

Result<void> append_alert(const ManagerConfig& cfg,
                          const std::string& host_id,
                          const std::string& source,
                          const std::string& severity,
                          const std::string& rule_id,
                          const std::string& message,
                          const std::string& evidence) {
    auto line = alert_json(host_id, source, severity, rule_id, message, evidence);
    return append_jsonl_retained(alert_dir(cfg), host_id + ".jsonl", line, 20000);
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
        auto path_to_read = fs::is_absolute(item) ? item : fs::join(dir, item);
        auto part = read_jsonl_filtered(path_to_read, "", operation_type, from, to, limit);
        lines.insert(lines.end(), part.begin(), part.end());
        if (limit > 0 && lines.size() > limit) {
            lines.erase(lines.begin(), lines.begin() + static_cast<std::ptrdiff_t>(lines.size() - limit));
        }
    }
    return lines;
}

std::string count_map_json(const std::map<std::string, std::size_t>& counts) {
    std::ostringstream o;
    o << "{";
    std::size_t i = 0;
    for (const auto& kv : counts) {
        if (i++) o << ", ";
        o << "\"" << json_escape(kv.first) << "\": " << kv.second;
    }
    o << "}";
    return o.str();
}

std::string logs_analytics_json(const ManagerConfig& cfg,
                                const std::string& host_id,
                                const std::string& from,
                                const std::string& to,
                                std::size_t limit) {
    auto logs = read_jsonl_dir_filtered(operation_log_dir(cfg), host_id, "", from, to, limit);
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
      << "  \"log_count\": " << logs.size() << ",\n"
      << "  \"alert_count\": " << alerts.size() << ",\n"
      << "  \"operation_types\": " << count_map_json(operation_types) << ",\n"
      << "  \"alert_severities\": " << count_map_json(alert_severities) << ",\n"
      << "  \"host_counts\": " << count_map_json(host_counts) << "\n"
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
        out << host_to_json(hosts[i], i + 1 < hosts.size(), now);
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
      << "  \"status_timeout_seconds\": 90,\n"
      << "  \"transport_security\": {\n"
      << "    \"authenticated\": " << (!cfg.auth_token.empty() ? "true" : "false") << ",\n"
      << "    \"tls_configured\": " << (cfg.use_tls ? "true" : "false") << ",\n"
      << "    \"command_queue_encryption\": \"AES-256-GCM\"\n"
      << "  },\n"
      << "  \"hosts\": [\n";
    for (std::size_t i = 0; i < hosts.size(); ++i) {
        o << host_to_json(hosts[i], i + 1 < hosts.size(), now);
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
    thr_ = std::thread([this] { accept_loop(); });
    AF_LOG_INFO("manager: listening on " << cfg_.listen);
    return Result<void>::ok();
}

void SimpleHttpManager::stop() {
    if (!running_.exchange(false)) return;
    if (listen_fd_ >= 0) {
        ::shutdown(listen_fd_, 2);
        ::close(listen_fd_);
        listen_fd_ = -1;
    }
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
        std::ostringstream o;
        o << "{\n"
          << "  \"running\": " << (agent_->is_running() ? "true" : "false") << ",\n"
          << "  \"events_collected\": " << s.events_collected << ",\n"
          << "  \"events_uploaded\": " << s.events_uploaded << ",\n"
          << "  \"events_failed\": " << s.events_failed << ",\n"
          << "  \"events_dropped\": " << s.events_dropped << ",\n"
          << "  \"alerts\": " << s.alerts << ",\n"
          << "  \"bytes_uploaded\": " << s.bytes_uploaded << ",\n"
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
        std::lock_guard<std::mutex> lk(host_store_mutex());
        for (const auto& item : objects) {
            auto host_id = json_string_field(item, "host_id");
            if (host_id.empty()) host_id = json_string_field(body, "host_id");
            if (host_id.empty() || !is_valid_host_id(host_id)) {
                status = 422;
                return validation_error_json({{"host_id", "format", "操作日志必须包含合法主机 ID"}});
            }
            if (first_host.empty()) first_host = host_id;
            auto saved = append_jsonl_retained(operation_log_dir(cfg_), host_id + ".jsonl", item, 50000);
            if (saved.is_err()) {
                status = 500;
                return "{\n  \"error\": \"cannot save operation logs\"\n}";
            }
            evaluate_operation_log_rules(cfg_, host_id, item);
            ++accepted;
        }
        std::ostringstream o;
        o << "{\n"
          << "  \"accepted\": true,\n"
          << "  \"accepted_count\": " << accepted << ",\n"
          << "  \"host_id\": \"" << json_escape(first_host) << "\",\n"
          << "  \"storage_dir\": \"" << json_escape(operation_log_dir(cfg_)) << "\",\n"
          << "  \"indexed_fields\": [\"host_id\", \"operation_type\", \"event_type\", \"timestamp\"]\n"
          << "}";
        return o.str();
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
        std::ostringstream o;
        o << "{\n"
          << "  \"accepted\": true,\n"
          << "  \"host_id\": \"" << json_escape(host_id) << "\",\n"
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
        std::string dir = path == "/alerts" ? alert_dir(cfg_) : operation_log_dir(cfg_);
        auto lines = read_jsonl_dir_filtered(dir, host_id, operation_type, from, to, limit);
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
        auto from = query_param(query, "from");
        auto to = query_param(query, "to");
        auto limit = json_size_field("{\"limit\":" + query_param(query, "limit") + "}", "limit", 1000);
        if (!host_id.empty() && !is_valid_host_id(host_id)) {
            status = 422;
            return validation_error_json({{"host_id", "format", "主机 ID 格式不正确"}});
        }
        return logs_analytics_json(cfg_, host_id, from, to, limit);
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
        if (kind == "metrics" || kind.empty()) dir = host_metrics_dir(cfg_);
        else if (kind == "audit") dir = audit_summary_dir(cfg_);
        else if (kind == "commands") dir = command_result_dir(cfg_);
        else if (kind == "logs") dir = operation_log_dir(cfg_);
        else if (kind == "alerts") dir = alert_dir(cfg_);
        else {
            status = 422;
            return validation_error_json({{"kind", "format", "历史类型只能是 metrics、audit、commands、logs 或 alerts"}});
        }
        auto content = read_text_file(fs::join(dir, host_id + ".jsonl"));
        std::ostringstream o;
        o << "{\n"
          << "  \"host_id\": \"" << json_escape(host_id) << "\",\n"
          << "  \"kind\": \"" << json_escape(kind.empty() ? "metrics" : kind) << "\",\n"
          << "  \"jsonl\": \"" << json_escape(content.is_ok() ? content.value() : "") << "\"\n"
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
