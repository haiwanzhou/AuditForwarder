#include "auditforwarder/database.h"

#include <algorithm>
#include <cctype>
#include <regex>

namespace af::db {

namespace {

bool blank(const std::string& value) {
    return std::all_of(value.begin(), value.end(), [](unsigned char c) { return std::isspace(c) != 0; });
}

bool between(std::size_t value, std::size_t min, std::size_t max) {
    return value >= min && value <= max;
}

bool valid_json_object_or_array(const std::string& value) {
    if (value.empty()) return false;
    auto first = value.find_first_not_of(" \t\r\n");
    auto last = value.find_last_not_of(" \t\r\n");
    if (first == std::string::npos || last == std::string::npos) return false;
    return (value[first] == '{' && value[last] == '}') || (value[first] == '[' && value[last] == ']');
}

bool valid_identifier(const std::string& value, std::size_t min, std::size_t max) {
    if (!between(value.size(), min, max)) return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return std::isalnum(c) != 0 || c == '_' || c == '-';
    });
}

bool valid_uuid(const std::string& value) {
    static const std::regex uuid_re(R"(^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$)");
    return std::regex_match(value, uuid_re);
}

bool valid_ip_like(const std::string& value) {
    if (value.empty()) return true;
    static const std::regex ip_re(R"(^[0-9A-Fa-f:.]{3,45}$)");
    return std::regex_match(value, ip_re);
}

Result<void> invalid(const std::string& message) {
    return Result<void>(Error::Code::InvalidArgument, message);
}

}  // namespace

std::string to_string(AccountStatus status) {
    switch (status) {
        case AccountStatus::Active: return "active";
        case AccountStatus::Disabled: return "disabled";
        case AccountStatus::Locked: return "locked";
    }
    return "disabled";
}

std::string to_string(HostOnlineStatus status) {
    switch (status) {
        case HostOnlineStatus::Online: return "online";
        case HostOnlineStatus::Offline: return "offline";
        case HostOnlineStatus::Unknown: return "unknown";
    }
    return "unknown";
}

std::string to_string(LogStatus status) {
    switch (status) {
        case LogStatus::New: return "new";
        case LogStatus::Parsed: return "parsed";
        case LogStatus::Alerted: return "alerted";
        case LogStatus::Archived: return "archived";
    }
    return "new";
}

AccountStatus account_status_from_string(const std::string& status) {
    if (status == "active") return AccountStatus::Active;
    if (status == "locked") return AccountStatus::Locked;
    return AccountStatus::Disabled;
}

HostOnlineStatus host_status_from_string(const std::string& status) {
    if (status == "online") return HostOnlineStatus::Online;
    if (status == "offline") return HostOnlineStatus::Offline;
    return HostOnlineStatus::Unknown;
}

LogStatus log_status_from_string(const std::string& status) {
    if (status == "parsed") return LogStatus::Parsed;
    if (status == "alerted") return LogStatus::Alerted;
    if (status == "archived") return LogStatus::Archived;
    return LogStatus::New;
}

bool Validator::looks_like_password_hash(const std::string& hash, const std::string& algorithm) {
    if (algorithm == "argon2id") return hash.rfind("$argon2id$", 0) == 0 && hash.size() >= 32;
    if (algorithm == "bcrypt") return hash.rfind("$2a$", 0) == 0 || hash.rfind("$2b$", 0) == 0 || hash.rfind("$2y$", 0) == 0;
    if (algorithm == "sha256") {
        return hash.size() == 64 && std::all_of(hash.begin(), hash.end(), [](unsigned char c) {
            return std::isxdigit(c) != 0;
        });
    }
    return false;
}

Result<void> Validator::validate_admin(const AdminUser& user) {
    if (!valid_uuid(user.user_id)) return invalid("user_id 必须是 UUID 格式");
    if (!between(user.username.size(), 3, 64) || blank(user.username)) return invalid("username 必须为 3-64 位非空字符串");
    if (!looks_like_password_hash(user.password_hash, user.password_algorithm)) return invalid("password_hash 必须是不可逆哈希值，推荐 argon2id");
    if (!between(user.role_code.size(), 2, 64) || blank(user.role_code)) return invalid("role_code 必须为 2-64 位非空字符串");
    if (user.permission_level < 0 || user.permission_level > 100) return invalid("permission_level 必须在 0-100 之间");
    return Result<void>::ok();
}

Result<void> Validator::validate_host(const HostInfo& host) {
    if (!valid_identifier(host.host_id, 3, 80)) return invalid("host_id 必须为 3-80 位字母、数字、下划线或短横线");
    if (!between(host.host_name.size(), 1, 128) || blank(host.host_name)) return invalid("host_name 必须为 1-128 位非空字符串");
    if (!valid_ip_like(host.ip_address)) return invalid("ip_address 格式不合法");
    if (!between(host.os_type.size(), 1, 64) || blank(host.os_type)) return invalid("os_type 必须为 1-64 位非空字符串");
    if (!between(host.os_version.size(), 1, 256) || blank(host.os_version)) return invalid("os_version 必须为 1-256 位非空字符串");
    if (!valid_json_object_or_array(host.hardware_info_json)) return invalid("hardware_info_json 必须是 JSON 对象或数组");
    return Result<void>::ok();
}

Result<void> Validator::validate_log(const HostLog& log) {
    if (!valid_identifier(log.host_id, 3, 80)) return invalid("host_id 必须为 3-80 位字母、数字、下划线或短横线");
    if (!between(log.log_type.size(), 1, 64) || blank(log.log_type)) return invalid("log_type 必须为 1-64 位非空字符串");
    if (log.log_content.empty()) return invalid("log_content 不能为空");
    if (log.log_content.size() > 1024 * 1024) return invalid("log_content 不能超过 1MB");
    if (!valid_json_object_or_array(log.metadata_json)) return invalid("metadata_json 必须是 JSON 对象或数组");
    return Result<void>::ok();
}

std::string InMemoryDatabaseStore::username_key(const std::string& username) {
    std::string key = username;
    std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return key;
}

Result<void> InMemoryDatabaseStore::create_admin(const AdminUser& user) {
    auto vr = Validator::validate_admin(user);
    if (vr.is_err()) return vr;
    std::lock_guard<std::mutex> lock(mutex_);
    if (admins_by_id_.count(user.user_id)) return Result<void>(Error::Code::AlreadyExists, "user_id 已存在");
    auto key = username_key(user.username);
    if (admin_id_by_username_.count(key)) return Result<void>(Error::Code::AlreadyExists, "username 已存在");
    admins_by_id_[user.user_id] = user;
    admin_id_by_username_[key] = user.user_id;
    return Result<void>::ok();
}

Result<std::optional<AdminUser>> InMemoryDatabaseStore::get_admin_by_id(const std::string& user_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = admins_by_id_.find(user_id);
    if (it == admins_by_id_.end()) return std::optional<AdminUser>{};
    return std::optional<AdminUser>{it->second};
}

Result<std::optional<AdminUser>> InMemoryDatabaseStore::get_admin_by_username(const std::string& username) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto id = admin_id_by_username_.find(username_key(username));
    if (id == admin_id_by_username_.end()) return std::optional<AdminUser>{};
    auto user = admins_by_id_.find(id->second);
    if (user == admins_by_id_.end()) return std::optional<AdminUser>{};
    return std::optional<AdminUser>{user->second};
}

Result<void> InMemoryDatabaseStore::update_admin(const AdminUser& user) {
    auto vr = Validator::validate_admin(user);
    if (vr.is_err()) return vr;
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = admins_by_id_.find(user.user_id);
    if (it == admins_by_id_.end()) return Result<void>(Error::Code::NotFound, "管理员不存在");
    auto old_key = username_key(it->second.username);
    auto new_key = username_key(user.username);
    auto owner = admin_id_by_username_.find(new_key);
    if (owner != admin_id_by_username_.end() && owner->second != user.user_id) {
        return Result<void>(Error::Code::AlreadyExists, "username 已存在");
    }
    admin_id_by_username_.erase(old_key);
    admin_id_by_username_[new_key] = user.user_id;
    it->second = user;
    return Result<void>::ok();
}

Result<void> InMemoryDatabaseStore::set_admin_status(const std::string& user_id, AccountStatus status) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = admins_by_id_.find(user_id);
    if (it == admins_by_id_.end()) return Result<void>(Error::Code::NotFound, "管理员不存在");
    it->second.status = status;
    return Result<void>::ok();
}

Result<void> InMemoryDatabaseStore::delete_admin(const std::string& user_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = admins_by_id_.find(user_id);
    if (it == admins_by_id_.end()) return Result<void>(Error::Code::NotFound, "管理员不存在");
    admin_id_by_username_.erase(username_key(it->second.username));
    admins_by_id_.erase(it);
    return Result<void>::ok();
}

Result<void> InMemoryDatabaseStore::upsert_host(const HostInfo& host) {
    auto vr = Validator::validate_host(host);
    if (vr.is_err()) return vr;
    std::lock_guard<std::mutex> lock(mutex_);
    hosts_[host.host_id] = host;
    return Result<void>::ok();
}

Result<std::optional<HostInfo>> InMemoryDatabaseStore::get_host(const std::string& host_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = hosts_.find(host_id);
    if (it == hosts_.end()) return std::optional<HostInfo>{};
    return std::optional<HostInfo>{it->second};
}

Result<std::vector<HostInfo>> InMemoryDatabaseStore::list_hosts(std::size_t limit, std::size_t offset) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<HostInfo> result;
    if (limit == 0) return result;
    std::size_t skipped = 0;
    for (const auto& item : hosts_) {
        if (skipped++ < offset) continue;
        result.push_back(item.second);
        if (result.size() >= limit) break;
    }
    return result;
}

Result<void> InMemoryDatabaseStore::delete_host(const std::string& host_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = hosts_.find(host_id);
    if (it == hosts_.end()) return Result<void>(Error::Code::NotFound, "主机不存在");
    hosts_.erase(it);
    return Result<void>::ok();
}

Result<std::uint64_t> InMemoryDatabaseStore::create_log(const HostLog& log) {
    auto vr = Validator::validate_log(log);
    if (vr.is_err()) return Result<std::uint64_t>(vr.error());
    std::lock_guard<std::mutex> lock(mutex_);
    if (!hosts_.count(log.host_id)) return Result<std::uint64_t>(Error::Code::NotFound, "关联主机不存在");
    HostLog stored = log;
    stored.log_id = next_log_id_++;
    logs_[stored.log_id] = stored;
    return stored.log_id;
}

Result<std::optional<HostLog>> InMemoryDatabaseStore::get_log(std::uint64_t log_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = logs_.find(log_id);
    if (it == logs_.end()) return std::optional<HostLog>{};
    return std::optional<HostLog>{it->second};
}

Result<std::vector<HostLog>> InMemoryDatabaseStore::query_logs(const LogQuery& query) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<HostLog> result;
    if (query.limit == 0) return result;
    std::size_t skipped = 0;
    for (auto it = logs_.rbegin(); it != logs_.rend(); ++it) {
        const auto& log = it->second;
        if (!query.host_id.empty() && log.host_id != query.host_id) continue;
        if (!query.log_type.empty() && log.log_type != query.log_type) continue;
        if (query.filter_status && log.status != query.status) continue;
        if (!query.from_time.empty() && log.generated_at < query.from_time) continue;
        if (!query.to_time.empty() && log.generated_at > query.to_time) continue;
        if (skipped++ < query.offset) continue;
        result.push_back(log);
        if (result.size() >= query.limit) break;
    }
    return result;
}

Result<void> InMemoryDatabaseStore::update_log_status(std::uint64_t log_id, LogStatus status) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = logs_.find(log_id);
    if (it == logs_.end()) return Result<void>(Error::Code::NotFound, "日志不存在");
    it->second.status = status;
    return Result<void>::ok();
}

Result<void> InMemoryDatabaseStore::delete_log(std::uint64_t log_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = logs_.find(log_id);
    if (it == logs_.end()) return Result<void>(Error::Code::NotFound, "日志不存在");
    logs_.erase(it);
    return Result<void>::ok();
}

namespace postgres_sql {

const char* create_admin = R"SQL(
INSERT INTO af_admin_users (
    user_id, username, password_hash, password_algorithm, role_id, permission_level, account_status
)
SELECT $1, $2, $3, $4, role_id, $6, $7
FROM af_admin_roles
WHERE role_code = $5
)SQL";

const char* get_admin_by_id = R"SQL(
SELECT u.user_id, u.username, u.password_hash, u.password_algorithm, r.role_code, u.permission_level, u.account_status, u.created_at, u.last_login_at
FROM af_admin_users u
JOIN af_admin_roles r ON r.role_id = u.role_id
WHERE u.user_id = $1
)SQL";

const char* get_admin_by_username = R"SQL(
SELECT u.user_id, u.username, u.password_hash, u.password_algorithm, r.role_code, u.permission_level, u.account_status, u.created_at, u.last_login_at
FROM af_admin_users u
JOIN af_admin_roles r ON r.role_id = u.role_id
WHERE lower(u.username) = lower($1)
)SQL";

const char* update_admin = R"SQL(
UPDATE af_admin_users
SET username = $2,
    password_hash = $3,
    password_algorithm = $4,
    role_id = (SELECT role_id FROM af_admin_roles WHERE role_code = $5),
    permission_level = $6,
    account_status = $7
WHERE user_id = $1
)SQL";

const char* set_admin_status = R"SQL(
UPDATE af_admin_users
SET account_status = $2
WHERE user_id = $1
)SQL";

const char* disable_admin = R"SQL(
UPDATE af_admin_users
SET account_status = 'disabled'
WHERE user_id = $1
)SQL";

const char* upsert_host = R"SQL(
INSERT INTO af_hosts (
    host_id, host_name, ip_address, port, os_type, os_version, hardware_info,
    network_status, registered_at, last_seen_at, note
) VALUES (
    $1, $2, $3::inet, $4, $5, $6, $7::jsonb, $8, now(), now(), $9
)
ON CONFLICT (host_id) DO UPDATE
SET host_name = EXCLUDED.host_name,
    ip_address = EXCLUDED.ip_address,
    port = EXCLUDED.port,
    os_type = EXCLUDED.os_type,
    os_version = EXCLUDED.os_version,
    hardware_info = EXCLUDED.hardware_info,
    network_status = EXCLUDED.network_status,
    last_seen_at = now(),
    note = EXCLUDED.note
)SQL";

const char* get_host = R"SQL(
SELECT host_id, host_name, ip_address::text, port, os_type, os_version, hardware_info, network_status, registered_at, last_seen_at, note
FROM af_hosts
WHERE host_id = $1
)SQL";

const char* list_hosts = R"SQL(
SELECT host_id, host_name, ip_address::text, port, os_type, os_version, hardware_info, network_status, registered_at, last_seen_at, note
FROM af_hosts
ORDER BY last_seen_at DESC NULLS LAST, registered_at DESC
LIMIT $1 OFFSET $2
)SQL";

const char* soft_delete_host = R"SQL(
UPDATE af_hosts
SET network_status = 'offline',
    note = concat(note, E'\n已从监管列表移除：', now())
WHERE host_id = $1
)SQL";

const char* create_host_log = R"SQL(
INSERT INTO af_host_logs (
    host_id, log_type, log_content, generated_at, uploaded_at, log_status, metadata
) VALUES (
    $1, $2, $3, $4, now(), $5, $6::jsonb
)
RETURNING log_id
)SQL";

const char* get_host_log = R"SQL(
SELECT log_id, host_id, log_type, log_content, generated_at, uploaded_at, log_status, metadata
FROM af_host_logs
WHERE log_id = $1
)SQL";

const char* query_host_logs = R"SQL(
SELECT log_id, host_id, log_type, log_content, generated_at, uploaded_at, log_status, metadata
FROM af_host_logs
WHERE ($1::varchar IS NULL OR host_id = $1)
  AND ($2::varchar IS NULL OR log_type = $2)
  AND ($3::timestamptz IS NULL OR generated_at >= $3)
  AND ($4::timestamptz IS NULL OR generated_at <= $4)
  AND ($5::varchar IS NULL OR log_status = $5)
ORDER BY generated_at DESC, log_id DESC
LIMIT $6 OFFSET $7
)SQL";

const char* update_host_log_status = R"SQL(
UPDATE af_host_logs
SET log_status = $2
WHERE log_id = $1
)SQL";

const char* delete_host_log = R"SQL(
DELETE FROM af_host_logs
WHERE log_id = $1
)SQL";

}  // namespace postgres_sql

}  // namespace af::db
