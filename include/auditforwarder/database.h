#pragma once
// AuditForwarder - 服务端数据库模型、校验规则和 CRUD 仓储接口。

#include "auditforwarder/types.h"

#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace af::db {

enum class AccountStatus { Active, Disabled, Locked };
enum class HostOnlineStatus { Online, Offline, Unknown };
enum class LogStatus { New, Parsed, Alerted, Archived };

std::string to_string(AccountStatus status);
std::string to_string(HostOnlineStatus status);
std::string to_string(LogStatus status);

AccountStatus account_status_from_string(const std::string& status);
HostOnlineStatus host_status_from_string(const std::string& status);
LogStatus log_status_from_string(const std::string& status);

struct AdminUser {
    std::string user_id;
    std::string username;
    std::string password_hash;
    std::string password_algorithm { "argon2id" };
    std::string role_code { "operator" };
    int permission_level { 0 };
    AccountStatus status { AccountStatus::Active };
    std::string created_at;
    std::string last_login_at;
};

struct HostInfo {
    std::string host_id;
    std::string host_name;
    std::string ip_address;
    std::uint16_t port { 0 };
    std::string os_type { "unknown" };
    std::string os_version { "unknown" };
    std::string hardware_info_json { "{}" };
    std::string registered_at;
    std::string last_seen_at;
    HostOnlineStatus online_status { HostOnlineStatus::Unknown };
    std::string note;
};

struct HostLog {
    std::uint64_t log_id { 0 };
    std::string host_id;
    std::string log_type;
    std::string log_content;
    std::string generated_at;
    std::string uploaded_at;
    LogStatus status { LogStatus::New };
    std::string metadata_json { "{}" };
};

struct LogQuery {
    std::string host_id;
    std::string log_type;
    std::string from_time;
    std::string to_time;
    LogStatus status { LogStatus::New };
    bool filter_status { false };
    std::size_t limit { 100 };
    std::size_t offset { 0 };
};

class Validator {
public:
    static Result<void> validate_admin(const AdminUser& user);
    static Result<void> validate_host(const HostInfo& host);
    static Result<void> validate_log(const HostLog& log);
    static bool looks_like_password_hash(const std::string& hash, const std::string& algorithm);
};

class DatabaseStore {
public:
    virtual ~DatabaseStore() = default;

    virtual Result<void> create_admin(const AdminUser& user) = 0;
    virtual Result<std::optional<AdminUser>> get_admin_by_id(const std::string& user_id) const = 0;
    virtual Result<std::optional<AdminUser>> get_admin_by_username(const std::string& username) const = 0;
    virtual Result<void> update_admin(const AdminUser& user) = 0;
    virtual Result<void> set_admin_status(const std::string& user_id, AccountStatus status) = 0;
    virtual Result<void> delete_admin(const std::string& user_id) = 0;

    virtual Result<void> upsert_host(const HostInfo& host) = 0;
    virtual Result<std::optional<HostInfo>> get_host(const std::string& host_id) const = 0;
    virtual Result<std::vector<HostInfo>> list_hosts(std::size_t limit, std::size_t offset) const = 0;
    virtual Result<void> delete_host(const std::string& host_id) = 0;

    virtual Result<std::uint64_t> create_log(const HostLog& log) = 0;
    virtual Result<std::optional<HostLog>> get_log(std::uint64_t log_id) const = 0;
    virtual Result<std::vector<HostLog>> query_logs(const LogQuery& query) const = 0;
    virtual Result<void> update_log_status(std::uint64_t log_id, LogStatus status) = 0;
    virtual Result<void> delete_log(std::uint64_t log_id) = 0;
};

class InMemoryDatabaseStore final : public DatabaseStore {
public:
    Result<void> create_admin(const AdminUser& user) override;
    Result<std::optional<AdminUser>> get_admin_by_id(const std::string& user_id) const override;
    Result<std::optional<AdminUser>> get_admin_by_username(const std::string& username) const override;
    Result<void> update_admin(const AdminUser& user) override;
    Result<void> set_admin_status(const std::string& user_id, AccountStatus status) override;
    Result<void> delete_admin(const std::string& user_id) override;

    Result<void> upsert_host(const HostInfo& host) override;
    Result<std::optional<HostInfo>> get_host(const std::string& host_id) const override;
    Result<std::vector<HostInfo>> list_hosts(std::size_t limit, std::size_t offset) const override;
    Result<void> delete_host(const std::string& host_id) override;

    Result<std::uint64_t> create_log(const HostLog& log) override;
    Result<std::optional<HostLog>> get_log(std::uint64_t log_id) const override;
    Result<std::vector<HostLog>> query_logs(const LogQuery& query) const override;
    Result<void> update_log_status(std::uint64_t log_id, LogStatus status) override;
    Result<void> delete_log(std::uint64_t log_id) override;

private:
    static std::string username_key(const std::string& username);

    mutable std::mutex mutex_;
    std::unordered_map<std::string, AdminUser> admins_by_id_;
    std::unordered_map<std::string, std::string> admin_id_by_username_;
    std::unordered_map<std::string, HostInfo> hosts_;
    std::map<std::uint64_t, HostLog> logs_;
    std::uint64_t next_log_id_ { 1 };
};

namespace postgres_sql {

extern const char* create_admin;
extern const char* get_admin_by_id;
extern const char* get_admin_by_username;
extern const char* update_admin;
extern const char* set_admin_status;
extern const char* disable_admin;

extern const char* upsert_host;
extern const char* get_host;
extern const char* list_hosts;
extern const char* soft_delete_host;

extern const char* create_host_log;
extern const char* get_host_log;
extern const char* query_host_logs;
extern const char* update_host_log_status;
extern const char* delete_host_log;

}  // namespace postgres_sql

}  // namespace af::db
