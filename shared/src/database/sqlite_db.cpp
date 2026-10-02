// AuditForwarder - SQLite 数据库封装层实现。

#include "auditforwarder/sqlite_db.h"

#include <sqlite3.h>

#include <algorithm>
#include <filesystem>
#include <sstream>

namespace fs = std::filesystem;

namespace af::db {

struct SqliteDb::Impl {
    sqlite3* handle { nullptr };
    std::string path;
};

SqliteDb::~SqliteDb() {
    close();
}

Result<void> SqliteDb::open(const std::string& path) {
    close();
    std::lock_guard<std::mutex> lk(mtx_);
    auto parent = fs::path(path).parent_path();
    std::error_code ec;
    fs::create_directories(parent, ec);
    if (ec) {
        return Result<void>(Error::Code::IoError, "cannot create dir: " + ec.message());
    }
    db_ = std::make_unique<Impl>();
    db_->path = path;
    int rc = sqlite3_open_v2(path.c_str(), &db_->handle,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                             nullptr);
    if (rc != SQLITE_OK) {
        last_error_ = sqlite3_errmsg(db_->handle ? db_->handle : nullptr);
        close();
        return Result<void>(Error::Code::IoError, "sqlite3 open failed: " + last_error_);
    }
    // 启用 WAL 模式 + 外键约束，提升并发与可靠性
    exec("PRAGMA journal_mode=WAL;");
    exec("PRAGMA foreign_keys=ON;");
    exec("PRAGMA synchronous=NORMAL;");
    return Result<void>::ok();
}

void SqliteDb::close() {
    std::lock_guard<std::mutex> lk(mtx_);
    if (db_ && db_->handle) {
        sqlite3_close_v2(db_->handle);
        db_->handle = nullptr;
    }
}

Result<void> SqliteDb::exec(const std::string& sql) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (!db_ || !db_->handle) {
        return Result<void>(Error::Code::InvalidArgument, "database not open");
    }
    char* err = nullptr;
    int rc = sqlite3_exec(db_->handle, sql.c_str(), nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        last_error_ = err ? err : "unknown sqlite error";
        sqlite3_free(err);
        return Result<void>(Error::Code::IoError, "sqlite exec: " + last_error_);
    }
    return Result<void>::ok();
}

Result<std::vector<std::vector<std::string>>> SqliteDb::query(const std::string& sql) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (!db_ || !db_->handle) {
        return Result<std::vector<std::vector<std::string>>>(Error::Code::InvalidArgument, "database not open");
    }
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_->handle, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        last_error_ = sqlite3_errmsg(db_->handle);
        return Result<std::vector<std::vector<std::string>>>(Error::Code::InvalidArgument, "sqlite prepare: " + last_error_);
    }
    std::vector<std::vector<std::string>> rows;
    int cols = sqlite3_column_count(stmt);
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        std::vector<std::string> row;
        row.reserve(static_cast<std::size_t>(cols));
        for (int i = 0; i < cols; ++i) {
            const char* v = reinterpret_cast<const char*>(sqlite3_column_text(stmt, i));
            row.emplace_back(v ? v : "");
        }
        rows.push_back(std::move(row));
    }
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        last_error_ = sqlite3_errmsg(db_->handle);
        return Result<std::vector<std::vector<std::string>>>(Error::Code::IoError, "sqlite step: " + last_error_);
    }
    return Result<std::vector<std::vector<std::string>>>(std::move(rows));
}

// ---------------------------------------------------------------------------
// HostDbManager
// ---------------------------------------------------------------------------

Result<void> HostDbManager::init(const std::string& data_dir) {
    std::lock_guard<std::mutex> lk(mtx_);
    root_dir_ = fs::path(data_dir).lexically_normal().string();
    std::error_code ec;
    fs::create_directories(fs::path(root_dir_) / "hosts", ec);
    if (ec) {
        return Result<void>(Error::Code::IoError, "cannot create hosts dir: " + ec.message());
    }
    return Result<void>::ok();
}

Result<SqliteDb*> HostDbManager::host_db(const std::string& host_id) {
    std::lock_guard<std::mutex> lk(mtx_);
    // 防止路径注入：只允许合法 host_id 字符
    if (host_id.empty() || host_id.find("..") != std::string::npos ||
        host_id.find('/') != std::string::npos || host_id.find('\\') != std::string::npos) {
        return Result<SqliteDb*>(Error::Code::InvalidArgument, "invalid host_id for database");
    }
    for (auto& pair : dbs_) {
        if (pair.first == host_id) return pair.second.get();
    }
    auto db = std::make_unique<SqliteDb>();
    std::string db_path = (fs::path(root_dir_) / "hosts" / host_id / "host.db").string();
    auto r = db->open(db_path);
    if (r.is_err()) return Result<SqliteDb*>(r.error());

    // 建表：events / metrics / alerts / audit
    auto exec_or_fail = [&](const std::string& sql) -> Result<void> {
        return db->exec(sql);
    };

    auto r1 = exec_or_fail(R"(
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            collector TEXT,
            priority TEXT DEFAULT 'normal',
            operation_type TEXT,
            event_type TEXT,
            message TEXT,
            raw_json TEXT NOT NULL,
            checksum TEXT
        );
    )");
    if (r1.is_err()) return Result<SqliteDb*>(r1.error());

    auto r2 = exec_or_fail(R"(
        CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
    )");
    if (r2.is_err()) return Result<SqliteDb*>(r2.error());

    auto r3 = exec_or_fail(R"(
        CREATE INDEX IF NOT EXISTS idx_events_collector ON events(collector);
    )");
    if (r3.is_err()) return Result<SqliteDb*>(r3.error());

    auto r4 = exec_or_fail(R"(
        CREATE TABLE IF NOT EXISTS metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            metric_name TEXT NOT NULL,
            metric_value TEXT,
            raw_json TEXT NOT NULL
        );
    )");
    if (r4.is_err()) return Result<SqliteDb*>(r4.error());

    auto r5 = exec_or_fail(R"(
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            severity TEXT DEFAULT 'info',
            rule_id TEXT,
            message TEXT,
            evidence TEXT,
            raw_json TEXT NOT NULL
        );
    )");
    if (r5.is_err()) return Result<SqliteDb*>(r5.error());

    auto r6 = exec_or_fail(R"(
        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            actor TEXT,
            action TEXT,
            detail TEXT,
            raw_json TEXT NOT NULL
        );
    )");
    if (r6.is_err()) return Result<SqliteDb*>(r6.error());

    auto r7 = exec_or_fail(R"(
        CREATE TABLE IF NOT EXISTS connection_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            host_id TEXT NOT NULL,
            client_ip TEXT,
            status TEXT DEFAULT 'connected',
            message TEXT
        );
    )");
    if (r7.is_err()) return Result<SqliteDb*>(r7.error());

    dbs_.emplace_back(host_id, std::move(db));
    return Result<SqliteDb*>(dbs_.back().second.get());
}

std::vector<std::string> HostDbManager::list_hosts() const {
    std::lock_guard<std::mutex> lk(mtx_);
    std::vector<std::string> out;
    // 扫描磁盘目录，保证服务重启后仍能列出已存在的主机数据库
    std::error_code ec;
    const fs::path hosts_dir = fs::path(root_dir_) / "hosts";
    for (const auto& entry : fs::directory_iterator(hosts_dir, ec)) {
        if (!entry.is_directory()) continue;
        if (fs::exists(entry.path() / "host.db")) {
            out.push_back(entry.path().filename().string());
        }
    }
    std::sort(out.begin(), out.end());
    return out;
}

} // namespace af::db
