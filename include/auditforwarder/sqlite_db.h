#pragma once
// AuditForwarder - SQLite 数据库封装层。
// 为每个客户端主机提供独立的 SQLite 数据库实例，支持日志/事件/指标的
// 结构化存储、检索与导出。

#include "auditforwarder/types.h"

#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace af::db {

// SQLite 数据库句柄的 RAII 封装。
class SqliteDb {
public:
    SqliteDb() = default;
    ~SqliteDb();

    SqliteDb(const SqliteDb&) = delete;
    SqliteDb& operator=(const SqliteDb&) = delete;

    // 打开（不存在则创建）指定路径的 SQLite 数据库文件。
    Result<void> open(const std::string& path);
    void close();
    bool is_open() const { return db_ != nullptr; }

    // 执行无返回的 SQL（建表、插入、更新等）。
    Result<void> exec(const std::string& sql);

    // 查询并返回全部行。每行为列值数组。
    Result<std::vector<std::vector<std::string>>> query(const std::string& sql);

    // 返回最后一次 SQLite 错误信息。
    std::string last_error() const { return last_error_; }

private:
    struct Impl;
    std::unique_ptr<Impl> db_;
    std::string last_error_;
    std::mutex mtx_;
};

// 主机数据库管理器：为每个客户端主机维护一个独立的 SQLite 数据库。
// 数据库文件位于 <data_dir>/hosts/<host_id>/host.db。
class HostDbManager {
public:
    HostDbManager() = default;
    ~HostDbManager() = default;

    // 初始化：确保根目录存在。
    Result<void> init(const std::string& data_dir);

    // 获取指定主机的数据库（不存在则创建并建表）。
    // 返回的引用在 HostDbManager 生命周期内有效。
    Result<SqliteDb*> host_db(const std::string& host_id);

    // 列出所有已创建数据库的主机 ID。
    std::vector<std::string> list_hosts() const;

    // 数据根目录。
    std::string root_dir() const { return root_dir_; }

private:
    std::string root_dir_;
    mutable std::mutex mtx_;
    std::vector<std::pair<std::string, std::unique_ptr<SqliteDb>>> dbs_;
};

} // namespace af::db
