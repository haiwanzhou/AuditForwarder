// 数据库审计适配器实现：轮询 JSON Lines 格式的 DB 审计日志导出文件。

#include "db_audit_adapter.h"

#include "auditforwarder/config.h"
#include "auditforwarder/log_meta.h"
#include "auditforwarder/logger.h"

#include <chrono>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>

namespace af {

DatabaseAuditAdapter::DatabaseAuditAdapter() = default;

DatabaseAuditAdapter::~DatabaseAuditAdapter() {
    close();
}

Result<void> DatabaseAuditAdapter::open(const std::string& config_json) {
    ConfigValue cfg;
    auto pr = parse_minimal_json(config_json, cfg);
    if (pr.is_err()) {
        return Result<void>::make_error(Error::Code::Parse, "db_audit: config parse failed");
    }
    path_   = cfg["path"].as_string();
    offset_ = 0;
    if (path_.empty()) {
        return Result<void>::make_error(Error::Code::InvalidArgument,
                                         "db_audit: 'path' is required");
    }
    opened_ = true;
    AF_LOG_INFO("db_audit: polling " << path_);
    return Result<void>::ok();
}

void DatabaseAuditAdapter::close() {
    opened_ = false;
    offset_ = 0;
}

int DatabaseAuditAdapter::poll(std::function<void(const AuditEvent&)> emit) {
    if (!opened_ || path_.empty()) return 0;

    std::ifstream f(path_, std::ios::binary);
    if (!f.is_open()) return 0;  // 文件不存在，本轮无数据

    // 检测文件轮转（文件变短了）
    f.seekg(0, std::ios::end);
    auto file_size = static_cast<std::uint64_t>(f.tellg());
    if (file_size < offset_) {
        offset_ = 0;  // 文件已轮转，从头开始
    }
    f.seekg(static_cast<std::streamoff>(offset_), std::ios::beg);

    int count = 0;
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty()) continue;
        offset_ += line.size() + 1;  // +1 for newline

        // 解析 JSON 行
        ConfigValue rec;
        auto pr = parse_minimal_json(line, rec);
        if (pr.is_err()) continue;  // 跳过非法行

        // 构造 AuditEvent
        AuditEvent ev;
        ev.timestamp = SysClock::now();
        ev.ts_micros = std::chrono::duration_cast<std::chrono::microseconds>(
                           ev.timestamp.time_since_epoch()).count();
        ev.host    = rec["host"].as_string();
        ev.actor.user = rec["user"].as_string();

        std::string stmt = rec["statement"].as_string();
        std::string cmd_type = rec["command_type"].as_string("QUERY");

        ev.command = stmt;
        ev.message = stmt;
        ev.category = EventCategory::Other;

        // 命令类型 → 动作映射
        if (cmd_type == "DDL" || cmd_type == "CREATE" || cmd_type == "ALTER" ||
            cmd_type == "DROP" || cmd_type == "TRUNCATE") {
            ev.action = EventAction::Set;
        } else if (cmd_type == "DML" || cmd_type == "INSERT" ||
                   cmd_type == "UPDATE" || cmd_type == "DELETE") {
            ev.action = EventAction::Write;
        } else {
            ev.action = EventAction::Read;
        }

        ev.attrs["db_command_type"] = cmd_type;
        ev.attrs["db_database"]     = rec["database"].as_string();
        ev.attrs["db_statement"]    = stmt;
        ev.attrs[logmeta::attr::kSource] = "db_audit";
        logmeta::tag_collector(ev, logmeta::collector::kDbAudit);

        emit(ev);
        ++count;
    }

    return count;
}

std::string DatabaseAuditAdapter::name() const {
    return "db_audit_" + path_;
}

}  // namespace af
