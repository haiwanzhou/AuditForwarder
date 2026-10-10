#pragma once
// 数据库审计适配器：轮询 DB 审计日志导出文件（JSON Lines 格式），
// 增量读取新增记录并转为标准 AuditEvent。
// 支持的日志源：MySQL audit plugin 日志导出、PostgreSQL pgaudit 日志导出等。

#include "auditforwarder/security_adapter.h"
#include "auditforwarder/types.h"
#include <cstdint>
#include <fstream>
#include <string>

namespace af {

class DatabaseAuditAdapter : public SecurityAdapter {
public:
    DatabaseAuditAdapter();
    ~DatabaseAuditAdapter() override;

    Result<void> open(const std::string& config_json) override;
    void         close() override;
    int          poll(std::function<void(const AuditEvent&)> emit) override;

    std::string  name() const override;
    std::string  source_type() const override { return "db_audit"; }

private:
    std::string  path_     ;          // 审计日志文件路径（JSON Lines）
    std::uint64_t offset_  { 0 };      // 当前读取偏移量
    bool         opened_   { false };
};

}  // namespace af
