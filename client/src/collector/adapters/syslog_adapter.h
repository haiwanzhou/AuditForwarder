#pragma once
// Syslog 适配器：监听 UDP 端口（默认 514），解析 RFC 3164（传统 BSD syslog）
// 和 RFC 5424（结构化 syslog）格式消息，转为标准 AuditEvent。

#include "auditforwarder/security_adapter.h"
#include "auditforwarder/types.h"
#include <cstdint>
#include <string>

namespace af {

class SyslogAdapter : public SecurityAdapter {
public:
    SyslogAdapter();
    ~SyslogAdapter() override;

    Result<void> open(const std::string& config_json) override;
    void         close() override;
    int          poll(std::function<void(const AuditEvent&)> emit) override;

    std::string  name() const override;
    std::string  source_type() const override { return "syslog"; }

    // 获取实际绑定端口（open 后可用，端口 0 时由 OS 分配）。
    u16 bound_port() const;

private:
    // 解析单条 syslog 报文并产出 AuditEvent
    void parse_and_emit(const std::string& raw, std::function<void(const AuditEvent&)>& emit);

    u16          port_      { 514 };   // 监听端口（0=OS 分配）
    std::string  bind_addr_ { "0.0.0.0" };
    bool         opened_     { false };

    // 跨平台 socket 句柄（不透明存储，-1=无效）
    std::intptr_t sock_ { -1 };
};

}  // namespace af
