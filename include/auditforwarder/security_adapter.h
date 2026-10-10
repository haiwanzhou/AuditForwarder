#pragma once
// AuditForwarder - 安全产品适配器基类接口。
// 统一对接 Syslog / 数据库审计 / 堡垒机等异构安全产品日志源，
// 适配器负责拉取/接收原始日志并转为标准 AuditEvent，经回调产出后进入链签名流水线。

#include "auditforwarder/event.h"
#include "auditforwarder/types.h"
#include <functional>
#include <string>

namespace af {

// 安全产品适配器抽象基类。每个具体适配器实现一个安全产品日志源的接入。
class SecurityAdapter {
public:
    virtual ~SecurityAdapter() = default;

    // 初始化适配器（解析配置 JSON、打开端口/文件句柄等）。必须在 poll() 之前调用。
    virtual Result<void> open(const std::string& config_json) = 0;

    // 关闭并释放资源（端口/句柄/线程等）。
    virtual void close() = 0;

    // 轮询：拉取一批日志并通过 emit 回调转为 AuditEvent，返回产出的事件数量。
    // 非阻塞或短超时：无数据时立即返回 0，由调用方控制休眠节奏。
    virtual int poll(std::function<void(const AuditEvent&)> emit) = 0;

    // 适配器实例名称（如 "syslog_udp_514"）。
    virtual std::string name() const = 0;

    // 适配器类型标识："syslog" | "db_audit" | "bastion"。
    virtual std::string source_type() const = 0;
};

}  // namespace af
