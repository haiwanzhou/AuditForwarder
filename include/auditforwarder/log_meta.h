#pragma once
// AuditForwarder - 日志元数据契约（采集器标识 / 优先级 / 高权限标注）。
//
// 设计原则：所有扩展元数据都写入 AuditEvent.attrs（该字段已进入 canonical JSON，
// 哈希链与 /ingest 编码批次天然携带），不改动 AuditEvent 结构体本身，
// 对既有采集流程的侵入仅为每个采集器一行 tag_collector() 调用。

#include "auditforwarder/event.h"

#include <chrono>
#include <cctype>
#include <string>

namespace af::logmeta {

// ---- 采集器规范 ID（与 Collector::name() 的返回值保持一致，单一事实来源）----
namespace collector {
constexpr const char* kFileWin     = "file_win";
constexpr const char* kProcessWin  = "process_win";
constexpr const char* kNetworkWin  = "network_win";
constexpr const char* kCommandWin  = "command_win";
constexpr const char* kRegistryWin = "registry_win";
constexpr const char* kEtwWin      = "etw_win";

constexpr const char* kFileLinux    = "file_linux";
constexpr const char* kProcessLinux = "process_linux";
constexpr const char* kNetworkLinux = "network_linux";
constexpr const char* kCommandLinux = "command_linux";
constexpr const char* kAuditLinux   = "audit_linux";

constexpr const char* kLegacy  = "legacy";   // 服务端迁移的旧记录
constexpr const char* kUnknown = "unknown";  // 无采集器字段时的兜底
}  // namespace collector

// ---- 事件来源（比 collector 更粗的唯一来源标记）----
namespace source {
constexpr const char* kEtwSecurity = "etw_security";  // Windows 安全事件日志
}  // namespace source

// ---- 传输优先级 ----
namespace priority {
constexpr const char* kHigh   = "high";
constexpr const char* kNormal = "normal";
}  // namespace priority

// ---- 高权限级别 ----
namespace priv {
constexpr const char* kElevated = "elevated";  // Windows UAC 提权（高完整性）
constexpr const char* kSystem   = "system";    // Windows SYSTEM（S-1-5-18）
constexpr const char* kRoot     = "root";      // Linux uid=0
constexpr const char* kNone     = "none";
}  // namespace priv

// ---- attrs 保留键名（客户端写入、服务端读取、传输 JSON 展开均使用这些常量）----
namespace attr {
constexpr const char* kCollector     = "collector";
constexpr const char* kSource        = "source";
constexpr const char* kPriority      = "priority";
constexpr const char* kPrivLevel     = "priv_level";
constexpr const char* kPrivOperation = "priv_operation";
constexpr const char* kPrivTs        = "priv_ts";      // 提权检测时间戳（毫秒 epoch）
constexpr const char* kClientTs      = "client_ts";    // 客户端发送时间戳（毫秒 epoch）
constexpr const char* kServerTs      = "server_ts";    // 服务端接收时间戳（毫秒 epoch）
constexpr const char* kEventId       = "event_id";
constexpr const char* kSubjectUser   = "subject_user";
constexpr const char* kSubjectDomain = "subject_domain";
constexpr const char* kLogonId       = "logon_id";
constexpr const char* kProcessName   = "process_name";
constexpr const char* kRawXml        = "raw_xml";
constexpr const char* kInjected      = "injected";     // 测试注入标记
}  // namespace attr

// 当前 Unix 毫秒时间戳。
inline std::string now_millis() {
    return std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
                              std::chrono::system_clock::now().time_since_epoch())
                              .count());
}

// 为事件打上采集器标识。
inline void tag_collector(AuditEvent& ev, const std::string& id) {
    ev.attrs[attr::kCollector] = id;
}

// 读取采集器标识，缺失时返回 unknown。
inline std::string collector_id(const AuditEvent& ev) {
    auto it = ev.attrs.find(attr::kCollector);
    if (it == ev.attrs.end() || it->second.empty()) return collector::kUnknown;
    return it->second;
}

// 是否为 Windows ETW 安全日志采集器产生的事件。
inline bool is_etw(const AuditEvent& ev) {
    return collector_id(ev) == collector::kEtwWin;
}

// 标注高权限操作：高优先级 + 权限级别 + 操作标记 + 检测时间戳，并提升严重级别。
inline void mark_privileged(AuditEvent& ev, const std::string& level) {
    ev.attrs[attr::kPriority]      = priority::kHigh;
    ev.attrs[attr::kPrivLevel]     = level;
    ev.attrs[attr::kPrivOperation] = "1";
    ev.attrs[attr::kPrivTs]        = now_millis();
    if (static_cast<u8>(ev.severity) < static_cast<u8>(Severity::Warning)) {
        ev.severity = Severity::Warning;
    }
}

// 是否为高优先级事件。
inline bool is_high_priority(const AuditEvent& ev) {
    auto it = ev.attrs.find(attr::kPriority);
    return it != ev.attrs.end() && it->second == priority::kHigh;
}

// 批次内是否含高优先级事件（传输层据此把整批送入高优先级队列）。
inline bool batch_is_high_priority(const EventBatch& b) {
    for (const auto& ev : b.events)
        if (is_high_priority(ev)) return true;
    return false;
}

// 高权限级别，未标注时返回 none。
inline std::string privilege_level_of(const AuditEvent& ev) {
    auto it = ev.attrs.find(attr::kPrivLevel);
    if (it == ev.attrs.end() || it->second.empty()) return priv::kNone;
    return it->second;
}

// 盖客户端发送时间戳（传输前调用）。
inline void stamp_client_ts(AuditEvent& ev) {
    ev.attrs[attr::kClientTs] = now_millis();
}

// 采集器 ID 安全化：仅允许 [a-z0-9_]，非法字符替换为 '_'，空串/全非法时兜底 unknown。
// 用于服务端把 collector 直接拼入存储路径前的防护。
inline std::string sanitize_collector_id(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        unsigned char uc = static_cast<unsigned char>(c);
        if (std::islower(uc) || std::isdigit(uc) || c == '_') {
            out.push_back(c);
        } else {
            out.push_back('_');
        }
    }
    if (out.empty()) return collector::kUnknown;
    return out;
}

}  // namespace af::logmeta
