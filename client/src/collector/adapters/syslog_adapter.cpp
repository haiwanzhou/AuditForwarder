// Syslog 适配器实现：UDP 监听 + RFC 3164/5424 解析。

#include "syslog_adapter.h"

#include "auditforwarder/config.h"
#include "auditforwarder/log_meta.h"
#include "auditforwarder/logger.h"

#include <chrono>
#include <cstring>
#include <string>

// 跨平台 socket 头文件
#ifdef AF_PLATFORM_WINDOWS
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  pragma comment(lib, "ws2_32.lib")
#else
#  include <arpa/inet.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <unistd.h>
#  include <sys/time.h>
#endif

namespace af {

// ---- 平台辅助 ----
#ifdef AF_PLATFORM_WINDOWS
using NativeSock = SOCKET;
static constexpr NativeSock kInvalidSock = INVALID_SOCKET;
static inline int close_sock(NativeSock s) { return ::closesocket(s); }
static inline bool init_net() {
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
}
static inline void shutdown_net() { WSACleanup(); }
#else
using NativeSock = int;
static constexpr NativeSock kInvalidSock = -1;
static inline int close_sock(NativeSock s) { return ::close(s); }
static inline bool init_net() { return true; }
static inline void shutdown_net() {}
#endif

static inline NativeSock to_native(std::intptr_t h) {
    return static_cast<NativeSock>(h);
}

// ---- syslog facility/severity 映射 ----
static Severity syslog_severity(int sev) {
    switch (sev) {
        case 0: return Severity::Emergency;
        case 1: return Severity::Alert;
        case 2: return Severity::Critical;
        case 3: return Severity::Error;
        case 4: return Severity::Warning;
        case 5: return Severity::Notice;
        case 6: return Severity::Info;
        default: return Severity::Debug;
    }
}

static EventCategory syslog_facility(int fac) {
    // auth(4) / authpriv(10) → Auth；其余归为 Other
    if (fac == 4 || fac == 10) return EventCategory::Auth;
    return EventCategory::Other;
}

// ---- SyslogAdapter ----

SyslogAdapter::SyslogAdapter() = default;

SyslogAdapter::~SyslogAdapter() {
    close();
}

Result<void> SyslogAdapter::open(const std::string& config_json) {
    // 解析配置
    ConfigValue cfg;
    auto pr = parse_minimal_json(config_json, cfg);
    if (pr.is_err()) {
        return Result<void>::make_error(Error::Code::Parse, "syslog: config parse failed");
    }
    port_      = static_cast<u16>(cfg["port"].as_int(514));
    bind_addr_ = cfg["bind"].as_string("0.0.0.0");

    if (!init_net()) {
        return Result<void>::make_error(Error::Code::Network, "syslog: WSAStartup failed");
    }

    NativeSock s = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (s == kInvalidSock) {
        shutdown_net();
        return Result<void>::make_error(Error::Code::Network, "syslog: socket() failed");
    }

    // 允许端口复用（避免重启时地址占用）
    int yes = 1;
    ::setsockopt(s, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&yes), sizeof(yes));

    // 设置接收超时 100ms（poll 不阻塞太久）
#ifdef AF_PLATFORM_WINDOWS
    DWORD timeout_ms = 100;
    ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
#else
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100 * 1000;
    ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_);
    addr.sin_addr.s_addr = ::inet_addr(bind_addr_.c_str());
    if (::bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        close_sock(s);
        shutdown_net();
        return Result<void>::make_error(Error::Code::Network,
                                         "syslog: bind(" + bind_addr_ + ":" + std::to_string(port_) + ") failed");
    }

    // 获取实际绑定端口（port_=0 时 OS 分配）
    sockaddr_in actual;
    socklen_t alen = sizeof(actual);
    std::memset(&actual, 0, sizeof(actual));
    if (::getsockname(s, reinterpret_cast<sockaddr*>(&actual), &alen) == 0) {
        port_ = ntohs(actual.sin_port);
    }

    sock_   = static_cast<std::intptr_t>(s);
    opened_ = true;
    AF_LOG_INFO("syslog: listening on " << bind_addr_ << ":" << port_);
    return Result<void>::ok();
}

void SyslogAdapter::close() {
    if (!opened_) return;
    NativeSock s = to_native(sock_);
    if (s != kInvalidSock) close_sock(s);
    sock_ = -1;
    opened_ = false;
    shutdown_net();
}

u16 SyslogAdapter::bound_port() const {
    return port_;
}

int SyslogAdapter::poll(std::function<void(const AuditEvent&)> emit) {
    if (!opened_) return 0;

    NativeSock s = to_native(sock_);
    if (s == kInvalidSock) return 0;

    int count = 0;
    // 循环读取直到超时（无更多数据）
    for (int i = 0; i < 64; ++i) {  // 单次最多 64 条，避免长时间占用
        char buf[65536];
        sockaddr_in from;
        socklen_t fromlen = sizeof(from);
        int n = ::recvfrom(s, buf, sizeof(buf) - 1, 0,
                           reinterpret_cast<sockaddr*>(&from), &fromlen);
        if (n <= 0) break;  // 超时或出错

        buf[n] = '\0';
        std::string raw(buf, static_cast<std::size_t>(n));
        parse_and_emit(raw, emit);
        ++count;
    }
    return count;
}

void SyslogAdapter::parse_and_emit(const std::string& raw,
                                   std::function<void(const AuditEvent&)>& emit) {
    // 最小格式：<PRI>...
    if (raw.empty() || raw[0] != '<') return;

    // 提取 PRI
    size_t close = raw.find('>');
    if (close == std::string::npos || close < 2 || close > 4) return;

    int pri = 0;
    try {
        pri = std::stoi(raw.substr(1, close - 1));
    } catch (...) {
        return;
    }
    int facility = pri / 8;
    int severity = pri % 8;

    std::string rest = raw.substr(close + 1);

    std::string hostname;
    std::string app_name;
    std::string message;

    // 判断 RFC 5424（PRI 后跟版本号 '1'）还是 RFC 3164
    bool is_rfc5424 = !rest.empty() && rest[0] == '1' && rest.size() > 1 && rest[1] == ' ';

    if (is_rfc5424) {
        // RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP PROCID MSGID SD MSG
        // 跳过版本 "1 "
        size_t pos = 2;
        auto next_field = [&](std::string& out) {
            size_t sp = rest.find(' ', pos);
            if (sp == std::string::npos) { out = rest.substr(pos); pos = rest.size(); }
            else { out = rest.substr(pos, sp - pos); pos = sp + 1; }
        };

        std::string ts, procid, msgid;
        next_field(ts);       // TIMESTAMP
        next_field(hostname); // HOSTNAME
        next_field(app_name); // APP-NAME
        next_field(procid);   // PROCID
        next_field(msgid);    // MSGID

        // STRUCTURED-DATA：以 '[' 开始或 '-' 表示空
        if (pos < rest.size()) {
            if (rest[pos] == '-') {
                pos += 2;  // "- "
            } else if (rest[pos] == '[') {
                // 找到 SD 结束（所有 ']' 闭合）
                size_t sd_end = pos;
                int depth = 0;
                while (sd_end < rest.size()) {
                    if (rest[sd_end] == '[') ++depth;
                    else if (rest[sd_end] == ']') {
                        --depth;
                        if (depth == 0) { sd_end += 1; break; }
                    }
                    ++sd_end;
                }
                pos = (sd_end < rest.size() && rest[sd_end] == ' ') ? sd_end + 1 : sd_end;
            }
        }
        message = (pos < rest.size()) ? rest.substr(pos) : "";
    } else {
        // RFC 3164: <PRI>TIMESTAMP HOSTNAME TAG: MESSAGE
        // TIMESTAMP = "Mmm DD HH:MM:SS"（15 字符）
        size_t pos = 0;
        if (rest.size() >= 16) pos = 16;  // 跳过时间戳 + 空格
        else return;

        // HOSTNAME（一个词）
        size_t sp = rest.find(' ', pos);
        if (sp == std::string::npos) return;
        hostname = rest.substr(pos, sp - pos);
        pos = sp + 1;

        // 剩余 = "tag: message" 或 "message"
        std::string remaining = rest.substr(pos);
        // 尝试在第一个 ": " 处分割 TAG 和 MESSAGE
        size_t colon = remaining.find(": ");
        if (colon != std::string::npos && colon < 64) {
            app_name = remaining.substr(0, colon);
            message  = remaining.substr(colon + 2);
        } else {
            message = remaining;
        }
    }

    // 构造 AuditEvent
    AuditEvent ev;
    ev.timestamp = SysClock::now();
    ev.ts_micros = std::chrono::duration_cast<std::chrono::microseconds>(
                       ev.timestamp.time_since_epoch()).count();
    ev.category   = syslog_facility(facility);
    ev.severity   = syslog_severity(severity);
    ev.host       = hostname;
    ev.actor.name = app_name.empty() ? hostname : app_name;
    ev.message    = message;
    ev.raw_payload.assign(raw.begin(), raw.end());
    ev.attrs["syslog_facility"]  = std::to_string(facility);
    ev.attrs["syslog_severity"]  = std::to_string(severity);
    ev.attrs[logmeta::attr::kSource] = "syslog";
    logmeta::tag_collector(ev, logmeta::collector::kSyslog);

    emit(ev);
}

std::string SyslogAdapter::name() const {
    return "syslog_udp_" + std::to_string(port_);
}

}  // namespace af
