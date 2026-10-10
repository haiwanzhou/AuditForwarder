// 堡垒机适配器实现：REST API 轮询 + 增量游标同步。

#include "bastion_adapter.h"

#include "auditforwarder/config.h"
#include "auditforwarder/log_meta.h"
#include "auditforwarder/logger.h"

#include <chrono>
#include <cstring>
#include <sstream>
#include <string>

// 跨平台 socket 头文件（默认 HTTP GET 客户端用）
#ifdef AF_PLATFORM_WINDOWS
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  pragma comment(lib, "ws2_32.lib")
#else
#  include <arpa/inet.h>
#  include <netinet/in.h>
#  include <netdb.h>
#  include <sys/socket.h>
#  include <unistd.h>
#endif

namespace af {

// ---- 平台辅助 ----
#ifdef AF_PLATFORM_WINDOWS
using NativeSock = SOCKET;
static constexpr NativeSock kInvalidSock = INVALID_SOCKET;
static inline int close_sock(NativeSock s) { return ::closesocket(s); }
static inline bool init_net() { WSADATA wsa; return WSAStartup(MAKEWORD(2, 2), &wsa) == 0; }
static inline void shutdown_net() { WSACleanup(); }
#else
using NativeSock = int;
static constexpr NativeSock kInvalidSock = -1;
static inline int close_sock(NativeSock s) { return ::close(s); }
static inline bool init_net() { return true; }
static inline void shutdown_net() {}
#endif

// ---- 简易 HTTP GET 客户端（仅 http://，用于本地测试）----
// 生产环境应注入支持 HTTPS 的 FetchFn。
static std::string http_get(const std::string& url, const std::string& token) {
    // 解析 URL: http://host:port/path
    if (url.substr(0, 7) != "http://") return "";

    std::string host_port = url.substr(7);
    std::string path = "/";
    auto slash = host_port.find('/');
    if (slash != std::string::npos) {
        path = host_port.substr(slash);
        host_port = host_port.substr(0, slash);
    }

    int port = 80;
    std::string host = host_port;
    auto colon = host_port.find(':');
    if (colon != std::string::npos) {
        host = host_port.substr(0, colon);
        port = std::stoi(host_port.substr(colon + 1));
    }

    static bool net_init = init_net();
    (void)net_init;

    // 解析主机名
    addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* res = nullptr;
    if (::getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0 || !res) {
        return "";
    }

    NativeSock sock = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock == kInvalidSock) {
        ::freeaddrinfo(res);
        return "";
    }

    // 连接超时 3 秒
    timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    ::setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&tv), sizeof(tv));

    if (::connect(sock, res->ai_addr, static_cast<int>(res->ai_addrlen)) < 0) {
        close_sock(sock);
        ::freeaddrinfo(res);
        return "";
    }
    ::freeaddrinfo(res);

    // 发送 HTTP GET
    std::ostringstream req;
    req << "GET " << path << " HTTP/1.0\r\n"
        << "Host: " << host << "\r\n";
    if (!token.empty()) {
        req << "Authorization: Bearer " << token << "\r\n";
    }
    req << "Connection: close\r\n\r\n";
    std::string request = req.str();
    ::send(sock, request.c_str(), static_cast<int>(request.size()), 0);

    // 读取响应
    std::string response;
    char buf[4096];
    int n;
    while ((n = ::recv(sock, buf, sizeof(buf), 0)) > 0) {
        response.append(buf, static_cast<std::size_t>(n));
    }
    close_sock(sock);

    // 分离 header 和 body（找 \r\n\r\n）
    auto body_start = response.find("\r\n\r\n");
    if (body_start == std::string::npos) return "";
    return response.substr(body_start + 4);
}

// ---- BastionAdapter ----

BastionAdapter::BastionAdapter() {
    // 默认拉取器：简易 HTTP GET
    fetcher_ = [](const std::string& url, const std::string& token, const std::string& cursor) -> std::string {
        (void)cursor;  // 默认实现不使用游标
        return http_get(url, token);
    };
}

BastionAdapter::BastionAdapter(FetchFn fetcher) : fetcher_(std::move(fetcher)) {}

BastionAdapter::~BastionAdapter() {
    close();
}

Result<void> BastionAdapter::open(const std::string& config_json) {
    ConfigValue cfg;
    auto pr = parse_minimal_json(config_json, cfg);
    if (pr.is_err()) {
        return Result<void>::make_error(Error::Code::Parse, "bastion: config parse failed");
    }
    url_   = cfg["url"].as_string();
    token_ = cfg["token"].as_string();
    cursor_.clear();
    if (url_.empty()) {
        return Result<void>::make_error(Error::Code::InvalidArgument,
                                         "bastion: 'url' is required");
    }
    opened_ = true;
    AF_LOG_INFO("bastion: polling " << url_);
    return Result<void>::ok();
}

void BastionAdapter::close() {
    opened_ = false;
}

int BastionAdapter::poll(std::function<void(const AuditEvent&)> emit) {
    if (!opened_ || !fetcher_) return 0;

    // 构造带游标的 URL
    std::string full_url = url_;
    if (!cursor_.empty()) {
        full_url += (url_.find('?') != std::string::npos ? "&" : "?");
        full_url += "after=" + cursor_;
    }

    std::string response = fetcher_(full_url, token_, cursor_);
    if (response.empty()) return 0;

    // 解析 JSON 响应
    ConfigValue root;
    auto pr = parse_minimal_json(response, root);
    if (pr.is_err()) return 0;

    int count = 0;

    // 解析命令列表
    if (root.has("commands") && root["commands"].type() == ConfigValue::Type::List) {
        const auto& cmds = root["commands"].as_list();
        for (const auto& cmd : cmds) {
            AuditEvent ev;
            ev.timestamp = SysClock::now();
            ev.ts_micros = std::chrono::duration_cast<std::chrono::microseconds>(
                               ev.timestamp.time_since_epoch()).count();
            ev.category = EventCategory::Command;
            ev.action   = EventAction::Execute;
            ev.actor.user = cmd["user"].as_string();
            ev.target.path = cmd["asset"].as_string();
            ev.target.kind = "host";
            std::string command = cmd["command"].as_string();
            ev.command = command;
            ev.message = command;
            std::string cmd_id = cmd["id"].as_string();
            ev.attrs["bastion_cmd_id"] = cmd_id;
            ev.attrs[logmeta::attr::kSource] = "bastion";
            logmeta::tag_collector(ev, logmeta::collector::kBastion);

            emit(ev);
            ++count;

            // 更新游标为最后一条记录的 ID
            if (!cmd_id.empty()) cursor_ = cmd_id;
        }
    }

    // 支持 next_cursor 字段
    if (root.has("next_cursor") && !root["next_cursor"].as_string().empty()) {
        cursor_ = root["next_cursor"].as_string();
    }

    return count;
}

std::string BastionAdapter::name() const {
    return "bastion";
}

}  // namespace af
