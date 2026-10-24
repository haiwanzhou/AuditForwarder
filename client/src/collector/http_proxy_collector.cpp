// M5-3 本地 HTTP 代理行为采集器实现。
//
// 形态：本机回环 HTTP 正向代理。
//   - 普通 HTTP：解析绝对 URL / Host 头，转发请求并读取响应状态码；
//   - CONNECT ：按盲隧道转发（HTTPS 只能看到目标 host:port，无法看到 uri）；
//   - 两种方式都产出 category=network 的操作事件，字段对齐 Zeek http.log 子集。

#ifdef AF_PLATFORM_WINDOWS
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  pragma comment(lib, "ws2_32.lib")
#else
#  include <arpa/inet.h>
#  include <fcntl.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <sys/select.h>
#  include <sys/socket.h>
#  include <unistd.h>
#  include <cerrno>
#endif

#include "http_proxy_collector.h"

#include "auditforwarder/log_meta.h"
#include "auditforwarder/logger.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <thread>

namespace af {
namespace {

// ---- 跨平台 socket 辅助 ----
#ifdef AF_PLATFORM_WINDOWS
using Sock = SOCKET;
const Sock kInvalidSock = INVALID_SOCKET;
inline int last_sock_error() { return ::WSAGetLastError(); }
inline void close_socket(Sock s) { ::closesocket(s); }
inline bool error_retryable(int e) {
    return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS || e == WSAETIMEDOUT || e == WSAEINTR;
}
inline bool error_in_progress(int e) { return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS; }
#else
using Sock = int;
const Sock kInvalidSock = -1;
inline int last_sock_error() { return errno; }
inline void close_socket(Sock s) { ::close(s); }
inline bool error_retryable(int e) {
    return e == EAGAIN || e == EWOULDBLOCK || e == EINPROGRESS || e == EINTR;
}
inline bool error_in_progress(int e) { return e == EINPROGRESS; }
#endif

constexpr int kIoTimeoutMs     = 5000;   // 单次读写超时
constexpr int kConnectTimeoutMs = 5000;
constexpr std::size_t kMaxHeadBytes = 64 * 1024;
constexpr std::size_t kMaxBodyBytes = 16 * 1024 * 1024;

void set_nonblocking(Sock s, bool on) {
#ifdef AF_PLATFORM_WINDOWS
    u_long mode = on ? 1 : 0;
    ::ioctlsocket(s, FIONBIO, &mode);
#else
    int flags = ::fcntl(s, F_GETFL, 0);
    if (flags < 0) return;
    ::fcntl(s, F_SETFL, on ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK));
#endif
}

void set_io_timeout(Sock s, int ms) {
#ifdef AF_PLATFORM_WINDOWS
    DWORD tv = static_cast<DWORD>(ms);
    ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    ::setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
    timeval tv{};
    tv.tv_sec  = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

// 等待 socket 可读/可写，返回 false 表示超时或出错。
bool wait_socket(Sock s, bool for_write, int ms) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(s, &fds);
    timeval tv{};
    tv.tv_sec  = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
#ifdef AF_PLATFORM_WINDOWS
    int n = ::select(0, for_write ? nullptr : &fds, for_write ? &fds : nullptr, nullptr, &tv);
#else
    int n = ::select(static_cast<int>(s) + 1,
                     for_write ? nullptr : &fds, for_write ? &fds : nullptr, nullptr, &tv);
#endif
    return n > 0;
}

// 带超时地连接目标主机，成功返回可用 socket。
Sock connect_target(const std::string& host, u16 port, int timeout_ms) {
    addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (::getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0 || !res) {
        return kInvalidSock;
    }

    Sock result = kInvalidSock;
    for (addrinfo* p = res; p != nullptr; p = p->ai_next) {
        Sock s = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s == kInvalidSock) continue;

        set_nonblocking(s, true);
        bool ok = ::connect(s, p->ai_addr, static_cast<int>(p->ai_addrlen)) == 0;
        if (!ok && error_in_progress(last_sock_error())) {
            ok = wait_socket(s, true, timeout_ms);
            if (ok) {
                int so_err = 0;
#ifdef AF_PLATFORM_WINDOWS
                int len = static_cast<int>(sizeof(so_err));
#else
                socklen_t len = sizeof(so_err);
#endif
                ::getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_err), &len);
                ok = (so_err == 0);
            }
        }
        if (ok) {
            set_nonblocking(s, false);
            set_io_timeout(s, kIoTimeoutMs);
            result = s;
            break;
        }
        close_socket(s);
    }
    ::freeaddrinfo(res);
    return result;
}

bool send_all(Sock s, const char* data, std::size_t len) {
    std::size_t sent = 0;
#ifdef MSG_NOSIGNAL
    const int flags = MSG_NOSIGNAL;
#else
    const int flags = 0;
#endif
    while (sent < len) {
        int n = ::send(s, data + sent, static_cast<int>(len - sent), flags);
        if (n <= 0) return false;
        sent += static_cast<std::size_t>(n);
    }
    return true;
}

// 读取响应/请求头直到分隔符（包含分隔符与可能已到达的正文）。
bool recv_until(Sock s, std::string& out, const char* delim, std::size_t max_bytes,
                std::size_t& delim_end) {
    out.clear();
    delim_end = 0;
    char buf[4096];
    for (;;) {
        std::size_t pos = out.find(delim);
        if (pos != std::string::npos) {
            delim_end = pos + std::strlen(delim);
            return true;
        }
        if (out.size() >= max_bytes) return false;
        int n = ::recv(s, buf, sizeof(buf), 0);
        if (n <= 0) return false;
        out.append(buf, static_cast<std::size_t>(n));
    }
}

bool recv_append(Sock s, std::string& out) {
    char buf[4096];
    int n = ::recv(s, buf, sizeof(buf), 0);
    if (n <= 0) return false;
    out.append(buf, static_cast<std::size_t>(n));
    return true;
}

std::string lower_copy(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string trim_copy(const std::string& s) {
    std::size_t b = 0, e = s.size();
    while (b < e && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r')) ++b;
    while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r')) --e;
    return s.substr(b, e - b);
}

struct RequestHead {
    std::string method;
    std::string target;
    std::string version;
    std::map<std::string, std::string> headers;  // 键统一小写
};

std::string header_of(const RequestHead& h, const std::string& name) {
    auto it = h.headers.find(name);
    return it == h.headers.end() ? std::string() : it->second;
}

// 从 Cookie 头里取指定名字的值（cookie 名大小写不敏感）。
std::string cookie_of(const RequestHead& h, const std::string& name) {
    const std::string raw = header_of(h, "cookie");
    if (raw.empty() || name.empty()) return {};
    std::size_t pos = 0;
    while (pos <= raw.size()) {
        std::size_t semi = raw.find(';', pos);
        std::string item = raw.substr(pos, semi == std::string::npos ? std::string::npos : semi - pos);
        std::size_t eq = item.find('=');
        if (eq != std::string::npos) {
            if (lower_copy(trim_copy(item.substr(0, eq))) == lower_copy(name)) {
                return trim_copy(item.substr(eq + 1));
            }
        }
        if (semi == std::string::npos) break;
        pos = semi + 1;
    }
    return {};
}

// 从 JSON 请求体里取某个字符串字段（仅用于登录请求的 username 兜底）。
std::string json_body_string(const std::string& body, const std::string& key) {
    if (body.empty() || key.empty()) return {};
    const std::string needle = "\"" + key + "\"";
    std::size_t p = body.find(needle);
    if (p == std::string::npos) return {};
    p = body.find(':', p + needle.size());
    if (p == std::string::npos) return {};
    ++p;
    while (p < body.size() && (body[p] == ' ' || body[p] == '\t')) ++p;
    if (p >= body.size() || body[p] != '"') return {};
    std::size_t q = body.find('"', p + 1);
    if (q == std::string::npos) return {};
    return body.substr(p + 1, q - p - 1);
}

// base64 / base64url 解码（忽略填充与非法字符）。
std::string base64_decode(const std::string& in) {
    static const char kTable[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val = 0, bits = 0;
    for (char c : in) {
        if (c == '=') break;
        int d = 0;
        if (c == '-')      d = 62;
        else if (c == '_') d = 63;
        else {
            const char* p = std::strchr(kTable, c);
            if (!p || c == '\0') continue;
            d = static_cast<int>(p - kTable);
        }
        val = (val << 6) | d;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((val >> bits) & 0xFF));
        }
    }
    return out;
}

// 从 Authorization: Bearer <token> 中解析登录用户名。
// 图书系统的 token 形如 base64url({"user_id":..,"username":..,"role":..}).<hmac>，
// 取第一段解码即可拿到 username —— 身份来自真实请求，而非客户端配置。
std::string username_from_bearer(const std::string& auth) {
    if (auth.empty()) return {};
    std::size_t sp = auth.find(' ');
    const std::string token = sp == std::string::npos ? auth : auth.substr(sp + 1);
    const std::size_t dot = token.find('.');
    const std::string payload = dot == std::string::npos ? token : token.substr(0, dot);
    if (payload.empty()) return {};
    return json_body_string(base64_decode(payload), "username");
}

bool parse_request_head(const std::string& raw, std::size_t head_end, RequestHead& out) {
    std::string block = raw.substr(0, head_end);
    std::size_t eol = block.find("\r\n");
    std::string request_line = eol == std::string::npos ? block : block.substr(0, eol);
    std::size_t sp1 = request_line.find(' ');
    if (sp1 == std::string::npos) return false;
    std::size_t sp2 = request_line.find(' ', sp1 + 1);
    if (sp2 == std::string::npos) return false;
    out.method  = request_line.substr(0, sp1);
    out.target  = request_line.substr(sp1 + 1, sp2 - sp1 - 1);
    out.version = trim_copy(request_line.substr(sp2 + 1));
    if (out.method.empty() || out.target.empty()) return false;

    std::size_t pos = eol == std::string::npos ? block.size() : eol + 2;
    while (pos < block.size()) {
        std::size_t next = block.find("\r\n", pos);
        std::string line = block.substr(pos, next == std::string::npos ? std::string::npos : next - pos);
        if (line.empty()) break;
        std::size_t colon = line.find(':');
        if (colon != std::string::npos) {
            out.headers[lower_copy(trim_copy(line.substr(0, colon)))] = trim_copy(line.substr(colon + 1));
        }
        if (next == std::string::npos) break;
        pos = next + 2;
    }
    return true;
}

int parse_status_code(const std::string& head) {
    std::size_t sp = head.find(' ');
    if (sp == std::string::npos) return 0;
    std::size_t sp2 = head.find(' ', sp + 1);
    std::string code = head.substr(sp + 1, sp2 == std::string::npos ? std::string::npos : sp2 - sp - 1);
    try {
        return std::stoi(code);
    } catch (...) {
        return 0;
    }
}

// "host[:port]" 拆分（忽略 IPv6 字面量场景，代理仅面向普通域名/IPv4）。
bool split_host_port(const std::string& in, u16 default_port, std::string& host, u16& port) {
    std::string s = trim_copy(in);
    if (s.empty()) return false;
    std::size_t colon = s.rfind(':');
    if (colon != std::string::npos && s.find(':') == colon) {
        host = s.substr(0, colon);
        try {
            port = static_cast<u16>(std::stoi(s.substr(colon + 1)));
        } catch (...) {
            return false;
        }
    } else {
        host = s;
        port = default_port;
    }
    return !host.empty() && port != 0;
}

// 读取 Content-Length 正文到 out（out 中可能已含头部之后的部分数据）。
bool read_content_length_body(Sock s, std::string& out, std::size_t total) {
    if (total > kMaxBodyBytes) return false;
    while (out.size() < total) {
        if (!recv_append(s, out)) return false;
    }
    if (out.size() > total) out.resize(total);
    return true;
}

// 原样读取 chunked 正文（转发保持原始编码），decoded 返回解码后的字节数。
bool read_chunked_body(Sock s, std::string& body, std::size_t& decoded) {
    std::size_t pos = 0;
    for (;;) {
        std::size_t eol = body.find("\r\n", pos);
        while (eol == std::string::npos) {
            if (body.size() > kMaxBodyBytes || !recv_append(s, body)) return false;
            eol = body.find("\r\n", pos);
        }
        std::string size_line = body.substr(pos, eol - pos);
        std::size_t semi = size_line.find(';');
        if (semi != std::string::npos) size_line = size_line.substr(0, semi);
        unsigned long chunk = 0;
        try {
            chunk = std::stoul(size_line, nullptr, 16);
        } catch (...) {
            return false;
        }
        std::size_t data_start = eol + 2;
        if (chunk == 0) {
            // 末块 + 可选 trailer，读到空行为止
            std::size_t end = body.find("\r\n\r\n", eol);
            while (end == std::string::npos && body.size() < kMaxBodyBytes && recv_append(s, body)) {
                end = body.find("\r\n\r\n", eol);
            }
            return true;
        }
        std::size_t need = data_start + chunk + 2;
        while (body.size() < need) {
            if (body.size() > kMaxBodyBytes || !recv_append(s, body)) return false;
        }
        decoded += chunk;
        pos = need;
    }
}

// 将请求体留存内容限制为可打印文本，避免二进制污染 JSON 事件。
std::string sanitize_snippet(const std::string& body, std::size_t max_len) {
    std::string out;
    out.reserve(std::min(body.size(), max_len));
    for (char c : body) {
        if (out.size() >= max_len) break;
        unsigned char uc = static_cast<unsigned char>(c);
        if (uc == '\r' || uc == '\n' || uc == '\t') out.push_back(' ');
        else if (uc >= 0x20 && uc < 0x7f) out.push_back(c);
        else out.push_back('.');
    }
    return out;
}

}  // namespace

// =========================================================================
// 纯解析工具（单元测试直接调用）
// =========================================================================
namespace http_proxy_detail {

UrlParts parse_absolute_url(const std::string& url) {
    UrlParts out;
    std::string s = trim_copy(url);
    std::string low = lower_copy(s);
    const std::string scheme = "http://";
    if (low.compare(0, scheme.size(), scheme) != 0) return out;

    std::size_t start = scheme.size();
    std::size_t path_pos = s.find('/', start);
    std::size_t query_pos = s.find('?', start);
    std::size_t host_end = s.size();
    if (path_pos != std::string::npos) host_end = std::min(host_end, path_pos);
    if (query_pos != std::string::npos) host_end = std::min(host_end, query_pos);

    std::string hostport = s.substr(start, host_end - start);
    // 丢弃 userinfo（http://user:pass@host/...）
    std::size_t at = hostport.rfind('@');
    if (at != std::string::npos) hostport = hostport.substr(at + 1);

    u16 port = 80;
    std::string host;
    if (!split_host_port(hostport, 80, host, port)) return out;

    std::string path = "/";
    if (path_pos != std::string::npos) path = s.substr(path_pos);
    else if (query_pos != std::string::npos) path = "/" + s.substr(query_pos);

    out.host = host;
    out.port = port;
    out.path = path;
    out.ok   = true;
    return out;
}

bool host_allowed(const std::vector<std::string>& targets, const std::string& host) {
    if (targets.empty()) return true;
    std::string h = lower_copy(trim_copy(host));
    if (h.empty()) return false;

    for (const auto& raw : targets) {
        std::string t = lower_copy(trim_copy(raw));
        if (t.empty()) continue;
        // 兼容 http:// 前缀与端口写法
        const std::string http_prefix  = "http://";
        const std::string https_prefix = "https://";
        if (t.compare(0, http_prefix.size(), http_prefix) == 0) t = t.substr(http_prefix.size());
        else if (t.compare(0, https_prefix.size(), https_prefix) == 0) t = t.substr(https_prefix.size());
        std::size_t slash = t.find('/');
        if (slash != std::string::npos) t = t.substr(0, slash);
        std::size_t colon = t.rfind(':');
        if (colon != std::string::npos && t.find(':') == colon) t = t.substr(0, colon);
        if (t.compare(0, 2, "*.") == 0) t = t.substr(2);
        if (!t.empty() && t.front() == '.') t = t.substr(1);
        if (t.empty()) continue;

        if (h == t) return true;
        // 子域后缀匹配：books.example.com ∈ example.com
        if (h.size() > t.size() &&
            h.compare(h.size() - t.size() - 1, t.size() + 1, "." + t) == 0) {
            return true;
        }
    }
    return false;
}

EventAction action_for_method(const std::string& method) {
    std::string m = lower_copy(trim_copy(method));
    if (m == "get" || m == "head" || m == "options" || m == "trace") return EventAction::Read;
    if (m == "post")   return EventAction::Create;
    if (m == "put" || m == "patch") return EventAction::Write;
    if (m == "delete") return EventAction::Delete;
    if (m == "connect") return EventAction::Connect;
    return EventAction::Unknown;
}

}  // namespace http_proxy_detail

// =========================================================================
// HttpProxyEngine::Impl
// =========================================================================
struct HttpProxyEngine::Impl {
    HttpProxyConfig cfg;
    EventCallback   cb;

    std::atomic<bool> running { false };
    Sock              listen_sock { kInvalidSock };
    u16               bound_port { 0 };
    std::thread       accept_thread;
    std::atomic<int>  active { 0 };
    bool              net_started { false };

    Impl(HttpProxyConfig c, EventCallback callback) : cfg(std::move(c)), cb(std::move(callback)) {}
    ~Impl() { stop(); }

    Result<void> start();
    void         stop();
    void         accept_loop();
    void         handle_client(Sock client);
    void         handle_connect(Sock client, const RequestHead& req, bool allowed);
    void         handle_plain(Sock client, const std::string& raw, std::size_t head_end,
                              const RequestHead& req);
    void         relay_bidirectional(Sock a, Sock b);
    void         relay_downstream(Sock from, Sock to);

    void emit_event(const std::string& method, const std::string& host, u16 port,
                    const std::string& uri, const std::string& user_agent,
                    int status_code, std::size_t req_body_len, const std::string& body_snippet,
                    bool allowed, const std::string& oper_id = {});

    // 操作员身份提取：从同一次 HTTP 请求中解析"这是谁做的"。
    // 顺序：显式身份头 > 身份 Cookie > 请求体 username（登录请求）> 空（由 Enricher 回退到配置值）。
    std::string extract_operator(const RequestHead& req, const std::string& body) const;
};

Result<void> HttpProxyEngine::Impl::start() {
    if (running.exchange(true)) return Result<void>::ok();

#ifdef AF_PLATFORM_WINDOWS
    WSADATA wsa;
    if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        running.store(false);
        return Result<void>::make_error(Error::Code::Network, "http_proxy: WSAStartup failed");
    }
    net_started = true;
#endif

    // bind 地址仅支持 IPv4 字面量或 localhost
    std::string bind_addr = cfg.bind_addr.empty() ? "127.0.0.1" : cfg.bind_addr;
    in_addr bind_in{};
    if (lower_copy(bind_addr) == "localhost") {
        bind_in.s_addr = htonl(INADDR_LOOPBACK);
    } else if (::inet_pton(AF_INET, bind_addr.c_str(), &bind_in) != 1) {
#ifdef AF_PLATFORM_WINDOWS
        ::WSACleanup();
        net_started = false;
#endif
        running.store(false);
        return Result<void>::make_error(Error::Code::InvalidArgument,
                                        "http_proxy: invalid bind address: " + bind_addr);
    }

    Sock s = ::socket(AF_INET, SOCK_STREAM, 0);
    if (s == kInvalidSock) {
#ifdef AF_PLATFORM_WINDOWS
        ::WSACleanup();
        net_started = false;
#endif
        running.store(false);
        return Result<void>::make_error(Error::Code::Network, "http_proxy: socket() failed");
    }

    int yes = 1;
    ::setsockopt(s, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&yes), sizeof(yes));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(cfg.listen_port);
    addr.sin_addr   = bind_in;
    if (::bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
        ::listen(s, 64) != 0) {
        close_socket(s);
#ifdef AF_PLATFORM_WINDOWS
        ::WSACleanup();
        net_started = false;
#endif
        running.store(false);
        return Result<void>::make_error(
            Error::Code::Network,
            "http_proxy: bind/listen(" + bind_addr + ":" + std::to_string(cfg.listen_port) + ") failed");
    }

    sockaddr_in actual{};
#ifdef AF_PLATFORM_WINDOWS
    int alen = static_cast<int>(sizeof(actual));
#else
    socklen_t alen = sizeof(actual);
#endif
    if (::getsockname(s, reinterpret_cast<sockaddr*>(&actual), &alen) == 0) {
        bound_port = ntohs(actual.sin_port);
    }
    listen_sock = s;
    accept_thread = std::thread([this] { accept_loop(); });
    AF_LOG_INFO("http_proxy: listening on " << bind_addr << ":" << bound_port
               << " target_hosts=" << cfg.target_hosts.size());
    return Result<void>::ok();
}

void HttpProxyEngine::Impl::stop() {
    if (!running.exchange(false)) return;
    if (listen_sock != kInvalidSock) {
        close_socket(listen_sock);
        listen_sock = kInvalidSock;
    }
    if (accept_thread.joinable()) accept_thread.join();
    // 等待在途连接处理完（各连接受 5s 读写超时约束）
    for (int i = 0; i < 200 && active.load() > 0; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
#ifdef AF_PLATFORM_WINDOWS
    if (net_started) {
        ::WSACleanup();
        net_started = false;
    }
#endif
}

void HttpProxyEngine::Impl::accept_loop() {
    while (running.load()) {
        if (!wait_socket(listen_sock, false, 300)) continue;
        Sock client = ::accept(listen_sock, nullptr, nullptr);
        if (client == kInvalidSock) continue;
        set_io_timeout(client, kIoTimeoutMs);
        active.fetch_add(1);
        std::thread([this, client] {
            handle_client(client);
            close_socket(client);
            active.fetch_sub(1);
        }).detach();
    }
}

void HttpProxyEngine::Impl::handle_client(Sock client) {
    if (!running.load()) return;

    std::string raw;
    std::size_t head_end = 0;
    if (!recv_until(client, raw, "\r\n\r\n", kMaxHeadBytes, head_end)) return;

    RequestHead req;
    if (!parse_request_head(raw, head_end, req)) {
        static const char kBad[] = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        send_all(client, kBad, sizeof(kBad) - 1);
        return;
    }

    if (lower_copy(req.method) == "connect") {
        bool allowed = http_proxy_detail::host_allowed(cfg.target_hosts, req.target);
        // target 形如 host:port，host_allowed 需要纯 host
        std::string host;
        u16 port = 443;
        if (split_host_port(req.target, 443, host, port)) {
            allowed = http_proxy_detail::host_allowed(cfg.target_hosts, host);
        }
        handle_connect(client, req, allowed);
        return;
    }

    handle_plain(client, raw, head_end, req);
}

void HttpProxyEngine::Impl::handle_connect(Sock client, const RequestHead& req, bool allowed) {
    std::string host;
    u16 port = 443;
    if (!split_host_port(req.target, 443, host, port)) {
        static const char kBad[] = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
        send_all(client, kBad, sizeof(kBad) - 1);
        return;
    }

    Sock target = connect_target(host, port, kConnectTimeoutMs);
    if (target == kInvalidSock) {
        static const char kFail[] = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        send_all(client, kFail, sizeof(kFail) - 1);
        emit_event("CONNECT", host, port, "", header_of(req, "user-agent"), 502, 0, "", allowed,
                   extract_operator(req, {}));
        return;
    }

    static const char kOk[] = "HTTP/1.1 200 Connection Established\r\n\r\n";
    if (!send_all(client, kOk, sizeof(kOk) - 1)) {
        close_socket(target);
        return;
    }
    emit_event("CONNECT", host, port, "", header_of(req, "user-agent"), 200, 0, "", allowed,
               extract_operator(req, {}));
    relay_bidirectional(client, target);
    close_socket(target);
}

void HttpProxyEngine::Impl::handle_plain(Sock client, const std::string& raw,
                                         std::size_t head_end, const RequestHead& req) {
    const std::string method = req.method;

    // 目标：优先解析绝对 URL，其次按 Host 头 + origin-form 处理
    auto url = http_proxy_detail::parse_absolute_url(req.target);
    std::string host_hdr = header_of(req, "host");
    if (!url.ok) {
        std::string host;
        u16 port = 80;
        if (!split_host_port(host_hdr, 80, host, port)) {
            static const char kBad[] = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            send_all(client, kBad, sizeof(kBad) - 1);
            return;
        }
        url.host = host;
        url.port = port;
        url.path = req.target.empty() ? "/" : req.target;
        url.ok   = true;
    }

    const bool allowed = http_proxy_detail::host_allowed(cfg.target_hosts, url.host);
    const std::string ua = header_of(req, "user-agent");

    // 请求体读取：chunked / Content-Length
    std::string body = raw.substr(head_end);
    std::size_t body_len = 0;
    const std::string te = lower_copy(header_of(req, "transfer-encoding"));
    const std::string cl = header_of(req, "content-length");
    if (te.find("chunked") != std::string::npos) {
        if (!read_chunked_body(client, body, body_len)) return;
    } else if (!cl.empty()) {
        try {
            body_len = static_cast<std::size_t>(std::strtoull(cl.c_str(), nullptr, 10));
        } catch (...) {
            body_len = 0;
        }
        if (body_len > 0 && !read_content_length_body(client, body, body_len)) return;
    } else {
        body.clear();
    }

    // 组装上游请求：绝对 URL → origin-form，强制 Connection: close
    std::string upstream;
    upstream += method + " " + (url.path.empty() ? "/" : url.path) + " " +
                (req.version.empty() ? "HTTP/1.1" : req.version) + "\r\n";
    for (const auto& kv : req.headers) {
        if (kv.first == "proxy-connection" || kv.first == "connection" ||
            kv.first == "proxy-authorization") {
            continue;
        }
        upstream += kv.first + ": " + kv.second + "\r\n";
    }
    upstream += "Connection: close\r\n\r\n";

    // 操作员身份：请求体读完后即可解析（登录请求用 username，后续请求用 Cookie/头）
    const std::string oper_id = extract_operator(req, body);

    Sock target = connect_target(url.host, url.port == 0 ? 80 : url.port, kConnectTimeoutMs);
    if (target == kInvalidSock) {
        static const char kFail[] = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        send_all(client, kFail, sizeof(kFail) - 1);
        emit_event(method, url.host, url.port, url.path, ua, 502, body_len, "", allowed, oper_id);
        return;
    }

    bool sent = send_all(target, upstream.data(), upstream.size());
    if (sent && !body.empty()) {
        sent = send_all(target, body.data(), body.size());
    }
    if (!sent) {
        close_socket(target);
        static const char kFail[] = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        send_all(client, kFail, sizeof(kFail) - 1);
        emit_event(method, url.host, url.port, url.path, ua, 502, body_len, "", allowed, oper_id);
        return;
    }

    std::string resp;
    std::size_t resp_end = 0;
    int status = 0;
    if (!recv_until(target, resp, "\r\n\r\n", kMaxHeadBytes, resp_end)) {
        close_socket(target);
        static const char kTimeout[] = "HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        send_all(client, kTimeout, sizeof(kTimeout) - 1);
        emit_event(method, url.host, url.port, url.path, ua, 504, body_len, "", allowed, oper_id);
        return;
    }

    status = parse_status_code(resp);
    std::string snippet;
    if (cfg.capture_body && allowed && !body.empty()) {
        snippet = sanitize_snippet(body, cfg.max_body_bytes);
    }
    emit_event(method, url.host, url.port, url.path, ua, status, body_len, snippet, allowed, oper_id);

    send_all(client, resp.data(), resp.size());
    relay_downstream(target, client);
    close_socket(target);
}

void HttpProxyEngine::Impl::relay_bidirectional(Sock a, Sock b) {
    char buf[8192];
    while (running.load()) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(a, &fds);
        FD_SET(b, &fds);
        timeval tv{};
        tv.tv_sec  = 0;
        tv.tv_usec = 200 * 1000;
#ifdef AF_PLATFORM_WINDOWS
        int n = ::select(0, &fds, nullptr, nullptr, &tv);
#else
        int n = ::select(static_cast<int>(std::max(a, b)) + 1, &fds, nullptr, nullptr, &tv);
#endif
        if (n <= 0) continue;

        if (FD_ISSET(a, &fds)) {
            int r = ::recv(a, buf, sizeof(buf), 0);
            if (r <= 0) return;
            if (!send_all(b, buf, static_cast<std::size_t>(r))) return;
        }
        if (FD_ISSET(b, &fds)) {
            int r = ::recv(b, buf, sizeof(buf), 0);
            if (r <= 0) return;
            if (!send_all(a, buf, static_cast<std::size_t>(r))) return;
        }
    }
}

void HttpProxyEngine::Impl::relay_downstream(Sock from, Sock to) {
    char buf[8192];
    while (running.load()) {
        if (!wait_socket(from, false, kIoTimeoutMs)) return;
        int n = ::recv(from, buf, sizeof(buf), 0);
        if (n <= 0) return;
        if (!send_all(to, buf, static_cast<std::size_t>(n))) return;
    }
}

void HttpProxyEngine::Impl::emit_event(const std::string& method, const std::string& host,
                                       u16 port, const std::string& uri,
                                       const std::string& user_agent, int status_code,
                                       std::size_t req_body_len, const std::string& body_snippet,
                                       bool allowed, const std::string& oper_id) {
    if (!allowed || !cb) return;

    AuditEvent ev;
    ev.timestamp = SysClock::now();
    ev.ts_micros = static_cast<u64>(std::chrono::duration_cast<std::chrono::microseconds>(
                       ev.timestamp.time_since_epoch()).count());
    ev.category  = EventCategory::Network;
    ev.action    = http_proxy_detail::action_for_method(method);
    ev.outcome   = (status_code >= 200 && status_code < 400) ? EventOutcome::Success
                                                             : EventOutcome::Failure;
    ev.severity  = Severity::Info;

    const std::string path = uri.empty() ? "/" : uri;
    ev.target.kind     = "http";
    ev.target.address  = host;
    ev.target.port     = port;
    ev.target.protocol = "tcp";
    ev.target.path     = path;

    std::string authority = host;
    if (port != 0 && port != 80) authority += ":" + std::to_string(port);
    ev.message = method + " " + authority + path + " status=" + std::to_string(status_code) +
                 " req_len=" + std::to_string(req_body_len);
    ev.command = method + " " + authority + path;

    ev.attrs[logmeta::attr::kSource]        = logmeta::collector::kHttpProxy;
    ev.attrs[logmeta::attr::kHttpMethod]    = method;
    ev.attrs[logmeta::attr::kHttpHost]      = host;
    ev.attrs[logmeta::attr::kHttpUri]       = path;
    ev.attrs[logmeta::attr::kHttpUserAgent] = user_agent;
    ev.attrs[logmeta::attr::kHttpStatusCode] = std::to_string(status_code);
    ev.attrs[logmeta::attr::kHttpReqBodyLen] = std::to_string(req_body_len);
    if (!body_snippet.empty()) {
        ev.attrs[logmeta::attr::kHttpReqBody] = body_snippet;
    }
    // 操作员身份：从本次请求解析出的真实身份。
    // 这里显式写入后，Enricher 的 "缺失才补配置值" 逻辑不会覆盖它，
    // 因此同一台机器上不同管理员的操作能被区分开（跨操作员合谋检测的前提）。
    if (!oper_id.empty()) {
        ev.attrs[logmeta::attr::kOperatorId]   = oper_id;
        ev.attrs[logmeta::attr::kOperatorName] = oper_id;
    }
    logmeta::tag_collector(ev, logmeta::collector::kHttpProxy);

    cb(ev);
}

std::string HttpProxyEngine::Impl::extract_operator(const RequestHead& req,
                                                    const std::string& body) const {
    // 1. 显式身份头：脚本、网关或演示工具直接声明操作员
    if (!cfg.identity_header.empty()) {
        std::string v = header_of(req, lower_copy(cfg.identity_header));
        if (!v.empty()) return v;
    }
    // 2. 身份 Cookie：业务系统登录后下发，代表"当前会话是谁"
    if (!cfg.identity_cookie.empty()) {
        std::string v = cookie_of(req, cfg.identity_cookie);
        if (!v.empty()) return v;
    }
    // 3. Authorization: Bearer <token>：从登录令牌里解出 username
    if (cfg.identity_from_bearer) {
        std::string v = username_from_bearer(header_of(req, "authorization"));
        if (!v.empty()) return v;
    }
    // 4. 请求体 username：登录动作本身
    if (cfg.identity_from_body && !body.empty()) {
        std::string v = json_body_string(body, "username");
        if (v.empty()) v = json_body_string(body, "operator");
        if (!v.empty()) return v;
    }
    // 5. 无法判定：返回空，由 Enricher 回退到客户端配置的 operator.id
    return {};
}

// =========================================================================
// HttpProxyEngine
// =========================================================================
HttpProxyEngine::HttpProxyEngine(HttpProxyConfig cfg, EventCallback cb)
    : impl_(std::make_unique<Impl>(std::move(cfg), std::move(cb))) {}

HttpProxyEngine::~HttpProxyEngine() = default;

Result<void> HttpProxyEngine::start() { return impl_->start(); }
void         HttpProxyEngine::stop()  { impl_->stop(); }
bool         HttpProxyEngine::is_running() const { return impl_->running.load(); }
u16          HttpProxyEngine::bound_port() const { return impl_->bound_port; }

// =========================================================================
// HttpProxyCollector
// =========================================================================
HttpProxyCollector::HttpProxyCollector(HttpProxyConfig cfg) : cfg_(std::move(cfg)) {}

HttpProxyCollector::~HttpProxyCollector() { stop(); }

Result<void> HttpProxyCollector::start(Agent& agent) {
    if (engine_) return Result<void>::ok();
    Agent* agent_ptr = &agent;
    engine_ = std::make_unique<HttpProxyEngine>(cfg_, [agent_ptr](const AuditEvent& ev) {
        AuditEvent copy = ev;
        agent_ptr->submit(copy);
    });
    return engine_->start();
}

void HttpProxyCollector::stop() {
    if (engine_) {
        engine_->stop();
        engine_.reset();
    }
}

std::string HttpProxyCollector::name() const { return logmeta::collector::kHttpProxy; }

EventCategory HttpProxyCollector::category() const { return EventCategory::Network; }

bool HttpProxyCollector::is_running() const { return engine_ && engine_->is_running(); }

u16 HttpProxyCollector::bound_port() const { return engine_ ? engine_->bound_port() : 0; }

}  // namespace af
