#pragma once
// AuditForwarder - M5-3 本地 HTTP 代理行为采集器。
//
// 操作员把浏览器 / 命令行工具的 HTTP 代理指向本采集器后，采集其对受管系统
// （如自建图书管理系统）的 HTTP 操作。字段对齐 Zeek http.log 子集：
// method / host / uri / user_agent / status_code / request_body_len。
//
// 事件 category=network，action 按 method 推断；operator_id 由 Enricher 注入，
// 因此无需在采集器内重复处理身份。

#include "auditforwarder/agent.h"
#include "auditforwarder/event.h"

#include <cstddef>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace af {

struct HttpProxyConfig {
    bool        enabled { false };            // 配置未开启时默认不启动（仍可被服务端远程开启）
    std::string bind_addr { "127.0.0.1" };    // 仅本机回环，避免代理被外部滥用
    u16         listen_port { 8888 };         // 0 = 由系统分配（测试用）
    std::vector<std::string> target_hosts;    // 受管系统主机列表，空 = 采集全部主机
    bool        capture_body { false };        // 是否留存请求体（下游 PIIMasker 负责脱敏）
    std::size_t max_body_bytes { 1024 };      // 请求体留存上限

    // 操作员身份提取（跨操作员合谋检测的前提）：
    // 事件的操作员默认取客户端配置的 operator.id，一台机器只能对应一个操作员。
    // 开启以下来源后，采集器会从每个请求里解析真实身份，覆盖配置值。
    std::string identity_header { "x-af-operator" };  // 显式身份头（脚本 / 网关注入）
    std::string identity_cookie { "af_operator" };    // 身份 Cookie（业务系统登录后下发）
    bool        identity_from_bearer { true };       // 解 Authorization: Bearer 里的 username
    bool        identity_from_body { true };         // 登录请求体中的 username 兜底
};

namespace http_proxy_detail {

struct UrlParts {
    std::string host;
    u16         port { 0 };
    std::string path;
    bool        ok { false };
};

// 解析代理绝对 URL（http://host[:port]/path?query）。
UrlParts parse_absolute_url(const std::string& url);

// host 是否命中 target_hosts：大小写不敏感，支持 "example.com"、"*.example.com"，
// 配置项允许带 http:// 前缀或端口。targets 为空表示放行全部主机。
bool host_allowed(const std::vector<std::string>& targets, const std::string& host);

// HTTP method → 审计动作：GET/HEAD=read，POST=create，PUT/PATCH=write，DELETE=delete。
EventAction action_for_method(const std::string& method);

}  // namespace http_proxy_detail

// 代理引擎：只负责网络转发与事件构造，通过回调送出事件（与 Agent 解耦，便于单元测试）。
class HttpProxyEngine {
public:
    using EventCallback = std::function<void(const AuditEvent&)>;

    HttpProxyEngine(HttpProxyConfig cfg, EventCallback cb);
    ~HttpProxyEngine();

    Result<void> start();
    void         stop();
    bool         is_running() const;
    u16          bound_port() const;  // listen_port=0 时为系统分配的实际端口

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

class HttpProxyCollector : public Collector {
public:
    explicit HttpProxyCollector(HttpProxyConfig cfg);
    ~HttpProxyCollector() override;

    Result<void> start(Agent& agent) override;
    void         stop() override;
    std::string  name() const override;
    EventCategory category() const override;
    bool         is_running() const override;
    u16          bound_port() const;

private:
    HttpProxyConfig                  cfg_;
    std::unique_ptr<HttpProxyEngine>  engine_;
};

}  // namespace af
