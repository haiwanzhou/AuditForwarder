#pragma once
// AuditForwarder - 管理服务器：最小化的 HTTP/HTTPS 管理接口，
// 用于状态查询、配置重载、日志查询和远程升级。

#include "auditforwarder/agent.h"
#include <atomic>
#include <map>
#include <mutex>
#include <string>
#include <thread>

namespace af {

struct ManagerConfig {
    std::string listen       { "127.0.0.1:8443" };
    std::string auth_token;
    std::string tls_cert;
    std::string tls_key;
    std::string tls_ca_cert;
    bool        use_tls      { false };
    bool        require_client_cert { false };
    bool        tls_crl_check { false };
    std::string enrollment_key;
    std::size_t max_host_count { 1000 };
    u64         status_timeout_seconds { 30 };   // 心跳超时判定下线（≤该值视为在线）
    std::string data_dir;
    std::string login_username { "admin" };
    std::string login_password_sha256;
};

class SimpleHttpManager : public ManagerServer {
public:
    explicit SimpleHttpManager(ManagerConfig cfg);
    ~SimpleHttpManager() override;

    Result<void> start(Agent& agent) override;
    void         stop() override;
    std::string  endpoint() const override { return cfg_.listen; }

private:
    void accept_loop();
    void handle_client(int fd, void* tls = nullptr);
    std::string route(const std::string& method, const std::string& path,
                      const std::string& query, const std::string& body,
                      std::string& content_type, int& status,
                      const std::string& client_ip = {});

    bool is_session_token_valid(const std::string& token);
    std::string create_session_token(const std::string& username, const std::string& client_ip);

    ManagerConfig       cfg_;
    std::atomic<bool>   running_ { false };
    std::thread         thr_;
    std::thread         monitor_thr_;        // 主动扫描主机在线/离线状态
    std::atomic<bool>   monitor_running_ { false };
    Agent*              agent_  { nullptr };
    int                 listen_fd_ { -1 };
    void*               tls_ctx_ { nullptr };
    std::mutex          auth_mutex_;
    std::map<std::string, std::pair<int, std::uint64_t>> login_failures_;
    std::map<std::string, std::pair<std::string, std::uint64_t>> session_tokens_;
};

}  // namespace af
