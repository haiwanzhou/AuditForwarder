#pragma once
// AuditForwarder - 管理服务器：最小化的 HTTP/HTTPS 管理接口，
// 用于状态查询、配置重载、日志查询和远程升级。

#include "auditforwarder/agent.h"
#include <atomic>
#include <map>
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
    std::string data_dir;
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
                      std::string& content_type, int& status);

    ManagerConfig       cfg_;
    std::atomic<bool>   running_ { false };
    std::thread         thr_;
    Agent*              agent_  { nullptr };
    int                 listen_fd_ { -1 };
    void*               tls_ctx_ { nullptr };
};

}  // namespace af
