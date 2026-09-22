#pragma once
// AuditForwarder - Agent 到中心管理端的主动上报与远控命令轮询客户端。

#include "auditforwarder/chain.h"
#include "auditforwarder/types.h"

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace af {

class Agent;

struct RemoteClientConfig {
    bool enabled { true };
    std::vector<std::string> server_urls;
    std::string auth_token;
    std::string host_id;
    std::string data_dir;

    int heartbeat_interval_sec { 30 };
    int command_poll_interval_sec { 10 };
    int audit_summary_interval_sec { 30 };
    int max_retry_backoff_sec { 300 };

    bool production_mode { false };
    bool require_tls { false };
    bool verify_tls { true };
    bool crl_check { false };
    std::string ca_cert;
    std::string client_cert;
    std::string client_key;
    std::string enrollment_key;
    std::vector<std::string> allowed_commands {
        "collect_status", "echo",
        "set_collector",   // 单个采集器开关，payload: {"name":"file_win","enabled":true}
        "set_collectors",  // 批量采集器开关，payload: [{"name":"...","enabled":...}]
        "load_rules",      // 热加载检测规则，payload 为规则 JSON 文本
    };
};

class RemoteAgentClient {
public:
    explicit RemoteAgentClient(RemoteClientConfig cfg);
    ~RemoteAgentClient();

    Result<void> start(Agent& agent);
    void stop();
    bool is_running() const { return running_.load(); }

    void enqueue_batch_summary(const chain::EventBatch& batch);

private:
    struct HttpResponse {
        bool ok { false };
        int status { 0 };
        std::string body;
        std::string error;
    };

    void worker_loop();
    void send_heartbeat();
    // high_only=true 时只发送高优先级队列（提权操作紧急通道，失败不降级）
    void send_audit_summaries(bool high_only = false);
    void poll_commands();
    void send_pending_results();

    std::string build_heartbeat_json();
    std::string build_metrics_json();
    std::string build_batch_summary_json(const chain::EventBatch& batch);
    std::string execute_command(const std::string& command_id,
                                const std::string& command_type,
                                const std::string& payload);

    HttpResponse http_request(const std::string& method,
                              const std::string& url,
                              const std::string& body,
                              const std::string& content_type);
    std::string endpoint(const std::string& base, const std::string& path) const;
    bool command_allowed(const std::string& command_type) const;

    RemoteClientConfig cfg_;
    Agent* agent_ { nullptr };
    std::atomic<bool> running_ { false };
    std::atomic<bool> stopping_ { false };
    std::thread worker_;
    std::mutex mtx_;
    std::condition_variable cv_;
    std::vector<chain::EventBatch> audit_queue_;       // 普通优先级
    std::vector<chain::EventBatch> hi_audit_queue_;    // 高优先级（提权操作），先于 audit_queue_ 发送
    std::vector<std::string> pending_results_;
    std::set<std::string> executed_commands_;
};

}  // namespace af
