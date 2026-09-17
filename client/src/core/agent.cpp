#include "auditforwarder/agent.h"

#include "auditforwarder/chain.h"
#include "auditforwarder/config.h"
#include "auditforwarder/fs.h"
#include "auditforwarder/logger.h"
#include "auditforwarder/manager.h"
#include "auditforwarder/processor.h"
#include "auditforwarder/process.h"
#include "auditforwarder/log_meta.h"
#include "auditforwarder/remote_client.h"
#include "auditforwarder/self_protect.h"
#include "auditforwarder/transport.h"
#include "auditforwarder/detector.h"
#ifdef AF_PLATFORM_LINUX
#  include "auditforwarder/platform_linux.h"
#endif
#ifdef AF_PLATFORM_WINDOWS
#  include "auditforwarder/platform_windows.h"
#endif

#include <chrono>
#include <csignal>
#include <fstream>
#include <sstream>

#ifdef AF_PLATFORM_WINDOWS
#  include <windows.h>
#endif

namespace af {

// 全局代理指针，用于信号处理
namespace {
Agent* g_agent = nullptr;
void on_signal(int sig) {
    if (g_agent) g_agent->stop();
    (void)sig;
}
}  // namespace

Agent::Agent() = default;
Agent::~Agent() { stop(); }

Result<void> Agent::init(const AgentConfig& cfg) {
    cfg_ = cfg;

    // 配置日志器
    LogConfig lcfg;
    lcfg.level       = cfg_.log_level;
    lcfg.file_path   = cfg_.log_file;
    lcfg.max_bytes   = cfg_.log_max_bytes;
    lcfg.targets     = static_cast<u8>(LogTarget::Console);
    if (!cfg_.log_file.empty()) {
        lcfg.targets = static_cast<u8>(static_cast<LogTarget>(lcfg.targets) | LogTarget::File);
    }
#ifdef AF_PLATFORM_UNIX
    lcfg.targets = static_cast<u8>(static_cast<LogTarget>(lcfg.targets) | LogTarget::Syslog);
#endif
    Logger::instance().configure(lcfg);

    // 确保数据目录存在
    if (!cfg_.data_dir.empty()) {
        auto r = fs::create_directories(cfg_.data_dir);
        if (r.is_err()) return r;
    }

    // Load config file if present
    if (!cfg_.config_path.empty() && fs::exists(cfg_.config_path)) {
        auto r = Config::instance().load_from_file(cfg_.config_path);
        if (r.is_err()) AF_LOG_WARN("config: load failed: " << r.error().message());
        else {
            auto& c = Config::instance();
            cfg_.agent_id = c.get_string("agent.id", cfg_.agent_id);
            cfg_.data_dir = c.get_string("agent.data_dir", cfg_.data_dir);
            cfg_.config_path = c.get_string("agent.config_path", cfg_.config_path);
            cfg_.log_level = severity_from_string(c.get_string("log.level", to_string(cfg_.log_level)));
            cfg_.log_file = c.get_string("log.file", cfg_.log_file);
            cfg_.log_max_bytes = static_cast<std::size_t>(c.get_int("log.max_bytes", static_cast<long long>(cfg_.log_max_bytes)));
            cfg_.manager_enabled  = c.get_bool("manager.enabled", cfg_.manager_enabled);
            cfg_.manager_listen   = c.get_string("manager.listen", cfg_.manager_listen);
            cfg_.manager_token    = c.get_string("manager.auth_token", cfg_.manager_token);
            cfg_.manager_use_tls  = c.get_bool("manager.use_tls", cfg_.manager_use_tls);
            cfg_.manager_tls_cert = c.get_string("manager.tls_cert", cfg_.manager_tls_cert);
            cfg_.manager_tls_key  = c.get_string("manager.tls_key", cfg_.manager_tls_key);
            cfg_.manager_tls_ca_cert = c.get_string("manager.tls_ca_cert", cfg_.manager_tls_ca_cert);
            cfg_.manager_require_client_cert = c.get_bool("manager.require_client_cert", cfg_.manager_require_client_cert);
            cfg_.manager_tls_crl_check = c.get_bool("manager.tls_crl_check", cfg_.manager_tls_crl_check);
            cfg_.manager_enrollment_key = c.get_string("manager.enrollment_key", cfg_.manager_enrollment_key);
            cfg_.manager_max_host_count = static_cast<std::size_t>(c.get_int("manager.max_host_count", static_cast<long long>(cfg_.manager_max_host_count)));
            cfg_.manager_status_timeout_seconds = static_cast<u64>(c.get_int("manager.status_timeout_seconds", static_cast<long long>(cfg_.manager_status_timeout_seconds)));
            cfg_.manager_login_username = c.get_string("manager.login_username", cfg_.manager_login_username);
            cfg_.manager_login_password_sha256 = c.get_string("manager.login_password_sha256", cfg_.manager_login_password_sha256);
            cfg_.chain_batch_size = static_cast<std::size_t>(c.get_int("chain.batch_size", static_cast<long long>(cfg_.chain_batch_size)));
            cfg_.chain_signing_key = c.get_string("chain.signing_key", cfg_.chain_signing_key);
            cfg_.chain_hmac_key = c.get_string("chain.hmac_key", cfg_.chain_hmac_key);
            cfg_.transport_mode = c.get_string("transport.mode", cfg_.transport_mode);
            cfg_.transport_interval_sec = static_cast<int>(c.get_int("transport.interval_sec", cfg_.transport_interval_sec));
            cfg_.transport_max_backoff_sec = static_cast<int>(c.get_int("transport.max_backoff_sec", cfg_.transport_max_backoff_sec));
            cfg_.transport_compress = c.get_bool("transport.compress", cfg_.transport_compress);
            cfg_.transport_encrypt = c.get_bool("transport.encrypt_payload", cfg_.transport_encrypt);
            cfg_.transport_auth_token = c.get_string("transport.auth_token", cfg_.transport_auth_token);
            cfg_.transport_verify_tls = c.get_bool("transport.verify_tls", cfg_.transport_verify_tls);
            cfg_.ca_cert = c.get_string("transport.ca_cert", cfg_.ca_cert);
            cfg_.client_cert = c.get_string("transport.client_cert", cfg_.client_cert);
            cfg_.client_key = c.get_string("transport.client_key", cfg_.client_key);
            const auto& servers = c.root().at("transport").at("servers").as_list();
            if (!servers.empty()) {
                cfg_.server_urls.clear();
                for (const auto& s : servers) {
                    auto url = s.as_string();
                    if (!url.empty()) cfg_.server_urls.push_back(url);
                }
            }
            cfg_.remote_enabled = c.get_bool("remote.enabled", cfg_.remote_enabled);
            cfg_.remote_host_id = c.get_string("remote.host_id", cfg_.remote_host_id);
            const auto& remote_servers = c.root().at("remote").at("servers").as_list();
            if (!remote_servers.empty()) {
                cfg_.remote_server_urls.clear();
                for (const auto& s : remote_servers) {
                    auto url = s.as_string();
                    if (!url.empty()) cfg_.remote_server_urls.push_back(url);
                }
            }
            cfg_.remote_heartbeat_interval_sec = static_cast<int>(c.get_int("remote.heartbeat_interval_sec", cfg_.remote_heartbeat_interval_sec));
            cfg_.remote_command_poll_interval_sec = static_cast<int>(c.get_int("remote.command_poll_interval_sec", cfg_.remote_command_poll_interval_sec));
            cfg_.remote_audit_summary_interval_sec = static_cast<int>(c.get_int("remote.audit_summary_interval_sec", cfg_.remote_audit_summary_interval_sec));
            cfg_.remote_production_mode = c.get_bool("remote.production_mode", cfg_.remote_production_mode);
            cfg_.remote_require_tls = c.get_bool("remote.require_tls", cfg_.remote_require_tls);
            cfg_.remote_crl_check = c.get_bool("remote.crl_check", cfg_.remote_crl_check);
            cfg_.remote_enrollment_key = c.get_string("remote.enrollment_key", cfg_.remote_enrollment_key);
            cfg_.self_protect_enabled = c.get_bool("self_protect.enabled", cfg_.self_protect_enabled);
            cfg_.rules_path = c.get_string("detector.rules_path", cfg_.rules_path);
            cfg_.collectors_enabled = c.get_bool("collectors.enabled", cfg_.collectors_enabled);
            cfg_.privilege_detect_enabled = c.get_bool("privilege_detect.enabled", cfg_.privilege_detect_enabled);
            cfg_.test_injection_enabled = c.get_bool("test_injection.enabled", cfg_.test_injection_enabled);
            cfg_.test_injection_interval_ms = static_cast<int>(
                c.get_int("test_injection.interval_ms", cfg_.test_injection_interval_ms));
            const auto& allowed = c.root().at("remote").at("allowed_commands").as_list();
            if (!allowed.empty()) {
                cfg_.remote_allowed_commands.clear();
                for (const auto& cmd : allowed) {
                    auto value = cmd.as_string();
                    if (!value.empty()) cfg_.remote_allowed_commands.push_back(value);
                }
            }
        }
    }

    // 配置文件可能覆盖日志路径、级别和数据目录，读取后需要重新应用一次。
    lcfg.level       = cfg_.log_level;
    lcfg.file_path   = cfg_.log_file;
    lcfg.max_bytes   = cfg_.log_max_bytes;
    lcfg.targets     = static_cast<u8>(LogTarget::Console);
    if (!cfg_.log_file.empty()) {
        lcfg.targets = static_cast<u8>(static_cast<LogTarget>(lcfg.targets) | LogTarget::File);
    }
#ifdef AF_PLATFORM_UNIX
    lcfg.targets = static_cast<u8>(static_cast<LogTarget>(lcfg.targets) | LogTarget::Syslog);
#endif
    Logger::instance().configure(lcfg);

    if (!cfg_.data_dir.empty()) {
        auto r = fs::create_directories(cfg_.data_dir);
        if (r.is_err()) return r;
    }

    // 初始化链
    chain::ChainConfig cc;
    cc.data_dir      = cfg_.data_dir;
    cc.batch_size    = cfg_.chain_batch_size;
    cc.auto_persist  = true;
    chain_ = std::make_unique<chain::Chain>(cc);
    chain_->start();
    if (!cfg_.chain_signing_key.empty()) {
        auto kp = crypto::KeyPair::load_pem(cfg_.chain_signing_key);
        if (kp.is_ok()) chain_->set_signer(std::move(kp).value());
    } else if (!cfg_.chain_hmac_key.empty()) {
        chain_->set_hmac_key(cfg_.chain_hmac_key);
    }
    // Register batch callback to forward to the transport once it is set.
    chain_->on_batch([this](const chain::EventBatch& b) {
        if (transport_) transport_->send_batch(b);
        if (remote_client_) remote_client_->enqueue_batch_summary(b);
    });

    // 构建默认处理器链
    processors_.emplace_back(std::make_unique<processor::Enricher>(proc::hostname(), cfg_.agent_id));
    processors_.emplace_back(std::make_unique<processor::PIIMasker>());
    processors_.emplace_back(std::make_unique<processor::Deduper>());

    // 检测器
    auto det = std::make_unique<detector::RuleEngine>();
    if (!cfg_.rules_path.empty() && fs::exists(cfg_.rules_path)) {
        auto r = det->load_rules(cfg_.rules_path);
        if (r.is_err()) AF_LOG_WARN("detector: " << r.error().message());
    } else {
        // Add a few sensible defaults
        detector::Rule r1;
        r1.id = "R-PROC-001";
        r1.name = "Sensitive file read";
        r1.severity = Severity::Warning;
        r1.categories = {"file"};
        r1.actions = {"read"};
        r1.path_match = {"/etc/shadow", "/etc/passwd", "/etc/sudoers", "C:\\\\Windows\\\\System32\\\\config\\\\SAM"};
        r1.responses = {"alert"};
        det->add_rule(r1);

        detector::Rule r2;
        r2.id = "R-NET-001";
        r2.name = "Outbound to suspicious TLD";
        r2.severity = Severity::Warning;
        r2.categories = {"network"};
        r2.actions = {"connect"};
        r2.path_match = {".*\\.(ru|cn|tk|xyz|top)$"};
        r2.responses = {"alert"};
        det->add_rule(r2);

        detector::Rule r3;
        r3.id = "R-CMD-001";
        r3.name = "Potential reverse shell";
        r3.severity = Severity::Critical;
        r3.categories = {"command"};
        r3.cmd_match = {"bash\\s+-i.*>&?\\s*/dev/tcp/", "nc\\s+-e\\s+/bin/bash", "nc\\s+-e\\s+/bin/sh", "python.*-c.*socket\\.socket"};
        r3.responses = {"alert", "kill"};
        det->add_rule(r3);
    }
    detector_ = std::move(det);

    // 传输模块
    TransportConfig tc;
    tc.server_urls     = cfg_.server_urls;
    tc.mode            = cfg_.transport_mode;
    tc.interval_sec    = cfg_.transport_interval_sec;
    tc.max_backoff_sec = cfg_.transport_max_backoff_sec;
    tc.compress        = cfg_.transport_compress;
    tc.encrypt_payload = cfg_.transport_encrypt;
    tc.client_cert     = cfg_.client_cert;
    tc.client_key      = cfg_.client_key;
    tc.ca_cert         = cfg_.ca_cert;
    tc.auth_token      = cfg_.transport_auth_token.empty() ? cfg_.manager_token : cfg_.transport_auth_token;
    tc.verify_tls      = cfg_.transport_verify_tls;
    tc.agent_id        = cfg_.agent_id;
    tc.data_dir        = cfg_.data_dir;
    transport_ = std::make_unique<HttpsTransport>(tc);

    RemoteClientConfig rc;
    rc.enabled = cfg_.remote_enabled;
    rc.server_urls = cfg_.remote_server_urls.empty() ? cfg_.server_urls : cfg_.remote_server_urls;
    rc.auth_token = tc.auth_token;
    rc.host_id = cfg_.remote_host_id.empty() ? cfg_.agent_id : cfg_.remote_host_id;
    rc.data_dir = cfg_.data_dir;
    rc.heartbeat_interval_sec = cfg_.remote_heartbeat_interval_sec;
    rc.command_poll_interval_sec = cfg_.remote_command_poll_interval_sec;
    rc.audit_summary_interval_sec = cfg_.remote_audit_summary_interval_sec;
    rc.production_mode = cfg_.remote_production_mode;
    rc.require_tls = cfg_.remote_require_tls;
    rc.verify_tls = cfg_.transport_verify_tls;
    rc.crl_check = cfg_.remote_crl_check;
    rc.ca_cert = cfg_.ca_cert;
    rc.client_cert = cfg_.client_cert;
    rc.client_key = cfg_.client_key;
    rc.enrollment_key = cfg_.remote_enrollment_key;
    rc.allowed_commands = cfg_.remote_allowed_commands;
    remote_client_ = std::make_unique<RemoteAgentClient>(rc);

    // Self protect
    if (cfg_.self_protect_enabled) {
        SelfProtectConfig sp;
        sp.install_path     = fs::executable_path();
        sp.data_dir         = cfg_.data_dir;
        sp.config_path      = cfg_.config_path;
        sp.check_interval_sec = 5;
        sp.lock_files       = true;
        sp.watchdog         = true;
        self_protect_ = std::make_unique<DefaultSelfProtect>(sp);
    }

    // Manager
    if (cfg_.manager_enabled) {
        ManagerConfig mc;
        mc.listen     = cfg_.manager_listen;
        mc.auth_token = cfg_.manager_token;
        mc.use_tls    = cfg_.manager_use_tls;
        mc.tls_cert   = cfg_.manager_tls_cert;
        mc.tls_key    = cfg_.manager_tls_key;
        mc.tls_ca_cert = cfg_.manager_tls_ca_cert;
        mc.require_client_cert = cfg_.manager_require_client_cert;
        mc.tls_crl_check = cfg_.manager_tls_crl_check;
        mc.enrollment_key = cfg_.manager_enrollment_key;
        mc.max_host_count = cfg_.manager_max_host_count;
        mc.status_timeout_seconds = cfg_.manager_status_timeout_seconds;
        mc.login_username = cfg_.manager_login_username;
        mc.login_password_sha256 = cfg_.manager_login_password_sha256;
        mc.data_dir   = cfg_.data_dir;
        manager_ = std::make_unique<SimpleHttpManager>(mc);
    }

    pool_.start(std::max<std::size_t>(4u, std::thread::hardware_concurrency()));
    AF_LOG_INFO("agent: init complete, id=" << cfg_.agent_id);
    return Result<void>::ok();
}

Result<void> Agent::start() {
    if (running_.exchange(true)) return Result<void>::ok();
    start_tp_ = Clock::now();

    // 构建平台特定的采集器
    std::vector<std::unique_ptr<Collector>> created;
    if (cfg_.collectors_enabled && collectors_.empty()) {
#ifdef AF_PLATFORM_LINUX
        create_linux_collectors(created, *this);
#elif defined(AF_PLATFORM_WINDOWS)
        create_windows_collectors(created, *this);
#endif
        collectors_ = std::move(created);
    }
    if (cfg_.collectors_enabled) {
        for (auto& c : collectors_) {
            auto r = c->start(*this);
            if (r.is_err()) AF_LOG_ERROR("collector: " << c->name() << " start failed: " << r.error().message());
            else AF_LOG_INFO("collector: " << c->name() << " started");
        }
    } else {
        AF_LOG_INFO("collectors: disabled by configuration");
    }

    if (self_protect_) {
        auto r = self_protect_->start(*this);
        if (r.is_err()) AF_LOG_ERROR("self_protect: " << r.error().message());
    }
    if (manager_) {
        auto r = manager_->start(*this);
        if (r.is_err()) AF_LOG_ERROR("manager: " << r.error().message());
    }
    if (detector_) detector_->start(*this);
    if (transport_ && !cfg_.server_urls.empty()) {
        transport_->start(*this);
    } else {
        AF_LOG_INFO("transport: disabled, no server configured");
    }
    const bool has_remote_server = !cfg_.remote_server_urls.empty() || !cfg_.server_urls.empty();
    if (remote_client_ && cfg_.remote_enabled && has_remote_server) {
        auto r = remote_client_->start(*this);
        if (r.is_err()) AF_LOG_ERROR("remote_client: " << r.error().message());
    } else {
        AF_LOG_INFO("remote_client: disabled, no server configured");
    }

    if (cfg_.test_injection_enabled) {
        injecting_.store(true);
        injector_ = std::thread([this] { injector_loop(); });
        AF_LOG_WARN("test_injection: ENABLED, interval_ms=" << cfg_.test_injection_interval_ms
                    << " — synthetic etw_win/privileged events will be emitted");
    }

    install_signal_handlers();
    g_agent = this;

    AF_LOG_INFO("agent: started, collectors=" << collectors_.size());
    return Result<void>::ok();
}

void Agent::stop() {
    if (!running_.exchange(false)) return;
    AF_LOG_INFO("agent: stopping");
    if (injecting_.exchange(false) && injector_.joinable()) injector_.join();
    if (remote_client_) remote_client_->stop();
    if (transport_) transport_->stop();
    if (manager_)   manager_->stop();
    if (detector_)  detector_->stop();
    for (auto& c : collectors_) c->stop();
    if (self_protect_) self_protect_->stop();
    if (chain_) chain_->stop();
    pool_.shutdown(true);
    Logger::instance().flush();
}

void Agent::submit(AuditEvent& ev) {
    if (ev.host.empty())     ev.host     = proc::hostname();
    if (ev.agent_id.empty()) ev.agent_id = cfg_.agent_id;
    if (ev.actor.pid == 0)   ev.actor.pid = proc::current_pid();
    if (ev.actor.user.empty()) ev.actor.user = proc::current_username();

    // 运行处理器管道
    for (auto& p : processors_) {
        if (!p->process(ev)) {
            std::lock_guard<std::mutex> lk(stats_mtx_);
            stats_.events_dropped++;
            return;
        }
    }

    // 检测
    if (detector_ && !detector_->inspect(ev)) {
        std::lock_guard<std::mutex> lk(stats_mtx_);
        stats_.events_dropped++;
        return;
    }
    if (!ev.rule_id.empty()) {
        std::lock_guard<std::mutex> lk(stats_mtx_);
        stats_.alerts++;
    }

    // 添加到链
    if (chain_) chain_->submit(ev);
    {
        std::lock_guard<std::mutex> lk(stats_mtx_);
        stats_.events_collected++;
    }

    // 转发到传输模块
    if (transport_ && !cfg_.server_urls.empty()) {
        // 批量转发由 chain.flush() 消费者完成
    }
}

void Agent::record_uploaded(u64 event_count, u64 bytes) {
    std::lock_guard<std::mutex> lk(stats_mtx_);
    stats_.events_uploaded += event_count;
    stats_.bytes_uploaded  += bytes;
}

std::string Agent::privilege_level_for_pid(u32 pid) {
    if (!cfg_.privilege_detect_enabled || pid == 0) return "";
    constexpr auto kTtl = std::chrono::seconds(5);
    auto now = Clock::now();
    {
        std::lock_guard<std::mutex> lk(priv_cache_mtx_);
        auto it = priv_cache_.find(pid);
        if (it != priv_cache_.end() && now - it->second.second < kTtl) {
            return it->second.first;
        }
    }
    std::string level = proc::privilege_level(pid);
    {
        std::lock_guard<std::mutex> lk(priv_cache_mtx_);
        priv_cache_[pid] = {level, now};
        // 简单兜底，防止缓存无限增长
        if (priv_cache_.size() > 4096) priv_cache_.erase(priv_cache_.begin());
    }
    return level;
}

// 测试注入：合成 ① ETW 安全日志富字段事件 ② 高权限进程事件，全部走正常 Agent::submit 链路。
// 所有事件带 injected="1"，生产配置 test_injection.enabled 必须为 false。
void Agent::injector_loop() {
    namespace lm = logmeta;
    u64 seq = 0;
    auto interruptible_sleep = [this](int ms) {
        const int step = 50;
        for (int waited = 0; waited < ms && injecting_.load(); waited += step) {
            std::this_thread::sleep_for(std::chrono::milliseconds(std::min(step, ms - waited)));
        }
    };
    while (injecting_.load()) {
        // ① ETW 4688 富字段事件（含完整 raw_xml，验证服务端宽松过滤保留率）
        {
            AuditEvent ev;
            ev.category = EventCategory::Process;
            ev.action   = EventAction::Spawn;
            ev.severity = Severity::Info;
            ev.actor.user = "INJECTED-PC\\Administrator";
            ev.actor.name = "cmd.exe";
            ev.actor.path = "C:\\Windows\\System32\\cmd.exe";
            ev.message = "etw event_id=4688 user=INJECTED-PC\\Administrator proc=cmd.exe [injected]";
            lm::tag_collector(ev, lm::collector::kEtwWin);
            ev.attrs[lm::attr::kSource]        = lm::source::kEtwSecurity;
            ev.attrs[lm::attr::kEventId]       = "4688";
            ev.attrs[lm::attr::kSubjectUser]   = "Administrator";
            ev.attrs[lm::attr::kSubjectDomain] = "INJECTED-PC";
            ev.attrs[lm::attr::kLogonId]       = "0x3e7";
            ev.attrs[lm::attr::kProcessName]   = "C:\\Windows\\System32\\cmd.exe";
            ev.attrs[lm::attr::kInjected]      = "1";
            // 模拟真实 ETW 渲染 XML（约 1.5KB，验证 lenient 策略不截断）
            std::string xml =
                "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">"
                "<System><Provider Name=\"Microsoft-Windows-Security-Auditing\" Guid=\"{54849625-5478-4994-a5ba-3e3b0328c30d}\"/>"
                "<EventID>4688</EventID><Version>2</Version><Level>0</Level><Task>13312</Task><Opcode>0</Opcode>"
                "<Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime=\"2025-01-01T00:00:00.0000000Z\"/>"
                "<RecordID>" + std::to_string(100000 + seq) + "</RecordID><Correlation/><Execution ProcessID=\"4\" ThreadID=\"88\"/>"
                "<Channel>Security</Channel><Computer>INJECTED-PC</Computer><Security/></System><EventData>"
                "<Data Name=\"SubjectUserSid\">S-1-5-21-0000-500</Data>"
                "<Data Name=\"SubjectUserName\">Administrator</Data>"
                "<Data Name=\"SubjectDomainName\">INJECTED-PC</Data>"
                "<Data Name=\"SubjectLogonId\">0x3e7</Data>"
                "<Data Name=\"NewProcessId\">0x" + std::to_string(seq + 1000) + "</Data>"
                "<Data Name=\"NewProcessName\">C:\\Windows\\System32\\cmd.exe</Data>"
                "<Data Name=\"TokenElevationType\">%%1843</Data>"
                "<Data Name=\"ProcessCommandLine\">cmd.exe /c echo injected-test-" + std::to_string(seq) + "</Data>"
                "<Data Name=\"TargetUserSid\">S-1-0-0</Data><Data Name=\"TargetUserName\">-</Data>"
                "<Data Name=\"TargetDomainName\">-</Data><Data Name=\"TargetLogonId\">0x0</Data>"
                "<Data Name=\"ParentProcessName\">C:\\Windows\\System32\\svchost.exe</Data>"
                "</EventData></Event>";
            ev.attrs[lm::attr::kRawXml] = std::move(xml);
            submit(ev);
        }
        // ② 高权限进程事件（system / elevated 交替，验证优先级通道与延迟）
        {
            AuditEvent ev;
            ev.category = EventCategory::Process;
            ev.action   = EventAction::Spawn;
            ev.severity = Severity::Info;
            ev.actor.pid  = static_cast<u32>(0x4000 + (seq & 0xFFFF));
            ev.actor.name = "inject-priv.exe";
            ev.actor.path = "C:\\Tools\\inject-priv.exe";
            ev.command    = "inject-priv.exe --case " + std::to_string(seq);
            ev.message    = "Spawn pid=" + std::to_string(ev.actor.pid) + " [injected privileged]";
            lm::tag_collector(ev, lm::collector::kProcessWin);
            lm::mark_privileged(ev, (seq % 2 == 0) ? lm::priv::kSystem : lm::priv::kElevated);
            ev.attrs[lm::attr::kInjected] = "1";
            submit(ev);
        }
        ++seq;
        interruptible_sleep(cfg_.test_injection_interval_ms > 0 ? cfg_.test_injection_interval_ms : 1000);
    }
}

void Agent::record_failed(u64 event_count) {
    std::lock_guard<std::mutex> lk(stats_mtx_);
    stats_.events_failed += event_count;
}

AgentStats Agent::stats() const {
    AgentStats s;
    {
        std::lock_guard<std::mutex> lk(stats_mtx_);
        s = stats_;
    }
    s.started_at = start_tp_;
    if (running_.load()) {
        s.uptime_seconds = static_cast<u64>(
            std::chrono::duration_cast<std::chrono::seconds>(Clock::now() - start_tp_).count());
    }
    return s;
}

Result<void> Agent::reload_config() {
    if (cfg_.config_path.empty()) return Result<void>(Error::Code::InvalidArgument, "no config path");
    return Config::instance().load_from_file(cfg_.config_path);
}

void Agent::install_signal_handlers() {
#ifdef AF_PLATFORM_UNIX
    std::signal(SIGINT,  on_signal);
    std::signal(SIGTERM, on_signal);
    std::signal(SIGPIPE, SIG_IGN);
#endif
#ifdef AF_PLATFORM_WINDOWS
    SetConsoleCtrlHandler([](DWORD type) -> BOOL {
        if (g_agent) g_agent->stop();
        return TRUE;
    }, TRUE);
#endif
}

}  // namespace af
