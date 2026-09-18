// AuditForwarder - Linux collectors (combined implementation file).

#include "auditforwarder/agent.h"
#include "auditforwarder/collector_base.h"
#include "auditforwarder/event.h"
#include "auditforwarder/fs.h"
#include "auditforwarder/log_meta.h"
#include "auditforwarder/logger.h"
#include "auditforwarder/process.h"

#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <map>
#include <poll.h>
#include <set>
#include <sstream>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#ifdef AF_HAVE_LIBAUDIT
#  include <libaudit.h>
#endif

namespace af::collector {

// =========================================================================
// InotifySource - 基于 inotify 的文件监控器
// =========================================================================
class InotifySource : public FileWatchSource {
public:
    InotifySource() = default;
    ~InotifySource() override { close(); }

    Result<void> open(const std::vector<std::string>& paths) override {
        close();
        fd_ = ::inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        if (fd_ < 0) return Result<void>(Error::Code::IoError, std::string("inotify_init1: ") + strerror(errno));
        for (const auto& p : paths) add_watch(p);
        return Result<void>::ok();
    }
    void close() override {
        for (auto& kv : wds_) ::inotify_rm_watch(fd_, kv.first);
        wds_.clear();
        if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
    }
    int poll(std::function<bool(const std::string&, const std::string&, u64)> cb) override {
        if (fd_ < 0) return 0;
        pollfd p{fd_, POLLIN, 0};
        if (::poll(&p, 1, 0) <= 0) return 0;
        char buf[16 * 1024];
        int total = 0;
        int n = 0;
        while ((n = static_cast<int>(::read(fd_, buf, sizeof(buf)))) > 0) {
            int i = 0;
            while (i < n) {
                auto* ev = reinterpret_cast<inotify_event*>(buf + i);
                auto it = wds_.find(ev->wd);
                if (it != wds_.end()) {
                    std::string name = ev->len ? ev->name : "";
                    std::string full = it->second + "/" + name;
                    std::string op = describe(ev->mask);
                    if (!op.empty()) {
                        u64 ts = static_cast<u64>(
                            std::chrono::duration_cast<std::chrono::microseconds>(
                                std::chrono::system_clock::now().time_since_epoch()).count());
                        if (!cb(full, op, ts)) return total;
                        ++total;
                    }
                }
                i += static_cast<int>(sizeof(inotify_event)) + ev->len;
            }
        }
        return total;
    }

private:
    void add_watch(const std::string& path) {
        int wd = ::inotify_add_watch(fd_, path.c_str(),
            IN_CREATE | IN_DELETE | IN_MODIFY | IN_MOVED_FROM | IN_MOVED_TO |
            IN_ATTRIB | IN_ACCESS | IN_OPEN | IN_CLOSE_WRITE | IN_CLOSE_NOWRITE);
        if (wd >= 0) wds_[wd] = path;
    }
    static std::string describe(uint32_t mask) {
        if (mask & IN_CREATE)  return "create";
        if (mask & IN_DELETE)  return "delete";
        if (mask & IN_MODIFY)  return "write";
        if (mask & IN_MOVED_FROM) return "rename_from";
        if (mask & IN_MOVED_TO)   return "rename_to";
        if (mask & IN_ATTRIB)  return "chmod";
        if (mask & IN_ACCESS)  return "read";
        if (mask & IN_OPEN)    return "open";
        if (mask & IN_CLOSE_WRITE) return "close_write";
        if (mask & IN_CLOSE_NOWRITE) return "close";
        return {};
    }
    int fd_ { -1 };
    std::map<int, std::string> wds_;
};

std::unique_ptr<FileWatchSource> make_file_watch_source() {
    return std::make_unique<InotifySource>();
}

// =========================================================================
// LinuxFileCollector
// =========================================================================
class LinuxFileCollector : public Collector {
public:
    Result<void> start(Agent& agent) override {
        agent_ = &agent;
        paths_ = {"/etc", "/var/log", "/tmp", "/root", "/home"};
        filter_.exclude({"/proc/*", "/sys/*"});
        src_ = make_file_watch_source();
        auto r = src_->open(paths_);
        if (r.is_err()) return r;
        running_ = true;
        thr_ = std::thread([this] { loop(); });
        return Result<void>::ok();
    }
    void stop() override { running_ = false; if (thr_.joinable()) thr_.join(); }
    std::string  name()   const override { return "file_linux"; }
    EventCategory category() const override { return EventCategory::File; }
    bool         is_running() const override { return running_; }

private:
    void loop() {
        while (running_) {
            src_->poll([this](const std::string& p, const std::string& op, u64 ts) {
                if (!filter_.allows(p)) return true;
                AuditEvent ev;
                ev.category = EventCategory::File;
                ev.action   = op_to_action(op);
                ev.target.path = p;
                ev.target.kind  = "file";
                ev.message = "file " + op + " " + p;
                ev.ts_micros = ts;
                logmeta::tag_collector(ev, logmeta::collector::kFileLinux);
                if (agent_) agent_->submit(ev);
                return true;
            });
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }
    static EventAction op_to_action(const std::string& op) {
        if (op == "create")  return EventAction::Create;
        if (op == "delete")  return EventAction::Delete;
        if (op == "write" || op == "close_write") return EventAction::Write;
        if (op == "rename_from" || op == "rename_to") return EventAction::Rename;
        if (op == "chmod")   return EventAction::Chmod;
        if (op == "read" || op == "open") return EventAction::Read;
        return EventAction::Unknown;
    }
    Agent* agent_ { nullptr };
    std::vector<std::string> paths_;
    PathFilter filter_;
    std::unique_ptr<FileWatchSource> src_;
    std::thread thr_;
    bool running_ { false };
};

// =========================================================================
// LinuxProcessCollector
// =========================================================================
class LinuxProcessCollector : public Collector {
public:
    Result<void> start(Agent& agent) override {
        agent_ = &agent;
        running_ = true;
        last_snapshot_ = snapshot();
        thr_ = std::thread([this] { loop(); });
        return Result<void>::ok();
    }
    void stop() override { running_ = false; if (thr_.joinable()) thr_.join(); }
    std::string  name()   const override { return "process_linux"; }
    EventCategory category() const override { return EventCategory::Process; }
    bool         is_running() const override { return running_; }

private:
    using PidSet = std::set<u32>;

    static PidSet snapshot() {
        PidSet out;
        DIR* d = opendir("/proc");
        if (!d) return out;
        while (auto* e = readdir(d)) {
            if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
            out.insert(static_cast<u32>(std::strtoul(e->d_name, nullptr, 10)));
        }
        closedir(d);
        return out;
    }

    void emit_event(u32 pid, EventAction act) {
        auto info = proc::get_process(pid);
        AuditEvent ev;
        ev.category = EventCategory::Process;
        ev.action   = act;
        ev.actor.pid  = pid;
        if (info.is_ok()) {
            ev.actor.name = info.value().name;
            ev.actor.path = info.value().exe;
            ev.actor.user = info.value().username;
            ev.command    = info.value().cmdline;
        }
        ev.message = to_string(act);
        ev.message += " pid=" + std::to_string(pid);
        logmeta::tag_collector(ev, logmeta::collector::kProcessLinux);
        if (agent_ && act == EventAction::Spawn) {
            auto lvl = agent_->privilege_level_for_pid(pid);
            if (!lvl.empty() && lvl != logmeta::priv::kNone) logmeta::mark_privileged(ev, lvl);
        }
        if (agent_) agent_->submit(ev);
    }

    void loop() {
        while (running_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            auto cur = snapshot();
            for (auto p : cur) if (last_snapshot_.find(p) == last_snapshot_.end()) emit_event(p, EventAction::Spawn);
            for (auto p : last_snapshot_) if (cur.find(p) == cur.end()) emit_event(p, EventAction::Exit);
            last_snapshot_ = cur;
        }
    }
    Agent* agent_ { nullptr };
    std::thread thr_;
    bool running_ { false };
    PidSet last_snapshot_;
};

// =========================================================================
// LinuxNetworkCollector
// =========================================================================
class LinuxNetworkCollector : public Collector {
public:
    Result<void> start(Agent& agent) override {
        agent_ = &agent;
        running_ = true;
        thr_ = std::thread([this] { loop(); });
        return Result<void>::ok();
    }
    void stop() override { running_ = false; if (thr_.joinable()) thr_.join(); }
    std::string  name()   const override { return "network_linux"; }
    EventCategory category() const override { return EventCategory::Network; }
    bool         is_running() const override { return running_; }

private:
    struct Conn { std::string local; std::string remote; u16 lport; u16 rport; int state; };

    static std::vector<Conn> parse_proc(const std::string& path) {
        std::vector<Conn> out;
        std::ifstream f(path);
        if (!f) return out;
        std::string line; std::getline(f, line);
        while (std::getline(f, line)) {
            std::istringstream iss(line);
            std::string sl, sh, rs, rh, st;
            iss >> sl >> sh >> rs >> rh >> st;
            if (st.empty()) continue;
            Conn c;
            c.lport = static_cast<u16>(std::stoul(sl.substr(sl.find(':') + 1), nullptr, 16));
            c.rport = static_cast<u16>(std::stoul(rs.substr(rs.find(':') + 1), nullptr, 16));
            c.local  = hex_to_ip(sh);
            c.remote = hex_to_ip(rh);
            c.state  = std::stoi(st, nullptr, 16);
            out.push_back(c);
        }
        return out;
    }
    static std::string hex_to_ip(const std::string& h) {
        if (h.size() == 8) {
            u32 a = std::stoul(h, nullptr, 16);
            char buf[32];
            std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                a & 0xFF, (a >> 8) & 0xFF, (a >> 16) & 0xFF, (a >> 24) & 0xFF);
            return buf;
        }
        if (h.size() == 32) {
            u8 b[16];
            for (int i = 0; i < 16; ++i) {
                b[15 - i] = static_cast<u8>(std::stoul(h.substr(i * 2, 2), nullptr, 16));
            }
            char buf[64];
            inet_ntop(AF_INET6, b, buf, sizeof(buf));
            return buf;
        }
        return {};
    }
    static std::string conn_key(const Conn& c) {
        return c.local + ":" + std::to_string(c.lport) + "-" + c.remote + ":" + std::to_string(c.rport);
    }
    void emit(const Conn& c, EventAction act) {
        AuditEvent ev;
        ev.category = EventCategory::Network;
        ev.action   = act;
        ev.target.address  = c.remote;
        ev.target.port     = c.rport;
        ev.target.protocol = "tcp";
        ev.message = "tcp " + c.local + ":" + std::to_string(c.lport)
                   + " -> " + c.remote + ":" + std::to_string(c.rport)
                   + " state=" + std::to_string(c.state);
        logmeta::tag_collector(ev, logmeta::collector::kNetworkLinux);
        if (agent_) agent_->submit(ev);
    }
    void loop() {
        std::set<std::string> last;
        while (running_) {
            auto cur = parse_proc("/proc/net/tcp");
            auto v6  = parse_proc("/proc/net/tcp6");
            cur.insert(cur.end(), v6.begin(), v6.end());
            std::set<std::string> now;
            for (auto& c : cur) {
                if (c.state != 1) continue;
                auto k = conn_key(c);
                now.insert(k);
                if (last.find(k) == last.end()) emit(c, EventAction::Connect);
            }
            for (auto& k : last) if (now.find(k) == now.end()) {
                for (auto& c : cur) if (conn_key(c) == k) { emit(c, EventAction::Disconnect); break; }
            }
            last = std::move(now);
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
    }
    Agent* agent_ { nullptr };
    std::thread thr_;
    bool running_ { false };
};

// =========================================================================
// LinuxCommandCollector - Linux 命令采集器
// =========================================================================
class LinuxCommandCollector : public Collector {
public:
    Result<void> start(Agent& agent) override {
        agent_ = &agent;
        running_ = true;
        thr_ = std::thread([this] { loop(); });
        return Result<void>::ok();
    }
    void stop() override { running_ = false; if (thr_.joinable()) thr_.join(); }
    std::string  name()   const override { return "command_linux"; }
    EventCategory category() const override { return EventCategory::Command; }
    bool         is_running() const override { return running_; }

private:
    static bool is_shell(const std::string& comm) {
        return comm == "bash" || comm == "sh" || comm == "zsh" ||
               comm == "fish" || comm == "dash" || comm == "csh" ||
               comm == "tcsh" || comm == "ksh" || comm == "ash" ||
               comm == "python" || comm == "python3" || comm == "perl" ||
               comm == "ruby" || comm == "node" || comm == "php";
    }
    static std::string read_file(const std::string& p) {
        std::ifstream f(p); std::stringstream ss; ss << f.rdbuf(); return ss.str();
    }
    void loop() {
        while (running_) {
            DIR* d = opendir("/proc");
            if (!d) { std::this_thread::sleep_for(std::chrono::seconds(1)); continue; }
            struct dirent* e;
            while ((e = readdir(d)) != nullptr) {
                if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
                u32 pid = static_cast<u32>(std::strtoul(e->d_name, nullptr, 10));
                if (seen_pids_.count(pid)) continue;
                seen_pids_.insert(pid);
                std::string base = std::string("/proc/") + e->d_name;
                std::string comm = read_file(base + "/comm");
                while (!comm.empty() && (comm.back() == '\n' || comm.back() == '\r')) comm.pop_back();
                if (!is_shell(comm)) continue;
                std::string cmdline = read_file(base + "/cmdline");
                for (auto& c : cmdline) if (c == '\0') c = ' ';
                if (!cmdline.empty() && cmdline.back() == ' ') cmdline.pop_back();
                AuditEvent ev;
                ev.category = EventCategory::Command;
                ev.action   = EventAction::Execute;
                ev.actor.pid  = pid;
                ev.actor.name = comm;
                ev.command    = cmdline;
                ev.message    = "shell exec: " + cmdline;
                logmeta::tag_collector(ev, logmeta::collector::kCommandLinux);
                if (agent_) agent_->submit(ev);
            }
            closedir(d);
            if (seen_pids_.size() > 100000) seen_pids_.clear();
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    }
    Agent* agent_ { nullptr };
    std::thread thr_;
    bool running_ { false };
    std::set<u32> seen_pids_;
};

// =========================================================================
// LinuxAuditCollector - Linux 审计采集器
// =========================================================================
#ifdef AF_HAVE_LIBAUDIT
class LinuxAuditCollector : public Collector {
public:
    Result<void> start(Agent& agent) override {
        agent_ = &agent;
        af_ = audit_open();
        if (!af_) {
            AF_LOG_WARN("audit: cannot open audit socket (need root or CAP_AUDIT_READ)");
            return Result<void>(Error::Code::PermissionDenied, "audit_open");
        }
        running_ = true;
        thr_ = std::thread([this] { loop(); });
        return Result<void>::ok();
    }
    void stop() override {
        running_ = false;
        if (thr_.joinable()) thr_.join();
        if (af_) { audit_close(af_); af_ = nullptr; }
    }
    std::string  name()   const override { return "audit_linux"; }
    EventCategory category() const override { return EventCategory::Syscall; }
    bool         is_running() const override { return running_; }

private:
    void dispatch(const char* raw) {
        if (!raw) return;
        std::string s = raw;
        AuditEvent ev;
        ev.category = EventCategory::Syscall;
        ev.message  = s;
        if (s.find("EXECVE") != std::string::npos) {
            ev.category = EventCategory::Command;
            ev.action   = EventAction::Execute;
        } else if (s.find("PATH") != std::string::npos) {
            ev.category = EventCategory::File;
            ev.action   = EventAction::Read;
        } else if (s.find("PROCTITLE") != std::string::npos) {
            ev.category = EventCategory::Process;
            ev.action   = EventAction::Execute;
        } else if (s.find("USER_AUTH") != std::string::npos) {
            ev.category = EventCategory::Auth;
            ev.action   = EventAction::Login;
        }
        logmeta::tag_collector(ev, logmeta::collector::kAuditLinux);
        if (agent_) agent_->submit(ev);
    }
    void loop() {
        while (running_) {
            int rc = audit_get_reply(af_, &rep_, GET_REPLY_NONBLOCKING, 0);
            if (rc > 0 && rep_.reply.len > 0) dispatch(rep_.reply.msg);
            else std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }
    audit_handle* af_ { nullptr };
    struct audit_reply rep_ {};
    Agent* agent_ { nullptr };
    std::thread thr_;
    bool running_ { false };
};
#else
// =========================================================================
// LinuxAuditCollector（无 libaudit 兜底实现）
//
// 编译环境缺少 audit 用户态库（audit_open/audit_get_reply）时，退化为
// “tail -F /var/log/audit/audit.log”：直接尾随 auditd 守护进程写出的文本日志。
// 语义、事件分类与 libaudit 版保持一致，采集器名称同为 audit_linux，
// Web 开关与后续规则无需区分两种实现。文件轮转（rename/rotate）也能跟踪。
// =========================================================================
class LinuxAuditCollector : public Collector {
public:
    Result<void> start(Agent& agent) override {
        agent_ = &agent;
        running_ = true;
        // 允许用环境变量覆盖日志位置（测试或定制发行版）。
        if (const char* env_path = std::getenv("AF_AUDIT_LOG_FILE")) {
            if (env_path[0] != '\0') log_path_override_ = env_path;
        }
        thr_ = std::thread([this] { loop(); });
        AF_LOG_INFO("audit: libaudit 不可用，使用 audit.log 尾随兜底采集器");
        return Result<void>::ok();
    }
    void stop() override {
        running_ = false;
        if (thr_.joinable()) thr_.join();
    }
    std::string  name()   const override { return "audit_linux"; }
    EventCategory category() const override { return EventCategory::Syscall; }
    bool         is_running() const override { return running_; }

private:
    static std::string audit_log_path() {
        const char* candidates[] = {
            "/var/log/audit/audit.log",
            "/var/log/audit.log",
        };
        struct stat st {};
        for (const char* p : candidates) {
            if (::stat(p, &st) == 0 && S_ISREG(st.st_mode)) return p;
        }
        return candidates[0];  // 即使不存在也返回首选路径，循环中会等待文件出现
    }

    // 解析 audit 文本日志中的 key=value（含引号包裹值）。
    static std::map<std::string, std::string> parse_fields(const std::string& line) {
        std::map<std::string, std::string> kv;
        std::size_t i = line.find(": ");  // 跳过 "type=X msg=audit(...) : " 头部
        if (i == std::string::npos) i = 0;
        while (i < line.size()) {
            while (i < line.size() && (line[i] == ' ' || line[i] == '\t')) ++i;
            std::size_t ks = i;
            while (i < line.size() && line[i] != '=' && line[i] != ' ') ++i;
            if (i >= line.size() || line[i] != '=') break;
            std::string key = line.substr(ks, i - ks);
            ++i;  // 跳过 '='
            std::string val;
            if (i < line.size() && line[i] == '"') {
                ++i;
                std::string raw;
                while (i < line.size() && line[i] != '"') {
                    if (line[i] == '\\' && i + 1 < line.size()) raw += line[++i];
                    else raw += line[i];
                    ++i;
                }
                ++i;  // 跳过结束引号
                val = raw;
            } else {
                std::size_t start = i;
                while (i < line.size() && line[i] != ' ') ++i;
                val = line.substr(start, i - start);
            }
            if (!key.empty()) kv[key] = val;
        }
        return kv;
    }

    void dispatch_line(const std::string& line) {
        if (line.empty()) return;
        std::string type;
        std::size_t tp = line.find("type=");
        if (tp != std::string::npos) {
            for (std::size_t i = tp + 5; i < line.size() && line[i] != ' ' && line[i] != '='; ++i) type += line[i];
        }
        auto f = parse_fields(line);
        AuditEvent ev;
        ev.message = line;
        ev.category = EventCategory::Syscall;
        auto it_pid = f.find("pid");
        if (it_pid != f.end()) ev.actor.pid = static_cast<u32>(std::stoul(it_pid->second.c_str()));
        auto uid = f.find("uid");
        if (uid != f.end()) ev.actor.user = uid->second;
        if (f.count("acct")) ev.actor.user = f["acct"];
        if (f.count("comm")) ev.actor.name = f["comm"];
        if (f.count("exe")) ev.actor.path = f["exe"];
        if (f.count("name")) ev.target.path = f["name"];
        if (f.count("res")) ev.outcome = f["res"] == "success" ? EventOutcome::Success : EventOutcome::Failure;
        else ev.outcome = EventOutcome::Unknown;

        if (type == "EXECVE") {
            ev.category = EventCategory::Command;
            ev.action   = EventAction::Execute;
            // 重组命令行：a0="cmd" a1="arg1" ...
            std::string cmd;
            for (int idx = 0;; ++idx) {
                auto a = f.find("a" + std::to_string(idx));
                if (a == f.end()) break;
                if (idx) cmd += ' ';
                cmd += a->second;
            }
            ev.command = cmd;
        } else if (type == "PATH") {
            ev.category = EventCategory::File;
            ev.action   = EventAction::Read;
        } else if (type == "USER_CMD" || type == "USER_START" || type == "USER_END") {
            ev.category = EventCategory::Process;
            ev.action   = EventAction::Execute;
        } else if (type == "USER_AUTH" || type == "USER_LOGIN" || type == "USER_ERR") {
            ev.category = EventCategory::Auth;
            ev.action   = ev.outcome == EventOutcome::Failure ? EventAction::AuthFail : EventAction::Login;
        } else if (type == "CRED_REFR" || type == "CRED_ACQ" ||
                   type == "ROLE_ADD"  || type == "ROLE_ASSIGN" || type == "ROLE_REM" || type == "ROLE_DEL") {
            ev.category = EventCategory::Privilege;
            ev.action   = EventAction::PrivilegeEsc;
        } else if (type == "SYSCALL") {
            ev.category = EventCategory::Syscall;
            ev.command  = f.count("comm") ? f["comm"] : "";
        }
        logmeta::tag_collector(ev, logmeta::collector::kAuditLinux);
        ev.attrs["source"] = "audit_log_tail";
        if (agent_) agent_->submit(ev);
    }

    bool open_locked() {
        close_locked();
        fp_ = std::fopen(path_.c_str(), "rb");
        if (!fp_) return false;
        if (::stat(path_.c_str(), &st_) != 0) return true;
        // 首次打开从文件末尾开始（tail 语义），不回放历史。
        std::fseek(fp_, 0, SEEK_END);
        offset_ = std::ftell(fp_);
        return true;
    }
    void close_locked() {
        if (fp_) { std::fclose(fp_); fp_ = nullptr; }
    }

    void loop() {
        path_ = log_path_override_.empty() ? audit_log_path() : log_path_override_;
        bool warned_missing = false;
        std::string partial;
        while (running_) {
            if (!fp_) {
                if (open_locked()) {
                    AF_LOG_INFO("audit: 开始尾随 " << path_);
                    warned_missing = false;
                } else if (!warned_missing) {
                    AF_LOG_WARN("audit: 无法打开 " << path_ << "（可能需要 root 权限或文件尚未生成），稍后重试");
                    warned_missing = true;
                }
            }
            if (fp_) {
                // 轮转检测：inode 变化或文件被截断。
                struct stat cur {};
                if (::stat(path_.c_str(), &cur) != 0 || cur.st_ino != st_.st_ino ||
                    cur.st_size < offset_) {
                    AF_LOG_INFO("audit: 检测到日志轮转/截断，重新打开 " << path_);
                    if (open_locked()) partial.clear();
                }
            }
            if (fp_) {
                char buf[64 * 1024];
                // fread 返回读取的字节数：size=1, count=buf_size 才能按字节计数
                std::size_t n = std::fread(buf, 1, sizeof(buf), fp_);
                if (n > 0) {
                    offset_ += static_cast<long>(n);
                    partial.append(buf, n);
                    while (true) {
                        auto pos = partial.find('\n');
                        if (pos == std::string::npos) break;
                        dispatch_line(partial.substr(0, pos));
                        partial.erase(0, pos + 1);
                    }
                }
            }
            for (int i = 0; i < 5 && running_; ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
        close_locked();
    }

    Agent*       agent_ { nullptr };
    std::thread  thr_;
    bool         running_ { false };
    std::string  log_path_override_;
    std::string  path_;
    FILE*        fp_ { nullptr };
    long         offset_ { 0 };
    struct stat  st_ {};
};
#endif

}  // namespace af::collector
