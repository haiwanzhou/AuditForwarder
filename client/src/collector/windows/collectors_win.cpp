// AuditForwarder - Windows collectors (combined implementation file).

#include "auditforwarder/agent.h"
#include "auditforwarder/collector_base.h"
#include "auditforwarder/event.h"
#include "auditforwarder/fs.h"
#include "auditforwarder/log_meta.h"
#include "auditforwarder/logger.h"
#include "auditforwarder/process.h"

#include <chrono>
#include <set>
#include <sstream>
#include <thread>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <winevt.h>
#include <evntrace.h>
#include <tdh.h>
#include <sddl.h>
#include <aclapi.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <iphlpapi.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wevtapi.lib")
#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "psapi.lib")

namespace af::collector {

namespace {

// ETW 渲染出的安全事件 XML 形如：
//   <Data Name="SubjectUserName">Administrator</Data>
// 做最小依赖的字符串提取；找不到返回空串。
std::string etw_data_field(const std::string& xml, const std::string& name) {
    std::string needle = "Name=\"" + name + "\"";
    auto p = xml.find(needle);
    if (p == std::string::npos) return {};
    p = xml.find('>', p);
    if (p == std::string::npos) return {};
    ++p;
    auto e = xml.find("</Data>", p);
    if (e == std::string::npos) return {};
    return xml.substr(p, e - p);
}

// 提取 <EventID>4688</EventID>。
std::string etw_event_id(const std::string& xml) {
    const std::string tag = "<EventID>";
    auto p = xml.find(tag);
    if (p == std::string::npos) return {};
    p += tag.size();
    auto e = xml.find("</EventID>", p);
    if (e == std::string::npos) return {};
    return xml.substr(p, e - p);
}

// ETW 原始 XML 保留上限（比普通日志宽松；服务端 etw_win 策略默认 8192）。
constexpr std::size_t kEtwRawMaxLen = 4096;

}  // namespace

// =========================================================================
// WindowsFileCollector - ReadDirectoryChangesW based
// =========================================================================
class WindowsFileSource : public FileWatchSource {
public:
    WindowsFileSource() = default;
    ~WindowsFileSource() override { close(); }

    Result<void> open(const std::vector<std::string>& paths) override {
        close();
        for (const auto& p : paths) {
            HANDLE h = ::CreateFileA(
                p.c_str(), FILE_LIST_DIRECTORY,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                nullptr);
            if (h == INVALID_HANDLE_VALUE) continue;
            Watcher w;
            w.h = h;
            w.path = p;
            w.buf.resize(64 * 1024);           // 一次性分配，避免 poll 中反复 resize 造成 ReadDirectoryChangesW 写入旧地址
            handles_.push_back(std::move(w));
        }
        // 为每个 handle 发出初始异步读取
        for (auto& w : handles_) {
            memset(&w.ov, 0, sizeof(w.ov));
            ::ReadDirectoryChangesW(w.h, w.buf.data(), static_cast<DWORD>(w.buf.size()),
                                    TRUE,
                                    FILE_NOTIFY_CHANGE_FILE_NAME |
                                    FILE_NOTIFY_CHANGE_SIZE |
                                    FILE_NOTIFY_CHANGE_LAST_WRITE |
                                    FILE_NOTIFY_CHANGE_ATTRIBUTES |
                                    FILE_NOTIFY_CHANGE_SECURITY,
                                    nullptr, &w.ov, nullptr);
        }
        running_ = !handles_.empty();
        return Result<void>::ok();
    }
    void close() override {
        running_ = false;
        for (auto& w : handles_) if (w.h != INVALID_HANDLE_VALUE) ::CloseHandle(w.h);
        handles_.clear();
    }
    int poll(std::function<bool(const std::string&, const std::string&, u64)> cb) override {
        if (!running_) return 0;
        int total = 0;
        for (auto& w : handles_) {
            DWORD n = 0;
            if (!::GetOverlappedResult(w.h, &w.ov, &n, FALSE)) {
                // 上一次 I/O 尚未完成，继续等待；轮询期间不重新发 Read
                continue;
            }
            if (n == 0 || w.buf.empty()) continue;
            auto* fni = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(w.buf.data());
            while (true) {
                char path[MAX_PATH];
                int len = WideCharToMultiByte(CP_ACP, 0, fni->FileName, fni->FileNameLength / 2,
                                              path, sizeof(path) - 1, nullptr, nullptr);
                path[len] = 0;
                std::string op;
                switch (fni->Action) {
                    case FILE_ACTION_ADDED:           op = "create"; break;
                    case FILE_ACTION_REMOVED:         op = "delete"; break;
                    case FILE_ACTION_MODIFIED:        op = "write"; break;
                    case FILE_ACTION_RENAMED_OLD_NAME:op = "rename_from"; break;
                    case FILE_ACTION_RENAMED_NEW_NAME:op = "rename_to"; break;
                    default: op = "modify";
                }
                u64 ts = static_cast<u64>(
                    std::chrono::duration_cast<std::chrono::microseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count());
                std::string full = w.path + "\\" + std::string(path);
                if (!cb(full, op, ts)) return total;
                ++total;
                if (!fni->NextEntryOffset) break;
                fni = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(
                    reinterpret_cast<char*>(fni) + fni->NextEntryOffset);
            }
            // 发出下一次异步读取（buf 空间已在 open() 预分配，不再 resize 避免指针失效）
            memset(&w.ov, 0, sizeof(w.ov));
            ::ReadDirectoryChangesW(w.h, w.buf.data(), static_cast<DWORD>(w.buf.size()),
                                    TRUE,
                                    FILE_NOTIFY_CHANGE_FILE_NAME |
                                    FILE_NOTIFY_CHANGE_SIZE |
                                    FILE_NOTIFY_CHANGE_LAST_WRITE |
                                    FILE_NOTIFY_CHANGE_ATTRIBUTES |
                                    FILE_NOTIFY_CHANGE_SECURITY,
                                    nullptr, &w.ov, nullptr);
        }
        return total;
    }
private:
    struct Watcher {
        HANDLE h { INVALID_HANDLE_VALUE };
        std::string path;
        OVERLAPPED ov {};
        std::vector<char> buf;
    };
    std::vector<Watcher> handles_;
    bool running_ { false };
};

std::unique_ptr<FileWatchSource> make_file_watch_source() {
    return std::make_unique<WindowsFileSource>();
}

class WindowsFileCollector : public Collector {
public:
    Result<void> start(Agent& agent) override {
        agent_ = &agent;
        paths_ = {"C:\\Windows\\System32", "C:\\Program Files", "C:\\Users", "C:\\ProgramData"};
        filter_.include({});
        filter_.exclude({"*.tmp", "*.log", "*.dll"});
        src_ = make_file_watch_source();
        auto r = src_->open(paths_);
        if (r.is_err()) return r;
        running_ = true;
        thr_ = std::thread([this] { loop(); });
        return Result<void>::ok();
    }
    void stop() override { running_ = false; if (thr_.joinable()) thr_.join(); if (src_) src_->close(); }
    std::string  name()   const override { return "file_win"; }
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
                logmeta::tag_collector(ev, logmeta::collector::kFileWin);
                if (agent_) agent_->submit(ev);
                return true;
            });
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }
    static EventAction op_to_action(const std::string& op) {
        if (op == "create")  return EventAction::Create;
        if (op == "delete")  return EventAction::Delete;
        if (op == "write")   return EventAction::Write;
        if (op == "rename_from" || op == "rename_to") return EventAction::Rename;
        if (op == "chmod")   return EventAction::Chmod;
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
// WindowsProcessCollector - Windows 进程采集器
// =========================================================================
class WindowsProcessCollector : public Collector {
public:
    Result<void> start(Agent& agent) override {
        agent_ = &agent;
        running_ = true;
        last_snapshot_ = snapshot();
        thr_ = std::thread([this] { loop(); });
        return Result<void>::ok();
    }
    void stop() override { running_ = false; if (thr_.joinable()) thr_.join(); }
    std::string  name()   const override { return "process_win"; }
    EventCategory category() const override { return EventCategory::Process; }
    bool         is_running() const override { return running_; }
private:
    using PidSet = std::set<u32>;
    static PidSet snapshot() {
        PidSet out;
        HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return out;
        PROCESSENTRY32 pe{sizeof(pe)};
        if (::Process32First(snap, &pe)) {
            do { out.insert(pe.th32ProcessID); } while (::Process32Next(snap, &pe));
        }
        ::CloseHandle(snap);
        return out;
    }
    void emit(u32 pid, EventAction act) {
        auto info = proc::get_process(pid);
        AuditEvent ev;
        ev.category = EventCategory::Process;
        ev.action   = act;
        ev.actor.pid = pid;
        if (info.is_ok()) {
            ev.actor.name = info.value().name;
            ev.actor.path = info.value().exe;
        }
        ev.message = std::string(to_string(act)) + " pid=" + std::to_string(pid);
        logmeta::tag_collector(ev, logmeta::collector::kProcessWin);
        // 仅对「新启动」进程做提权令牌检测（退出事件无意义），Agent 内带 TTL 缓存
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
            for (auto p : cur) if (last_snapshot_.find(p) == last_snapshot_.end()) emit(p, EventAction::Spawn);
            for (auto p : last_snapshot_) if (cur.find(p) == cur.end()) emit(p, EventAction::Exit);
            last_snapshot_ = cur;
        }
    }
    Agent* agent_ { nullptr };
    std::thread thr_;
    bool running_ { false };
    PidSet last_snapshot_;
};

// =========================================================================
// WindowsNetworkCollector - GetTcpTable2 / GetUdpTable
// =========================================================================
class WindowsNetworkCollector : public Collector {
public:
    Result<void> start(Agent& agent) override {
        agent_ = &agent;
        running_ = true;
        thr_ = std::thread([this] { loop(); });
        return Result<void>::ok();
    }
    void stop() override { running_ = false; if (thr_.joinable()) thr_.join(); }
    std::string  name()   const override { return "network_win"; }
    EventCategory category() const override { return EventCategory::Network; }
    bool         is_running() const override { return running_; }
private:
    static std::string fmt_ip(u32 ip) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
            ip & 0xFF, (ip >> 8) & 0xFF, (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
        return buf;
    }
    void loop() {
        while (running_) {
            DWORD sz = 0;
            ::GetTcpTable2(nullptr, &sz, FALSE);
            std::vector<char> buf(sz);
            auto* tab = reinterpret_cast<MIB_TCPTABLE2*>(buf.data());
            if (::GetTcpTable2(tab, &sz, FALSE) == NO_ERROR) {
                for (DWORD i = 0; i < tab->dwNumEntries; ++i) {
                    auto& r = tab->table[i];
                    AuditEvent ev;
                    ev.category = EventCategory::Network;
                    ev.action   = EventAction::Connect;
                    ev.target.address  = fmt_ip(r.dwRemoteAddr);
                    ev.target.port     = static_cast<u16>(r.dwRemotePort);
                    ev.target.protocol = "tcp";
                    ev.message = "tcp " + fmt_ip(r.dwLocalAddr) + ":" + std::to_string(r.dwLocalPort)
                                 + " -> " + fmt_ip(r.dwRemoteAddr) + ":" + std::to_string(r.dwRemotePort)
                                 + " state=" + std::to_string(r.dwState);
                    logmeta::tag_collector(ev, logmeta::collector::kNetworkWin);
                    if (agent_) agent_->submit(ev);
                }
            }
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }
    Agent* agent_ { nullptr };
    std::thread thr_;
    bool running_ { false };
};

// =========================================================================
// WindowsCommandCollector - 基于 WMI Win32_ProcessStartTrace / WTS 日志
// =========================================================================
class WindowsCommandCollector : public Collector {
public:
    Result<void> start(Agent& agent) override {
        agent_ = &agent;
        running_ = true;
        thr_ = std::thread([this] { loop(); });
        return Result<void>::ok();
    }
    void stop() override { running_ = false; if (thr_.joinable()) thr_.join(); }
    std::string  name()   const override { return "command_win"; }
    EventCategory category() const override { return EventCategory::Command; }
    bool         is_running() const override { return running_; }
private:
    void loop() {
        while (running_) {
            HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32 pe{sizeof(pe)};
                if (::Process32First(snap, &pe)) {
                    do {
                        if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4) continue;
                        if (seen_pids_.count(pe.th32ProcessID)) continue;
                        seen_pids_.insert(pe.th32ProcessID);
                        std::string name = pe.szExeFile;
                        // 启发式：任何看起来像 shell / 脚本宿主的进程
                        if (name.find("cmd.exe") != std::string::npos ||
                            name.find("powershell") != std::string::npos ||
                            name.find("wscript") != std::string::npos ||
                            name.find("cscript") != std::string::npos ||
                            name.find("bash") != std::string::npos ||
                            name.find("sh.exe") != std::string::npos) {
                            AuditEvent ev;
                            ev.category = EventCategory::Command;
                            ev.action   = EventAction::Execute;
                            ev.actor.pid = pe.th32ProcessID;
                            ev.actor.name = name;
                            ev.message = "process start: " + name;
                            logmeta::tag_collector(ev, logmeta::collector::kCommandWin);
                            if (agent_) {
                                auto lvl = agent_->privilege_level_for_pid(pe.th32ProcessID);
                                if (!lvl.empty() && lvl != logmeta::priv::kNone) logmeta::mark_privileged(ev, lvl);
                            }
                            if (agent_) agent_->submit(ev);
                        }
                    } while (::Process32Next(snap, &pe));
                }
                ::CloseHandle(snap);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }
    Agent* agent_ { nullptr };
    std::thread thr_;
    bool running_ { false };
    std::set<u32> seen_pids_;
};

// =========================================================================
// WindowsRegistryCollector - RegNotifyChangeKeyValue
// =========================================================================
class WindowsRegistryCollector : public Collector {
public:
    Result<void> start(Agent& agent) override {
        agent_ = &agent;
        keys_ = {
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "SYSTEM\\CurrentControlSet\\Services",
            "SOFTWARE\\Classes\\*\\shell\\open\\command",
        };
        for (const auto& k : keys_) watch(k);
        running_ = true;
        thr_ = std::thread([this] { loop(); });
        return Result<void>::ok();
    }
    void stop() override { running_ = false; if (thr_.joinable()) thr_.join();
                          for (auto& w : watchers_) ::RegCloseKey(w.h);
                          watchers_.clear(); }
    std::string  name()   const override { return "registry_win"; }
    EventCategory category() const override { return EventCategory::Registry; }
    bool         is_running() const override { return running_; }
private:
    struct Watcher { HKEY h; std::string path; HANDLE evt; };
    void watch(const std::string& rel) {
        HKEY h;
        if (::RegOpenKeyExA(HKEY_LOCAL_MACHINE, rel.c_str(), 0,
            KEY_NOTIFY | KEY_READ, &h) != ERROR_SUCCESS) return;
        HANDLE evt = ::CreateEventA(nullptr, FALSE, FALSE, nullptr);
        ::RegNotifyChangeKeyValue(h, TRUE,
            REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_ATTRIBUTES,
            evt, TRUE);
        watchers_.push_back({h, rel, evt});
    }
    void loop() {
        while (running_) {
            for (auto& w : watchers_) {
                if (::WaitForSingleObject(w.evt, 100) == WAIT_OBJECT_0) {
                    AuditEvent ev;
                    ev.category = EventCategory::Registry;
                    ev.action   = EventAction::Set;
                    ev.target.path = w.path;
                    ev.target.kind  = "registry";
                    ev.message = "registry change: " + w.path;
                    logmeta::tag_collector(ev, logmeta::collector::kRegistryWin);
                    if (agent_) agent_->submit(ev);
                    ::RegNotifyChangeKeyValue(w.h, TRUE,
                        REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
                        w.evt, TRUE);
                }
            }
        }
    }
    std::vector<std::string> keys_;
    std::vector<Watcher>     watchers_;
    Agent* agent_ { nullptr };
    std::thread thr_;
    bool running_ { false };
};

// =========================================================================
// WindowsEtwCollector - light-weight ETW consumer for security events
// =========================================================================
class WindowsEtwCollector : public Collector {
public:
    Result<void> start(Agent& agent) override {
        agent_ = &agent;
        // 订阅安全事件日志
        EVT_HANDLE sub = ::EvtSubscribe(nullptr, nullptr, L"Security",
            L"*[System/EventID=4624 or System/EventID=4625 or System/EventID=4688 or System/EventID=4689]",
            nullptr, nullptr, nullptr, EvtSubscribeToFutureEvents);
        if (!sub) {
            AF_LOG_WARN("etw: failed to subscribe to Security log");
            return Result<void>(Error::Code::PermissionDenied, "EvtSubscribe");
        }
        sub_ = sub;
        running_ = true;
        thr_ = std::thread([this] { loop(); });
        return Result<void>::ok();
    }
    void stop() override { running_ = false; if (thr_.joinable()) thr_.join();
                          if (sub_) { ::EvtClose(sub_); sub_ = nullptr; } }
    std::string  name()   const override { return "etw_win"; }
    EventCategory category() const override { return EventCategory::Auth; }
    bool         is_running() const override { return running_; }
private:
    void loop() {
        EVT_HANDLE events[16];
        while (running_) {
            DWORD n = 0;
            BOOL ok = ::EvtNext(sub_, 16, events, 1000, FALSE, &n);
            if (!ok || n == 0) continue;
            for (DWORD i = 0; i < n; ++i) {
                // EvtRenderEventXml 输出 UTF-16LE，先取所需长度再转 UTF-8。
                DWORD used = 0, needed = 0;
                ::EvtRender(nullptr, events[i], EvtRenderEventXml, 0, nullptr, &used, &needed);
                std::string xml;
                if (used >= sizeof(wchar_t)) {
                    std::vector<wchar_t> wbuf(used / sizeof(wchar_t) + 1);
                    used = static_cast<DWORD>(wbuf.size() * sizeof(wchar_t));
                    if (::EvtRender(nullptr, events[i], EvtRenderEventXml, used,
                                    wbuf.data(), &used, &needed)) {
                        int cap = static_cast<int>(used + 8);
                        std::vector<char> utf8(cap);
                        int len = ::WideCharToMultiByte(CP_UTF8, 0, wbuf.data(), -1,
                                                        utf8.data(), cap, nullptr, nullptr);
                        if (len > 0) xml.assign(utf8.data(), static_cast<std::size_t>(len) - 1);
                    }
                }
                if (!xml.empty()) {
                    AuditEvent ev;
                    ev.category = EventCategory::Auth;
                    ev.action   = EventAction::Login;
                    const std::string eid = etw_event_id(xml);
                    if (eid == "4688") {
                        ev.category = EventCategory::Process; ev.action = EventAction::Spawn;
                    } else if (eid == "4689") {
                        ev.category = EventCategory::Process; ev.action = EventAction::Exit;
                    } else if (eid == "4625") {
                        ev.category = EventCategory::Auth;    ev.action = EventAction::AuthFail;
                    }

                    // 来源标识：etw_win 采集器 + etw_security 唯一来源
                    logmeta::tag_collector(ev, logmeta::collector::kEtwWin);
                    ev.attrs[logmeta::attr::kSource   ] = logmeta::source::kEtwSecurity;
                    ev.attrs[logmeta::attr::kEventId  ] = eid;

                    // 结构化详情（宽松保留：不做 256 字符截断）
                    auto subject_user   = etw_data_field(xml, "SubjectUserName");
                    auto subject_domain = etw_data_field(xml, "SubjectDomainName");
                    auto logon_id       = etw_data_field(xml, "SubjectLogonId");
                    auto new_process    = etw_data_field(xml, "NewProcessName");
                    if (!subject_user.empty())   { ev.attrs[logmeta::attr::kSubjectUser]   = subject_user;   ev.actor.user = subject_user; }
                    if (!subject_domain.empty())   ev.attrs[logmeta::attr::kSubjectDomain] = subject_domain;
                    if (!logon_id.empty())         ev.attrs[logmeta::attr::kLogonId]       = logon_id;
                    if (!new_process.empty()) {
                        ev.attrs[logmeta::attr::kProcessName] = new_process;
                        ev.actor.path = new_process;
                        auto slash = new_process.find_last_of("\\/");
                        ev.actor.name = slash == std::string::npos ? new_process : new_process.substr(slash + 1);
                    }
                    // 高权限标注：SubjectUserSid=S-1-5-18 为 SYSTEM；
                    // 4688 的 TokenElevationType=%%1842（Full）为 UAC 完全提权。
                    if (agent_ && agent_->privilege_detect_enabled()) {
                        const auto sid = etw_data_field(xml, "SubjectUserSid");
                        const auto elev_type = etw_data_field(xml, "TokenElevationType");
                        if (sid == "S-1-5-18") {
                            logmeta::mark_privileged(ev, logmeta::priv::kSystem);
                        } else if ((eid == "4688" || eid == "4624") && elev_type == "%%1842") {
                            logmeta::mark_privileged(ev, logmeta::priv::kElevated);
                        }
                    }
                    ev.attrs[logmeta::attr::kRawXml] = xml.substr(0, kEtwRawMaxLen);

                    ev.message = "etw event_id=" + eid
                               + (subject_user.empty() ? "" : " user=" + subject_domain + "\\" + subject_user)
                               + (new_process.empty()  ? "" : " proc=" + ev.actor.name);
                    if (agent_) agent_->submit(ev);
                }
                ::EvtClose(events[i]);
            }
        }
    }
    EVT_HANDLE sub_ { nullptr };
    Agent* agent_ { nullptr };
    std::thread thr_;
    bool running_ { false };
};

}  // namespace af::collector

namespace af {

void create_windows_collectors(std::vector<std::unique_ptr<Collector>>& out, Agent& /*agent*/) {
    out.push_back(std::unique_ptr<Collector>(new af::collector::WindowsFileCollector()));
    out.push_back(std::unique_ptr<Collector>(new af::collector::WindowsProcessCollector()));
    out.push_back(std::unique_ptr<Collector>(new af::collector::WindowsNetworkCollector()));
    out.push_back(std::unique_ptr<Collector>(new af::collector::WindowsCommandCollector()));
    out.push_back(std::unique_ptr<Collector>(new af::collector::WindowsRegistryCollector()));
    out.push_back(std::unique_ptr<Collector>(new af::collector::WindowsEtwCollector()));
}

}  // namespace af
