// AuditForwarder - 采集器降噪过滤实现（纯逻辑，无平台 API 依赖）。
#include "auditforwarder/collector_filter.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>

namespace af::collector {

namespace {

std::string lower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// 取路径最后一段（兼容 \ 与 /）
std::string basename_of(const std::string& path) {
    auto p = path.find_last_of("\\/");
    return p == std::string::npos ? path : path.substr(p + 1);
}

std::string env_or_empty(const char* name) {
    const char* v = std::getenv(name);
    return v ? std::string(v) : std::string();
}

}  // namespace

bool filter_glob_match(const std::string& pattern, const std::string& text) {
    const std::string pat = lower(pattern);
    const std::string s   = lower(text);
    std::size_t pi = 0, si = 0;
    std::size_t star_pi = std::string::npos, star_si = 0;
    while (si < s.size()) {
        if (pi < pat.size() && (pat[pi] == '?' || pat[pi] == s[si])) {
            ++pi; ++si;
        } else if (pi < pat.size() && pat[pi] == '*') {
            star_pi = pi++; star_si = si;
        } else if (star_pi != std::string::npos) {
            pi = star_pi + 1;
            si = ++star_si;
        } else {
            return false;
        }
    }
    while (pi < pat.size() && pat[pi] == '*') ++pi;
    return pi == pat.size();
}

std::vector<std::string> default_file_paths() {
    std::vector<std::string> out;
#ifdef _WIN32
    const std::string home = env_or_empty("USERPROFILE");
    if (!home.empty()) {
        out.push_back(home + "\\Desktop");
        out.push_back(home + "\\Documents");
        out.push_back(home + "\\Downloads");
    }
#else
    const std::string home = env_or_empty("HOME");
    if (!home.empty()) out.push_back(home);
    out.push_back("/etc");
#endif
    return out;
}

std::vector<std::string> default_file_excludes() {
    // 只排除「已知无检测价值」的高频噪声，保留文档/代码等用户资产。
    return {
        "*.tmp", "*.temp", "*.log", "*.etl", "*.evtx", "*.dll", "*.sys",
        "*.mui", "*.cache", "*.jsonl", "*.lock", "*~$*", "*.crash",
        "*\\AppData\\Local\\Temp\\*", "*\\AppData\\Local\\Microsoft\\*",
        "*\\AppData\\Local\\Packages\\*", "*\\AppData\\Local\\CrashDumps\\*",
        "*\\.git\\*", "*\\node_modules\\*", "*\\__pycache__\\*",
        "*\\build\\*", "*\\dist\\*", "*\\.cache\\*",
        "*/AppData/Local/Temp/*", "*/.git/*", "*/node_modules/*",
        "*/build/*", "*/__pycache__/*", "*/.cache/*",
        "*/data/client/*", "*/data/server/*",
    };
}

std::vector<std::string> default_process_excludes() {
    // 系统管道进程：启动频繁、无操作员语义，属于典型背景噪声。
    // 故意不包含 cmd.exe / powershell.exe / bash / wscript 等命令宿主。
    return {
        "conhost.exe", "svchost.exe", "taskhostw.exe", "runtimebroker.exe",
        "dllhost.exe", "searchprotocolhost.exe", "searchfilterhost.exe",
        "wmiprvse.exe", "backgroundtaskhost.exe", "smartscreen.exe",
        "sppsvc.exe", "msmpeng.exe", "securityhealthservice.exe",
        "ctfmon.exe", "textinputhost.exe", "shellexperiencehost.exe",
    };
}

CollectorFilterConfig default_collector_filter() {
    CollectorFilterConfig cfg;
    cfg.file.paths        = default_file_paths();
    cfg.file.exclude      = default_file_excludes();
    cfg.process.exclude_images = default_process_excludes();
    return cfg;
}

bool file_event_allowed(const FileFilterConfig& cfg, const std::string& path) {
    for (const auto& p : cfg.exclude) {
        if (filter_glob_match(p, path)) return false;
    }
    if (cfg.include.empty()) return true;
    for (const auto& p : cfg.include) {
        if (filter_glob_match(p, path)) return true;
    }
    return false;
}

bool process_image_allowed(const ProcessFilterConfig& cfg, const std::string& image_path) {
    if (image_path.empty()) return true;  // 取不到镜像名时放行，避免漏采
    const std::string name = basename_of(image_path);
    for (const auto& p : cfg.exclude_images) {
        if (filter_glob_match(p, name)) return false;
    }
    return true;
}

bool is_loopback_ip(const std::string& ip) {
    if (ip == "::1" || ip == "0.0.0.0" || ip == "::" || ip.empty()) return true;
    if (ip.rfind("127.", 0) == 0) return true;
    if (ip.rfind("::ffff:127.", 0) == 0) return true;
    return false;
}

bool network_event_allowed(const NetworkFilterConfig& cfg,
                           const std::string& local_ip,
                           const std::string& remote_ip,
                           u16 remote_port,
                           bool established) {
    if (cfg.only_established && !established) return false;
    if (!cfg.include_loopback && (is_loopback_ip(local_ip) || is_loopback_ip(remote_ip))) {
        return false;
    }
    if (remote_port == 0) return false;
    for (auto p : cfg.exclude_remote_ports) {
        if (p == remote_port) return false;
    }
    return true;
}

bool etw_event_allowed(const EtwFilterConfig& cfg,
                       int event_id,
                       int logon_type,
                       const std::string& user,
                       const std::string& sid) {
    if (event_id != 4624) return true;  // 失败登录/进程事件不做账户维度过滤
    if (cfg.skip_system && (sid == "S-1-5-18" || user == "SYSTEM")) return false;
    if (cfg.skip_machine_accounts && !user.empty() && user.back() == '$') return false;
    if (!cfg.logon_types.empty()) {
        if (std::find(cfg.logon_types.begin(), cfg.logon_types.end(), logon_type) ==
            cfg.logon_types.end()) {
            return false;
        }
    }
    return true;
}

bool FileEventCoalescer::accept(const std::string& path, const std::string& action, u64 ts_us) {
    if (window_us_ == 0) return true;
    const std::string key = path + "\n" + action;
    auto it = last_.find(key);
    if (it != last_.end() && ts_us >= it->second && ts_us - it->second < window_us_) {
        return false;
    }
    last_[key] = ts_us;
    order_.emplace_back(ts_us, key);
    // 淘汰窗口外的旧记录，保持 map 规模与活跃文件数同阶
    while (!order_.empty() && ts_us >= order_.front().first &&
           ts_us - order_.front().first >= window_us_) {
        auto& old = order_.front().second;
        auto old_it = last_.find(old);
        if (old_it != last_.end() && old_it->second + window_us_ <= ts_us) last_.erase(old_it);
        order_.pop_front();
    }
    return true;
}

void FileEventCoalescer::clear() {
    last_.clear();
    order_.clear();
}

bool NetworkSnapshotDiffer::accept(const std::string& key, int state) {
    auto it = state_.find(key);
    if (it == state_.end()) {
        state_[key] = state;
        return true;
    }
    if (it->second != state) {
        it->second = state;
        return true;
    }
    return false;
}

void NetworkSnapshotDiffer::sweep(const std::vector<std::string>& alive_keys) {
    if (state_.empty()) return;
    std::map<std::string, int> next;
    for (const auto& k : alive_keys) {
        auto it = state_.find(k);
        if (it != state_.end()) next.emplace(*it);
    }
    state_.swap(next);
}

void NetworkSnapshotDiffer::clear() { state_.clear(); }

}  // namespace af::collector
