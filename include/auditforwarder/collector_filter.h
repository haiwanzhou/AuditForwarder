#pragma once
// AuditForwarder - 采集器降噪过滤配置与纯逻辑判定。
//
// 设计借鉴（GitHub 主流主机采集方案）：
//   - Sysmon：Include/Exclude 规则集，排除优先，可按事件类型分组配置过滤；
//   - osquery：事件型表开销大，只保留有检测价值的事件，默认关闭高噪声项；
//   - Zeek conn.log：一条连接只记录一次，不按快照重复记录；
//   - auditd：按字段（路径/端口/用户）做过滤，而非全部落盘。
//
// 本模块只做「是否采集」的纯逻辑判定，便于单元测试；
// 平台采集器负责取数据并调用这些函数，不重复实现过滤条件。

#include "auditforwarder/types.h"

#include <deque>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace af::collector {

// ---- 文件采集过滤 ----
struct FileFilterConfig {
    std::vector<std::string> paths;     // 监控目录（空 = 平台默认目录）
    std::vector<std::string> include;   // 允许列表（空 = 全部允许）
    std::vector<std::string> exclude;   // 排除列表（优先于 allow）
    u64 coalesce_ms { 2000 };           // 同路径同动作合并窗口（毫秒），0 = 不去重
};

// ---- 进程采集过滤 ----
struct ProcessFilterConfig {
    std::vector<std::string> exclude_images;  // 噪声进程名（大小写不敏感，支持 * ?）
    bool emit_exit { false };                 // 是否上报进程退出（默认不上报）
};

// ---- 网络采集过滤 ----
struct NetworkFilterConfig {
    bool include_loopback { false };            // 是否保留回环/本机连接
    bool only_established { true };             // 仅保留 ESTABLISHED
    bool emit_only_new { true };                // 仅上报新连接/状态变化
    int  poll_ms { 2000 };                      // 连接表快照轮询间隔（毫秒）
    std::vector<u16> exclude_remote_ports;      // 排除远端端口（如 137/138/139）
};

// ---- Windows 安全事件（ETW）过滤 ----
struct EtwFilterConfig {
    std::vector<int> event_ids { 4624, 4625, 4688 };  // 登录成功/失败/进程创建（4689 退出默认不上报）
    std::vector<int> logon_types { 2, 10, 11 };  // 4624 仅保留交互式/远程交互/缓存交互
    bool skip_machine_accounts { true };         // 跳过以 $ 结尾的机器账户
    bool skip_system { true };                   // 跳过 SYSTEM（S-1-5-18）
    bool extract_command_line { true };          // 4688 提取命令行
};

struct CollectorFilterConfig {
    FileFilterConfig    file;
    ProcessFilterConfig process;
    NetworkFilterConfig network;
    EtwFilterConfig     etw;
};

// 平台默认监控目录：Windows 为用户桌面/文档/下载；Linux 为用户主目录 + /etc
std::vector<std::string> default_file_paths();

// 默认噪声排除：构建产物、版本库、包管理目录、缓存/临时/日志、采集端自身落盘
std::vector<std::string> default_file_excludes();

// 默认噪声进程：系统管道进程（保留 cmd/powershell/bash 等命令宿主）
std::vector<std::string> default_process_excludes();

// 组装默认配置（各平台一致，路径部分由 default_file_paths 提供）
CollectorFilterConfig default_collector_filter();

// 通配符匹配：支持 * 与 ?，大小写不敏感
bool filter_glob_match(const std::string& pattern, const std::string& text);

// 文件事件是否放行（exclude 优先，include 为空表示全放行）
bool file_event_allowed(const FileFilterConfig& cfg, const std::string& path);

// 进程镜像是否放行（按可执行文件名匹配，大小写不敏感）
bool process_image_allowed(const ProcessFilterConfig& cfg, const std::string& image_path);

// 是否回环/本机地址（127.0.0.0/8、::1、0.0.0.0、::）
bool is_loopback_ip(const std::string& ip);

// 网络连接是否放行：回环、未建立、排除端口
bool network_event_allowed(const NetworkFilterConfig& cfg,
                           const std::string& local_ip,
                           const std::string& remote_ip,
                           u16 remote_port,
                           bool established);

// ETW 事件是否放行：仅对 4624 应用登录类型/机器账户/SYSTEM 过滤
bool etw_event_allowed(const EtwFilterConfig& cfg,
                       int event_id,
                       int logon_type,
                       const std::string& user,
                       const std::string& sid);

// 文件事件合并器：同一 (path, action) 在窗口内只放行一次，
// 避免编辑器/浏览器反复写同一文件时刷屏（默认 2 秒）。
class FileEventCoalescer {
public:
    explicit FileEventCoalescer(u64 window_ms = 2000) : window_us_(window_ms * 1000) {}
    bool accept(const std::string& path, const std::string& action, u64 ts_us);
    void clear();
    std::size_t size() const { return last_.size(); }
private:
    u64 window_us_ { 2000000 };
    std::map<std::string, u64> last_;
    std::deque<std::pair<u64, std::string>> order_;
};

// 连接快照差分器：同一条连接只在首次出现或状态变化时放行，
// 避免「每 5 秒把整张 TCP 表再上报一遍」。
class NetworkSnapshotDiffer {
public:
    bool accept(const std::string& key, int state);
    // 清理已消失的连接（防止 map 无限增长）
    void sweep(const std::vector<std::string>& alive_keys);
    void clear();
    std::size_t size() const { return state_.size(); }
private:
    std::map<std::string, int> state_;
};

}  // namespace af::collector
