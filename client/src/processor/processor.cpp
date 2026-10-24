#include "auditforwarder/processor.h"

#include "auditforwarder/logger.h"
#include "auditforwarder/log_meta.h"

#include <algorithm>
#include <cctype>
#include <initializer_list>
#include <regex>
#include <sstream>

namespace af::processor {

// =====================================================================
// RegexFilter
// =====================================================================
namespace {
const std::string& pick_field(const AuditEvent& ev, RegexFilter::Field f) {
    switch (f) {
        case RegexFilter::Field::ActorName:   return ev.actor.name;
        case RegexFilter::Field::ActorPath:   return ev.actor.path;
        case RegexFilter::Field::ActorUser:   return ev.actor.user;
        case RegexFilter::Field::TargetPath:  return ev.target.path;
        case RegexFilter::Field::Command:     return ev.command;
        case RegexFilter::Field::Message:     return ev.message;
        case RegexFilter::Field::Any: {
            static const std::string empty;
            (void)ev;
            return empty;
        }
    }
    static const std::string empty;
    return empty;
}
}  // namespace

RegexFilter::RegexFilter(Field f, std::string pattern, bool allow_when_match)
    : f_(f), pattern_(std::move(pattern)), allow_(allow_when_match) {
    try { re_ = new std::regex(pattern_); } catch (...) { re_ = nullptr; }
}
RegexFilter::~RegexFilter() { delete static_cast<std::regex*>(re_); }

bool RegexFilter::process(AuditEvent& ev) {
    auto* re = static_cast<std::regex*>(re_);
    if (!re) return true;
    if (f_ == Field::Any) {
        if (std::regex_search(ev.actor.name,   *re) ||
            std::regex_search(ev.actor.path,   *re) ||
            std::regex_search(ev.actor.user,   *re) ||
            std::regex_search(ev.target.path,  *re) ||
            std::regex_search(ev.command,      *re) ||
            std::regex_search(ev.message,      *re)) {
            return allow_;
        }
        return !allow_;
    }
    const std::string& s = pick_field(ev, f_);
    bool match = std::regex_search(s, *re);
    return match ? allow_ : !allow_;
}

// =====================================================================
// Sampler
// =====================================================================
Sampler::Sampler(double keep_ratio) : keep_(std::min(1.0, std::max(0.0, keep_ratio))) {}
bool Sampler::process(AuditEvent&) {
    if (keep_ >= 1.0) return true;
    if (keep_ <= 0.0) return false;
    auto n = counter_.fetch_add(1, std::memory_order_relaxed);
    double r = static_cast<double>(n % 1000) / 1000.0;
    return r < keep_;
}

// =====================================================================
// Deduper（去重器）
// =====================================================================
Deduper::Deduper(std::chrono::milliseconds window) : window_(window) {}

bool Deduper::process(AuditEvent& ev) {
    std::lock_guard<std::mutex> lk(mtx_);
    std::string key = ev.actor.name + "|" + ev.actor.path + "|" +
                      std::to_string(static_cast<int>(ev.action)) + "|" +
                      ev.target.path + "|" + ev.command;
    auto now = Clock::now();
    auto it = seen_.find(key);
    if (it != seen_.end() && (now - it->second) < window_) {
        return false;
    }
    seen_[key] = now;
    // GC old entries
    for (auto i = seen_.begin(); i != seen_.end();) {
        if ((now - i->second) > window_ * 10) i = seen_.erase(i); else ++i;
    }
    return true;
}

// =====================================================================
// Enricher
// =====================================================================
Enricher::Enricher(std::string host, std::string agent_id,
                   std::string operator_id, std::string operator_name)
    : host_(std::move(host)), agent_id_(std::move(agent_id)),
      operator_id_(std::move(operator_id)), operator_name_(std::move(operator_name)) {}

bool Enricher::process(AuditEvent& ev) {
    if (ev.host.empty())     ev.host = host_;
    if (ev.agent_id.empty()) ev.agent_id = agent_id_;
    if (ev.actor.user.empty()) {
#ifdef AF_PLATFORM_WINDOWS
        // best-effort: leave empty if unknown
#else
        if (char* l = std::getenv("USER"); l) ev.actor.user = l;
#endif
    }
    // 操作员身份贯通：本机采集的全部操作归属配置的操作员（M5）。
    if (!operator_id_.empty() && ev.attrs.find(logmeta::attr::kOperatorId) == ev.attrs.end()) {
        ev.attrs[logmeta::attr::kOperatorId] = operator_id_;
    }
    if (!operator_name_.empty() && ev.attrs.find(logmeta::attr::kOperatorName) == ev.attrs.end()) {
        ev.attrs[logmeta::attr::kOperatorName] = operator_name_;
    }
    return true;
}

// =====================================================================
// Aggregator
// =====================================================================
Aggregator::Aggregator(std::chrono::seconds window, std::size_t max)
    : window_(window), max_(max) {}

static std::string agg_key(const AuditEvent& ev) {
    return std::to_string(static_cast<int>(ev.category)) + "|" +
           std::to_string(static_cast<int>(ev.action)) + "|" +
           ev.actor.name + "|" + ev.target.path;
}

bool Aggregator::process(AuditEvent& ev) {
    std::lock_guard<std::mutex> lk(mtx_);
    auto k = agg_key(ev);
    auto it = buckets_.find(k);
    auto now = Clock::now();
    if (it == buckets_.end() || (now - it->second.first) > window_) {
        if (it != buckets_.end() && !it->second.events.empty()) {
            // 立即发出摘要
            AuditEvent sum = it->second.events.front();
            sum.message = "[aggregated " + std::to_string(it->second.events.size()) + " events] " + sum.message;
            sum.attrs["aggregated_count"] = std::to_string(it->second.events.size());
            if (sum.command.empty()) sum.command = it->second.events.back().command;
            ev = std::move(sum);
            buckets_.erase(it);
        }
        buckets_[k] = { {ev}, now, now };
        return true;
    }
    it->second.events.push_back(ev);
    it->second.last = now;
    if (it->second.events.size() >= max_) {
        AuditEvent sum = it->second.events.front();
        sum.message = "[aggregated " + std::to_string(it->second.events.size()) + " events] " + sum.message;
        sum.attrs["aggregated_count"] = std::to_string(it->second.events.size());
        ev = std::move(sum);
        buckets_.erase(it);
    }
    return true;
}

void Aggregator::flush(std::function<void(AuditEvent&&)> emit) {
    std::lock_guard<std::mutex> lk(mtx_);
    for (auto& [k, b] : buckets_) {
        if (b.events.empty()) continue;
        AuditEvent sum = b.events.front();
        sum.message = "[aggregated " + std::to_string(b.events.size()) + " events] " + sum.message;
        sum.attrs["aggregated_count"] = std::to_string(b.events.size());
        emit(std::move(sum));
    }
    buckets_.clear();
}

// =====================================================================
// PIIMasker
// =====================================================================
PIIMasker::PIIMasker() {
    re_ = new std::regex(
        R"((password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?token)\s*[=:]\s*['"]?([^\s'";,]+))",
        std::regex_constants::icase);
}
PIIMasker::~PIIMasker() { delete static_cast<std::regex*>(re_); }

bool PIIMasker::process(AuditEvent& ev) {
    auto* re = static_cast<std::regex*>(re_);
    if (!ev.command.empty()) {
        ev.command = std::regex_replace(ev.command, *re, "$1=***REDACTED***");
    }
    if (!ev.message.empty()) {
        ev.message = std::regex_replace(ev.message, *re, "$1=***REDACTED***");
    }
    for (auto& [k, v] : ev.attrs) {
        v = std::regex_replace(v, *re, "$1=***REDACTED***");
    }
    return true;
}

// =====================================================================
// Normalizer（数据清洗与标准化）
// =====================================================================
namespace {
std::string norm_lower(std::string s) {
    for (auto& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}
// 小写匹配：文本是否包含任一关键词
bool norm_contains_any(const std::string& text, std::initializer_list<const char*> kws) {
    auto low = norm_lower(text);
    for (auto kw : kws) {
        if (low.find(kw) != std::string::npos) return true;
    }
    return false;
}
}  // namespace

bool Normalizer::process(AuditEvent& ev) {
    // 1. 时间规整：ts_micros 为 0 时从 timestamp 补算微秒粒度
    if (ev.ts_micros == 0) {
        ev.ts_micros = static_cast<u64>(std::chrono::duration_cast<std::chrono::microseconds>(
            ev.timestamp.time_since_epoch()).count());
    }
    // timestamp 仍为空（time_since_epoch 为 0）→ 用当前时间补全
    if (ev.ts_micros == 0) {
        ev.timestamp = SysClock::now();
        ev.ts_micros = static_cast<u64>(std::chrono::duration_cast<std::chrono::microseconds>(
            ev.timestamp.time_since_epoch()).count());
    }

    // 2. 来源标注：attrs[source] 缺失时标注为本机采集
    auto sit = ev.attrs.find(logmeta::attr::kSource);
    if (sit == ev.attrs.end() || sit->second.empty()) {
        ev.attrs[logmeta::attr::kSource] = "agent";
    }

    // 3. 字段补全：command 与 message 互补
    if (ev.command.empty() && !ev.message.empty()) {
        ev.command = ev.message;
    } else if (ev.message.empty() && !ev.command.empty()) {
        ev.message = ev.command;
    }

    // 4. action 推断：仅当 Unknown 时按 message/command 关键词推断
    if (ev.action == EventAction::Unknown) {
        const std::string& text = !ev.command.empty() ? ev.command : ev.message;
        if      (norm_contains_any(text, {"logoff", "logout"}))                    ev.action = EventAction::Logout;
        else if (norm_contains_any(text, {"login", "logon", "session open"}))      ev.action = EventAction::Login;
        else if (norm_contains_any(text, {"auth", "denied", "reject", "refus", "password"}))   ev.action = EventAction::AuthFail;
        else if (norm_contains_any(text, {"delete", "remove", "rm "}))             ev.action = EventAction::Delete;
        else if (norm_contains_any(text, {"exec", "cmd", "command"}))              ev.action = EventAction::Execute;
        else if (norm_contains_any(text, {"connect"}))                             ev.action = EventAction::Connect;
        else if (norm_contains_any(text, {"write", "modify", "insert", "update"})) ev.action = EventAction::Write;
        else if (norm_contains_any(text, {"read"}))                                ev.action = EventAction::Read;
        // 其余保留 Unknown
    }

    // 5. outcome 标准化：Unknown 时按关键词判定成功/失败
    if (ev.outcome == EventOutcome::Unknown) {
        const std::string& text = !ev.message.empty() ? ev.message : ev.command;
        if (norm_contains_any(text, {"fail", "denied", "error", "refus", "reject"}))
            ev.outcome = EventOutcome::Failure;
        else
            ev.outcome = EventOutcome::Success;
    }

    // 6. severity 推断：Info（默认值）时按 outcome/action 提升
    //    注意：syslog 已显式设置 severity（非 Info），不会被覆盖
    if (ev.severity == Severity::Info) {
        if (ev.outcome == EventOutcome::Failure || ev.outcome == EventOutcome::Denied ||
            ev.action == EventAction::AuthFail ||
            ev.action == EventAction::PrivilegeEsc) {
            ev.severity = Severity::Warning;
        } else if (ev.action == EventAction::Delete ||
                   ev.action == EventAction::Block ||
                   ev.action == EventAction::Quarantine ||
                   ev.action == EventAction::Kill) {
            ev.severity = Severity::Notice;
        }
    }

    return true;
}

// =====================================================================
// SchemaMapper（OCSF 子集映射，M6-1）
// =====================================================================
namespace {
// 读取 attrs 值，缺失时返回空串。
std::string get_attr(const AuditEvent& ev, const char* key) {
    auto it = ev.attrs.find(key);
    return it == ev.attrs.end() ? std::string() : it->second;
}

// 仅在缺失或为空时写入：保留采集器/适配器已显式设置的映射字段。
void set_attr_if_empty(AuditEvent& ev, const char* key, std::string value) {
    if (value.empty()) return;
    auto it = ev.attrs.find(key);
    if (it == ev.attrs.end() || it->second.empty()) ev.attrs[key] = std::move(value);
}

// OCSF severity_id：0=Unknown 1=Informational 2=Low 3=Medium 4=High 5=Critical 6=Fatal
int ocsf_severity_id(Severity s) {
    switch (s) {
        case Severity::Debug:     return 1;
        case Severity::Info:      return 1;
        case Severity::Notice:    return 2;
        case Severity::Warning:   return 3;
        case Severity::Error:     return 4;
        case Severity::Critical:  return 5;
        case Severity::Alert:     return 5;
        case Severity::Emergency: return 6;
    }
    return 0;
}

// 最小 JSON 字符串转义（metadata 为内嵌 JSON 文本）。
std::string schema_json_escape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\b': o += "\\b";  break;
            case '\f': o += "\\f";  break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            default:
                if (c < 0x20) {
                    static const char* hex = "0123456789abcdef";
                    o += "\\u00";
                    o += hex[(c >> 4) & 0xF];
                    o += hex[c & 0xF];
                } else {
                    o.push_back(static_cast<char>(c));
                }
        }
    }
    return o;
}

// 受管系统标识：优取 HTTP Host（补端口），其次目标地址，兜底 local（本机）。
std::string resolve_target_system(const AuditEvent& ev) {
    std::string sys = get_attr(ev, logmeta::attr::kHttpHost);
    if (sys.empty()) sys = ev.target.address;
    if (sys.empty()) return "local";
    if (ev.target.port != 0 && sys.find(':') == std::string::npos) {
        sys += ":" + std::to_string(ev.target.port);
    }
    return sys;
}

// 对象标识：优先资源路径，其次 HTTP URI，再次目标地址。
std::string resolve_object(const AuditEvent& ev) {
    if (!ev.target.path.empty()) return ev.target.path;
    std::string uri = get_attr(ev, logmeta::attr::kHttpUri);
    if (!uri.empty()) return uri;
    if (!ev.target.address.empty()) {
        std::string obj = ev.target.address;
        if (ev.target.port != 0) obj += ":" + std::to_string(ev.target.port);
        return obj;
    }
    return {};
}

// ---------------- 动作归一化辅助 ----------------

bool ci_equal(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) return false;
    }
    return true;
}

bool ci_contains(const std::string& hay, const std::string& needle) {
    if (needle.empty() || hay.size() < needle.size()) return false;
    const std::string h = [&] {
        std::string s = hay;
        for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return s;
    }();
    std::string n = needle;
    for (auto& c : n) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return h.find(n) != std::string::npos;
}

// 路径切段：按 / 与 ? 分割，剔除空段、api 前缀、版本号与纯数字 ID。
std::vector<std::string> path_segments(const std::string& uri) {
    std::vector<std::string> out;
    std::string cur;
    auto flush = [&] {
        if (cur.empty()) return;
        std::string low;
        low.reserve(cur.size());
        for (char c : cur) low.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        const bool is_version = low.size() > 1 && low[0] == 'v' &&
                                low.find_first_not_of("0123456789", 1) == std::string::npos;
        const bool is_id = low.find_first_not_of("0123456789") == std::string::npos;
        if (low != "api" && low != "rest" && low != "v1" && !is_version && !is_id) {
            out.push_back(low);
        }
        cur.clear();
    };
    for (char c : uri) {
        if (c == '/' || c == '?' || c == '&' || c == '=') flush();
        else cur.push_back(c);
    }
    flush();
    return out;
}

// 路径段中的"纯行为词"：只表示"做了什么"，不表示"对什么做"。
// 注意不要把 backup / snapshot / key / volume 这类实体词放进来：
// 它们既能当名词也能当动词（/api/backup 是"备份资源"，不是"做备份"），
// 一律按实体处理，动作由 HTTP 方法给出，才得到 delete.backup 而不是 backup.unknown。
const char* verb_of_token(const std::string& tok) {
    static const char* kVerbs[] = {
        "unmount", "detach", "mount", "attach", "restart", "stop", "start",
        "clear", "purge", "clean", "restore", "recover", "export", "download",
        "dump", "grant", "privilege", "assign", "distribute", "generate",
        "exec", "execute", "rotate", "revoke", "login", "logout"
    };
    for (const char* v : kVerbs) {
        if (tok == v) return v;
    }
    // 英文动词的常见变形（deleted / deletion / removing ...）做前缀收敛
    static const char* kPrefix[] = {
        "delet", "remov", "unmount", "detach", "restart", "clear", "pur",
        "clean", "restor", "export", "download", "dump", "grant", "privileg",
        "assign", "distribut", "generat", "execut", "rotat", "revok"
    };
    for (const char* p : kPrefix) {
        if (tok.rfind(p, 0) == 0) return p;
    }
    return nullptr;
}

// 路径段中的"实体词"：表示对什么做，归一为单数规范名。
std::string entity_of_token(const std::string& tok) {
    struct Alias { const char* from; const char* to; };
    static const Alias kAliases[] = {
        {"books", "book"}, {"book", "book"},
        {"backups", "backup"}, {"backup", "backup"}, {"bak", "backup"},
        {"snapshots", "snapshot"}, {"snapshot", "snapshot"},
        {"volumes", "volume"}, {"volume", "volume"}, {"storage", "volume"},
        {"logs", "logs"}, {"log", "logs"},
        {"configs", "config"}, {"config", "config"}, {"configuration", "config"},
        {"settings", "config"}, {"setting", "config"},
        {"keys", "key"}, {"key", "key"}, {"secrets", "key"}, {"secret", "key"},
        {"certs", "key"}, {"cert", "key"},
        {"users", "user"}, {"user", "user"},
        {"audits", "audit"}, {"audit", "audit"},
        {"services", "service"}, {"service", "service"},
        {"systems", "system"}, {"system", "system"},
        {"admins", "admin"}, {"admin", "admin"},
        {"database", "db"}, {"databases", "db"}, {"db", "db"}, {"data", "db"},
        {"privileges", "privilege"}, {"privilege", "privilege"},
        {"roles", "role"}, {"role", "role"}
    };
    for (const auto& a : kAliases) {
        if (tok == a.from) return a.to;
    }
    return {};
}

// 路径语义动作：/api/backup/3 (DELETE) → delete.backup
//             /api/storage/volume/1/unmount → unmount.volume
//             /api/system/logs/clear       → clear.logs
//             /api/admin/exec + body action=purge_books → exec.purge_books
std::string norm_from_uri(const std::string& uri, const std::string& method,
                          const std::string& body) {
    auto segs = path_segments(uri);
    std::string verb;
    std::string object;

    // 从后往前找动作词：最后一个动作词即真正的语义动作
    for (std::size_t i = segs.size(); i > 0; --i) {
        const char* v = verb_of_token(segs[i - 1]);
        if (v) {
            verb = v;
            // 动词 -> 规范形
            if (verb == "privilege") verb = "grant";
            if (verb == "execut")    verb = "exec";
            if (verb == "delet")     verb = "delete";
            if (verb == "remov")     verb = "delete";
            if (verb == "unmount")   verb = "unmount";
            if (verb == "clean")     verb = "clear";
            if (verb == "pur")       verb = "clear";
            if (verb == "restor")    verb = "restore";
            if (verb == "updat")     verb = "update";
            if (verb == "generat")   verb = "create";
            if (verb == "distribut") verb = "distribute";
            // 实体取动作词之前的最近实体；没有则继续向后找
            for (std::size_t k = i - 1; k > 0; --k) {
                object = entity_of_token(segs[k - 1]);
                if (!object.empty()) break;
            }
            // 动作词出现在最前（如 /api/exec/...）时，实体可能在其后
            if (object.empty()) {
                for (std::size_t k = i; k < segs.size(); ++k) {
                    object = entity_of_token(segs[k]);
                    if (!object.empty()) break;
                }
            }
            break;
        }
    }

    // 无路径动作词：动词由 HTTP 方法决定，实体取**最后**一个实体词
    // （/api/system/config → update.config，而不是 update.system）
    if (verb.empty()) {
        const std::string m = [&] {
            std::string s = method;
            for (auto& c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
            return s;
        }();
        if      (m == "DELETE")              verb = "delete";
        else if (m == "POST")                verb = "create";
        else if (m == "PUT" || m == "PATCH") verb = "update";
        else if (m == "GET" || m == "HEAD")  verb = "read";
        else                                 verb = "call";
        for (const auto& s : segs) {
            std::string e = entity_of_token(s);
            if (!e.empty()) object = e;
        }
    }

    // audit 是"被审计对象的审计记录"，单说 clear.audit 会混淆"清书籍审计"与"清密钥审计"，
    // 需要带上限定词：/api/books/audit/clear → clear.book_audit。
    if (object == "audit") {
        std::string qualifier;
        for (const auto& s : segs) {
            std::string e = entity_of_token(s);
            if (e.empty() || e == "audit") continue;
            qualifier = e;
        }
        if (!qualifier.empty()) object = qualifier + "_audit";
    }

    // exec 类接口把具体动作放在请求体里：{"action":"purge_books"}
    if (verb == "exec" && !body.empty()) {
        const std::string key = "\"action\"";
        auto p = body.find(key);
        if (p != std::string::npos) {
            auto q = body.find('"', p + key.size() + 1);
            if (q != std::string::npos) {
                auto r = body.find('"', q + 1);
                if (r != std::string::npos && r > q + 1) {
                    std::string act = body.substr(q + 1, r - q - 1);
                    for (auto& c : act) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                    if (!act.empty()) object = act;
                }
            }
        }
    }

    if (object.empty()) object = "unknown";
    return verb + "." + object;
}

// 命令行/进程名语义动作：mountvol X: /D → unmount.volume
//                       vssadmin delete shadows → delete.backup
//                       wbadmin delete catalog  → delete.backup
std::string norm_from_command(const std::string& text, const std::string& image) {
    const std::string t = text + " " + image;
    if (ci_contains(t, "vssadmin") && ci_contains(t, "delete"))                 return "delete.snapshot";
    if (ci_contains(t, "wbadmin") && ci_contains(t, "delete"))                  return "delete.backup";
    if (ci_contains(t, "mountvol"))                                             return "unmount.volume";
    if (ci_contains(t, "diskpart"))                                             return "unmount.volume";
    if (ci_contains(t, "bcdedit"))                                              return "update.config";
    if (ci_contains(t, "reg ") && ci_contains(t, "delete"))                      return "delete.config";
    if (ci_contains(t, "sc ") && (ci_contains(t, "stop") || ci_contains(t, "delete")))
                                                                                return "stop.service";
    if (ci_contains(t, "net user") && ci_contains(t, "/add"))                    return "create.user";
    if (ci_contains(t, "net localgroup") && ci_contains(t, "add"))               return "assign.admin";
    if ((ci_contains(t, "del ") || ci_contains(t, "rm ") || ci_contains(t, "erase ")) &&
        (ci_contains(t, ".bak") || ci_contains(t, "backup") || ci_contains(t, "备份")))
                                                                                return "delete.backup";
    if (ci_contains(t, "log clear") || ci_contains(t, "wevtutil cl"))            return "clear.logs";
    if (ci_contains(t, "taskkill") || ci_contains(t, "net stop"))                return "stop.service";
    if (ci_contains(t, "purge") || ci_contains(t, "truncate"))                   return "clear.db";
    if (ci_contains(t, "export") || ci_contains(t, "mysqldump") || ci_contains(t, "pg_dump"))
                                                                                return "export.db";
    return {};
}

}  // namespace

bool ActionNormalizer::process(AuditEvent& ev) {
    // 采集器或适配器已显式给出归一动作时不覆盖（便于测试注入与外部系统直报）
    if (!get_attr(ev, logmeta::attr::kActionNorm).empty()) return true;

    const std::string collector = logmeta::collector_id(ev);
    const bool is_http = collector == logmeta::collector::kHttpProxy ||
                         !get_attr(ev, logmeta::attr::kHttpUri).empty();

    std::string norm;
    if (is_http) {
        std::string uri = get_attr(ev, logmeta::attr::kHttpUri);
        if (uri.empty()) uri = ev.target.path;
        const std::string method = get_attr(ev, logmeta::attr::kHttpMethod);
        norm = norm_from_uri(uri, method, get_attr(ev, logmeta::attr::kHttpReqBody));
    } else {
        // 进程/命令/文件类：优先命令行，其次 message + 进程名
        std::string text = get_attr(ev, logmeta::attr::kCommandLine);
        if (text.empty()) text = ev.command.empty() ? ev.message : ev.command;
        norm = norm_from_command(text, ev.actor.name);
        if (norm.empty()) {
            // 文件类事件：按目标路径与 action 收敛
            const std::string path = ev.target.path;
            if (!path.empty()) {
                std::string object;
                if (ci_contains(path, "backup") || ci_contains(path, ".bak") || ci_contains(path, "备份"))
                    object = "backup";
                else if (ci_contains(path, "snapshot") || ci_contains(path, "快照")) object = "snapshot";
                else if (ci_contains(path, ".conf") || ci_contains(path, ".ini") ||
                         ci_contains(path, ".yaml") || ci_contains(path, ".yml") ||
                         ci_contains(path, "config")) object = "config";
                else if (ci_contains(path, ".log")) object = "logs";
                if (!object.empty()) {
                    norm = std::string(to_string(ev.action)) + "." + object;
                }
            }
        }
    }

    if (norm.empty()) {
        // 兜底：category/action 两级，保证每条事件都有可匹配的动作名
        norm = std::string(to_string(ev.action)) + ".unknown";
    }
    ev.attrs[logmeta::attr::kActionNorm] = norm;
    return true;
}

// =====================================================================
// SchemaMapper（OCSF 子集映射，M6-1）
// =====================================================================
bool SchemaMapper::process(AuditEvent& ev) {
    // 1. actor：操作员身份优先，其次登录用户，再次进程名（M7 图谱以操作员为主键）
    std::string actor = get_attr(ev, logmeta::attr::kOperatorId);
    if (actor.empty()) actor = ev.actor.user;
    if (actor.empty()) actor = ev.actor.name;
    set_attr_if_empty(ev, logmeta::attr::kSchemaActor, std::move(actor));

    // 2. activity_name：复用 EventAction 规范名（read/create/delete...），与规则引擎口径一致
    set_attr_if_empty(ev, logmeta::attr::kSchemaActivityName, to_string(ev.action));

    // 3. object / target_system：规则与图谱将按资产画像解释这两个字段（M6-2）
    set_attr_if_empty(ev, logmeta::attr::kSchemaObject, resolve_object(ev));
    set_attr_if_empty(ev, logmeta::attr::kSchemaTargetSystem, resolve_target_system(ev));

    // 4. outcome / severity_id：统一结果与数值严重度
    set_attr_if_empty(ev, logmeta::attr::kSchemaOutcome, to_string(ev.outcome));
    set_attr_if_empty(ev, logmeta::attr::kSchemaSeverityId,
                      std::to_string(ocsf_severity_id(ev.severity)));

    // 5. metadata：OCSF 风格元数据（JSON 文本），时间戳保持微秒粒度
    std::ostringstream m;
    m << "{\"version\":\"1.1.0\",\"product\":\"AuditForwarder\"";
    auto add_str = [&](const char* key, const std::string& value) {
        if (value.empty()) return;
        m << ",\"" << key << "\":\"" << schema_json_escape(value) << '"';
    };
    add_str("collector",   get_attr(ev, logmeta::attr::kCollector));
    add_str("source",      get_attr(ev, logmeta::attr::kSource));
    add_str("host",        ev.host);
    add_str("agent_id",    ev.agent_id);
    add_str("operator_id", get_attr(ev, logmeta::attr::kOperatorId));
    m << ",\"logged_time_us\":" << ev.ts_micros;
    m << ",\"schema_ver\":" << ev.schema_ver << '}';
    set_attr_if_empty(ev, logmeta::attr::kSchemaMetadata, m.str());

    return true;
}

}  // namespace af::processor
