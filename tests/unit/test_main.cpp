// Unit tests for AuditForwarder core utilities.

#include "auditforwarder/agent.h"
#include "auditforwarder/build_config.h"
#include "auditforwarder/chain.h"
#include "auditforwarder/config.h"
#include "auditforwarder/crypto.h"
#include "auditforwarder/database.h"
#include "auditforwarder/event.h"
#include "auditforwarder/fs.h"
#include "auditforwarder/logger.h"
#include "auditforwarder/log_meta.h"
#include "auditforwarder/process.h"
#include "auditforwarder/thread_pool.h"
#include "manager/log_policy_util.h"

#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include <thread>

namespace {

int passed = 0, failed = 0;

#define AF_EXPECT(cond)                                                      \
    do {                                                                      \
        if (cond) { ++passed; std::printf("[ok]   %s\n", #cond); }            \
        else      { ++failed; std::printf("[FAIL] %s (line %d)\n",            \
                                  #cond, __LINE__); }                         \
    } while (0)

#define AF_EXPECT_EQ(a, b)                                                   \
    do {                                                                      \
        auto _a = (a); auto _b = (b);                                         \
        if (_a == _b) { ++passed; std::printf("[ok]   %s == %s\n",            \
            #a, #b); }                                                       \
        else { ++failed; std::printf("[FAIL] %s != %s (line %d)\n",           \
            #a, #b, __LINE__); }                                              \
    } while (0)

void test_types_and_string_conversion() {
    using namespace af;
    AF_EXPECT_EQ(af::to_string(Severity::Info), std::string("info"));
    AF_EXPECT_EQ(severity_from_string("warning"), Severity::Warning);
    AF_EXPECT_EQ(af::to_string(EventCategory::Process), std::string("process"));
    AF_EXPECT_EQ(category_from_string("network"), EventCategory::Network);
    AF_EXPECT_EQ(af::to_string(EventAction::Execute), std::string("execute"));
    AF_EXPECT_EQ(action_from_string("kill"), EventAction::Kill);
    AF_EXPECT_EQ(af::to_string(EventOutcome::Success), std::string("success"));
}

void test_crypto_hash_and_sign() {
    using namespace af::crypto;
    auto h1 = sha256_hex("hello");
    auto h2 = sha256_hex("hello");
    AF_EXPECT_EQ(h1, h2);
    AF_EXPECT_EQ(h1.size(), (std::size_t)64);

    auto kp = KeyPair::generate(KeyPair::Algorithm::Ed25519);
    AF_EXPECT(kp.is_ok());
    auto msg = std::string("the quick brown fox");
    auto sig = kp.value().sign_hex(msg);
    AF_EXPECT(kp.value().verify_hex(msg, sig));
    AF_EXPECT(!kp.value().verify_hex(msg + "X", sig));
}

void test_crypto_aead_roundtrip() {
    using namespace af::crypto;
    auto key = random_bytes(32);
    std::string pt_string = "classified payload";
    af::ByteBuffer pt(pt_string.begin(), pt_string.end());
    auto enc = aes_gcm_encrypt(key, pt);
    AF_EXPECT_EQ(enc.error, 0);
    auto dec = aes_gcm_decrypt(key, enc);
    AF_EXPECT(dec.is_ok());
    AF_EXPECT_EQ(std::string(dec.value().begin(), dec.value().end()), pt_string);

    // Tamper with ciphertext -> should fail
    enc.ciphertext[0] ^= 0x55;
    auto dec2 = aes_gcm_decrypt(key, enc);
    AF_EXPECT(dec2.is_err());
}

void test_crypto_merkle_proof() {
    using namespace af::crypto;
    std::vector<af::ByteBuffer> leaves;
    for (int i = 0; i < 8; ++i) {
        std::string s = std::to_string(i);
        leaves.emplace_back(s.begin(), s.end());
    }
    MerkleTree tree(std::move(leaves));
    auto root = tree.root_hex();
    AF_EXPECT_EQ(root.size(), (std::size_t)64);
    auto proof = tree.proof(3);
    std::string s3 = std::to_string(3);
    std::string s4 = std::to_string(4);
    AF_EXPECT(MerkleTree::verify(root, af::ByteBuffer(s3.begin(), s3.end()), 3, proof));
    AF_EXPECT(!MerkleTree::verify(root, af::ByteBuffer(s4.begin(), s4.end()), 3, proof));
}

void test_config_load_yaml() {
    using namespace af;
    std::string yaml = R"(
agent:
  id: test-1
  data_dir: /var/lib/af
log:
  level: debug
server:
  urls:
    - https://a.example.com
    - https://b.example.com
)";
    auto r = Config::instance().load_from_string(yaml, "yaml");
    AF_EXPECT(r.is_ok());
    AF_EXPECT_EQ(Config::instance().get_string("agent.id"), std::string("test-1"));
    AF_EXPECT_EQ(Config::instance().get_string("log.level"), std::string("debug"));
    AF_EXPECT_EQ(Config::instance().get_int("server.urls.size"), 0);
}

void test_config_load_json() {
    using namespace af;
    std::string json = R"({"a":{"b":{"c":42}},"list":[1,2,3]})";
    auto r = Config::instance().load_from_string(json, "json");
    AF_EXPECT(r.is_ok());
    AF_EXPECT_EQ(Config::instance().get_int("a.b.c"), 42);
    AF_EXPECT_EQ(Config::instance().get_int("list.size"), 0);
}

void test_event_json_roundtrip() {
    using namespace af;
    AuditEvent ev;
    ev.id = 42;
    ev.seq = 1;
    ev.category = EventCategory::File;
    ev.action   = EventAction::Write;
    ev.outcome  = EventOutcome::Success;
    ev.host     = "host-1";
    ev.actor.pid = 1234;
    ev.actor.name = "bash";
    ev.actor.user = "root";
    ev.target.path = "/etc/passwd";
    ev.command = "echo hi";
    ev.message = "file write /etc/passwd";
    auto s = ev.to_json();
    AF_EXPECT(s.find("\"file\"") != std::string::npos);
    AF_EXPECT(s.find("\"bash\"") != std::string::npos);
    AF_EXPECT(s.find("\"root\"") != std::string::npos);
    AF_EXPECT(s.find("\"write\"") != std::string::npos);
}

void test_log_meta_contract() {
    using namespace af;
    namespace lm = af::logmeta;

    // 采集器打标 / 读取 / ETW 识别
    AuditEvent ev;
    AF_EXPECT_EQ(lm::collector_id(ev), std::string(lm::collector::kUnknown));
    AF_EXPECT(!lm::is_etw(ev));
    lm::tag_collector(ev, lm::collector::kEtwWin);
    ev.attrs[lm::attr::kSource] = lm::source::kEtwSecurity;
    AF_EXPECT_EQ(lm::collector_id(ev), std::string(lm::collector::kEtwWin));
    AF_EXPECT(lm::is_etw(ev));

    // 高权限标注
    AuditEvent ev2;
    AF_EXPECT(!lm::is_high_priority(ev2));
    AF_EXPECT_EQ(lm::privilege_level_of(ev2), std::string(lm::priv::kNone));
    lm::mark_privileged(ev2, lm::priv::kSystem);
    AF_EXPECT(lm::is_high_priority(ev2));
    AF_EXPECT_EQ(ev2.attrs[lm::attr::kPriority], std::string(lm::priority::kHigh));
    AF_EXPECT_EQ(ev2.attrs[lm::attr::kPrivLevel], std::string(lm::priv::kSystem));
    AF_EXPECT_EQ(ev2.attrs[lm::attr::kPrivOperation], std::string("1"));
    AF_EXPECT(!ev2.attrs[lm::attr::kPrivTs].empty());
    AF_EXPECT(ev2.severity == Severity::Warning);  // Info 被提升到 Warning

    // client_ts 时间戳为纯数字毫秒
    AuditEvent ev3;
    lm::stamp_client_ts(ev3);
    const auto& ts = ev3.attrs[lm::attr::kClientTs];
    AF_EXPECT(!ts.empty());
    AF_EXPECT(std::all_of(ts.begin(), ts.end(), [](char c){ return c >= '0' && c <= '9'; }));

    // 采集器名安全化
    AF_EXPECT_EQ(lm::sanitize_collector_id("etw_win"), std::string("etw_win"));
    AF_EXPECT_EQ(lm::sanitize_collector_id("../evil"), std::string("___evil"));
    AF_EXPECT_EQ(lm::sanitize_collector_id(""), std::string(lm::collector::kUnknown));
    AF_EXPECT_EQ(lm::sanitize_collector_id("etw-win"), std::string("etw_win"));

    // 元数据进入 canonical JSON（/ingest 路径完整性）
    AuditEvent ev4;
    lm::tag_collector(ev4, lm::collector::kEtwWin);
    ev4.attrs[lm::attr::kSource] = lm::source::kEtwSecurity;
    lm::mark_privileged(ev4, lm::priv::kElevated);
    const std::string j = ev4.to_json();
    AF_EXPECT(j.find("\"collector\":\"etw_win\"") != std::string::npos);
    AF_EXPECT(j.find("\"source\":\"etw_security\"") != std::string::npos);
    AF_EXPECT(j.find("\"priority\":\"high\"") != std::string::npos);
    AF_EXPECT(j.find("\"priv_level\":\"elevated\"") != std::string::npos);

    // 批次级高优先级判定（传输双队列分流依据）
    EventBatch b0;
    b0.events = {AuditEvent{}, AuditEvent{}};
    AF_EXPECT(!lm::batch_is_high_priority(b0));
    EventBatch b1;
    AuditEvent hi;
    lm::mark_privileged(hi, lm::priv::kElevated);
    b1.events = {AuditEvent{}, std::move(hi)};
    AF_EXPECT(lm::batch_is_high_priority(b1));
}

void test_privilege_detection() {
    using namespace af;
    namespace lm = af::logmeta;

    // /proc/<pid>/status 的 Uid 行解析（Linux 语义，跨平台可测）
    AF_EXPECT_EQ(proc::priv_level_from_status_uid_line("Uid:\t0\t0\t0\t0"), std::string(lm::priv::kRoot));
    AF_EXPECT_EQ(proc::priv_level_from_status_uid_line("Uid:\t1000\t1000\t1000\t1000"), std::string(lm::priv::kNone));
    AF_EXPECT_EQ(proc::priv_level_from_status_uid_line("Name:\tbash"), std::string(lm::priv::kNone));

    // 对当前进程：privilege_level 必须与 is_elevated() 自洽
    const std::string lvl = proc::privilege_level(proc::current_pid());
    if (proc::is_elevated()) {
        AF_EXPECT(lvl == lm::priv::kRoot || lvl == lm::priv::kElevated || lvl == lm::priv::kSystem);
    } else {
        AF_EXPECT_EQ(lvl, std::string(lm::priv::kNone));
    }

    // 不存在的 PID 静默返回 none
    AF_EXPECT_EQ(proc::privilege_level(0x7FFFFFFFu), std::string(lm::priv::kNone));
}

void test_thread_pool_priority() {
    using namespace af;
    ThreadPool pool(2);
    pool.start(2);
    std::atomic<int> order{0};
    std::vector<int> seq;
    std::mutex m;
    auto a = pool.submit([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        std::lock_guard<std::mutex> lk(m);
        seq.push_back(1);
    });
    auto b = pool.submit([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        std::lock_guard<std::mutex> lk(m);
        seq.push_back(2);
    }, ThreadPool::Priority::High);
    a.wait(); b.wait();
    AF_EXPECT_EQ(seq.size(), (std::size_t)2);
    AF_EXPECT(std::find(seq.begin(), seq.end(), 1) != seq.end());
    AF_EXPECT(std::find(seq.begin(), seq.end(), 2) != seq.end());
    pool.shutdown();
}

void test_chain_submission_and_signing() {
    using namespace af;
    chain::ChainConfig cfg;
    cfg.data_dir = ".";
    cfg.batch_size = 64;
    cfg.auto_persist = false;
    chain::Chain ch(cfg);
    ch.start();
    ch.set_hmac_key("test-key");

    for (int i = 0; i < 5; ++i) {
        AuditEvent ev;
        ev.category = EventCategory::Process;
        ev.action   = EventAction::Spawn;
        ev.actor.pid = 1000 + i;
        ev.target.path = "/usr/bin/test";
        ch.submit(ev);
    }
    auto b = ch.flush();
    AF_EXPECT(b.is_ok());
    AF_EXPECT_EQ(b.value().events.size(), (std::size_t)5);
    AF_EXPECT(ch.verify_batch(b.value(), "test-key"));
    AF_EXPECT(!ch.verify_batch(b.value(), "wrong-key"));
}

void test_path_utilities() {
    using namespace af::fs;
    AF_EXPECT_EQ(basename("/etc/hosts"), std::string("hosts"));
    AF_EXPECT_EQ(basename("C:\\Windows\\hosts"), std::string("hosts"));
#ifdef AF_PLATFORM_WINDOWS
    AF_EXPECT_EQ(dirname("/etc/hosts"), std::string("\\etc"));
    AF_EXPECT_EQ(normalize("a//b"), std::string("a\\b"));
#else
    AF_EXPECT_EQ(dirname("/etc/hosts"), std::string("/etc"));
    AF_EXPECT_EQ(normalize("a//b"), std::string("a/b"));
#endif
    AF_EXPECT_EQ(extension("a.tar.gz"), std::string(".gz"));
}

void test_database_validation_and_crud() {
    using namespace af::db;

    InMemoryDatabaseStore store;

    AdminUser admin;
    admin.user_id = "11111111-1111-4111-8111-111111111111";
    admin.username = "admin";
    admin.password_hash = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$YmFzZTY0aGFzaA";
    admin.role_code = "admin";
    admin.permission_level = 100;
    AF_EXPECT(store.create_admin(admin).is_ok());
    AF_EXPECT(store.create_admin(admin).is_err());

    auto loaded_admin = store.get_admin_by_username("ADMIN");
    AF_EXPECT(loaded_admin.is_ok());
    AF_EXPECT(loaded_admin.value().has_value());
    AF_EXPECT_EQ(loaded_admin.value()->user_id, std::string("11111111-1111-4111-8111-111111111111"));

    AdminUser invalid_admin = admin;
    invalid_admin.user_id = "bad clear";
    invalid_admin.password_hash = "admin123";
    AF_EXPECT(Validator::validate_admin(invalid_admin).is_err());

    HostInfo host;
    host.host_id = "host-001";
    host.host_name = "测试主机";
    host.ip_address = "127.0.0.1";
    host.port = 8443;
    host.os_type = "Windows";
    host.os_version = "Windows 11";
    host.hardware_info_json = R"({"cpu_threads":8,"memory":"16GB"})";
    host.online_status = HostOnlineStatus::Online;
    AF_EXPECT(store.upsert_host(host).is_ok());

    HostLog log;
    log.host_id = "host-001";
    log.log_type = "security";
    log.log_content = "用户登录成功";
    log.generated_at = "2026-07-03T12:00:00Z";
    log.metadata_json = R"({"collector":"win_event"})";
    auto log_id = store.create_log(log);
    AF_EXPECT(log_id.is_ok());

    LogQuery query;
    query.host_id = "host-001";
    query.log_type = "security";
    auto logs = store.query_logs(query);
    AF_EXPECT(logs.is_ok());
    AF_EXPECT_EQ(logs.value().size(), (std::size_t)1);

    AF_EXPECT(store.update_log_status(log_id.value(), LogStatus::Parsed).is_ok());
    auto loaded_log = store.get_log(log_id.value());
    AF_EXPECT(loaded_log.is_ok());
    AF_EXPECT(loaded_log.value().has_value());
    AF_EXPECT_EQ(to_string(loaded_log.value()->status), std::string("parsed"));
}

// 统计 JSON 文本中 "key": 字段出现次数（测试数据值中不含该模式）。
std::size_t count_json_key_tokens(const std::string& s) {
    static const std::string token = "\":";
    std::size_t n = 0, pos = 0;
    while ((pos = s.find(token, pos)) != std::string::npos) { ++n; pos += token.size(); }
    return n;
}

void test_log_filter_profiles() {
    namespace lp = af::logpolicy;
    const std::string def = lp::default_profiles_json();

    // 默认策略：etw_win 精确命中宽松档；其他采集器走 default 严格档
    lp::Profile etw = lp::resolve_profile_json(def, lp::kEtwCollector);
    AF_EXPECT_EQ(etw.mode, std::string(lp::kModeLenient));
    AF_EXPECT_EQ(etw.message_max_len, (std::size_t)8192);
    AF_EXPECT_EQ(etw.retention_lines, (std::size_t)50000);
    AF_EXPECT_EQ(etw.drop_fields.size(), (std::size_t)0);
    lp::Profile filep = lp::resolve_profile_json(def, "file_win");
    AF_EXPECT_EQ(filep.mode, std::string(lp::kModeStrict));
    AF_EXPECT_EQ(filep.message_max_len, (std::size_t)512);
    AF_EXPECT_EQ(filep.drop_fields.size(), (std::size_t)1);
    AF_EXPECT_EQ(filep.drop_fields[0], std::string("raw_xml"));

    // 配置缺失时内置兜底：etw 宽松、其余严格
    AF_EXPECT_EQ(lp::resolve_profile_json("", "etw_win").mode, std::string(lp::kModeLenient));
    lp::Profile builtin_strict = lp::resolve_profile_json("{}", "process_win");
    AF_EXPECT_EQ(builtin_strict.mode, std::string(lp::kModeStrict));
    AF_EXPECT_EQ(builtin_strict.message_max_len, (std::size_t)512);

    // 自定义配置：精确命中优先于 default；缺 mode 回落 strict
    const std::string custom =
        R"({"profiles":[)"
        R"({"collector":"network_win","mode":"lenient","message_max_len":4096,)"
        R"("drop_fields":[],"retention_lines":1234},)"
        R"({"collector":"default","drop_fields":["a","b"]}]})";
    lp::Profile net = lp::resolve_profile_json(custom, "network_win");
    AF_EXPECT_EQ(net.mode, std::string("lenient"));
    AF_EXPECT_EQ(net.message_max_len, (std::size_t)4096);
    AF_EXPECT_EQ(net.retention_lines, (std::size_t)1234);
    lp::Profile cmd = lp::resolve_profile_json(custom, "command_win");
    AF_EXPECT_EQ(cmd.mode, std::string("strict"));
    AF_EXPECT_EQ(cmd.drop_fields.size(), (std::size_t)2);

    // json_remove_field：首/中/尾字段删除后逗号处理正确，结构保持合法
    AF_EXPECT_EQ(lp::json_remove_field(std::string(R"({"a":1,"b":2,"c":3})"), "b"),
                 std::string(R"({"a":1,"c":3})"));
    AF_EXPECT_EQ(lp::json_remove_field(std::string(R"({"b":2,"c":3})"), "b"),
                 std::string(R"({"c":3})"));
    AF_EXPECT_EQ(lp::json_remove_field(std::string(R"({"a":1,"b":2})"), "b"),
                 std::string(R"({"a":1})"));
    AF_EXPECT_EQ(lp::json_remove_field(std::string(R"({"a":1})"), "zzz"),
                 std::string(R"({"a":1})"));
    // 嵌套 attrs 对象内字段可命中，兄弟字段保留
    const std::string nested = R"({"a":1,"attrs":{"raw_xml":"<X/>","keep":"y"}})";
    const std::string nested_out = lp::json_remove_field(nested, "raw_xml");
    AF_EXPECT(nested_out.find("raw_xml") == std::string::npos);
    AF_EXPECT(nested_out.find(R"("keep":"y")") != std::string::npos);
    // 字符串值中形如 \"b\" 的转义内容不会被误删，真实字段被删除且值完整保留
    const std::string escaped = R"({"msg":"x,\"b\":9","b":2})";
    AF_EXPECT_EQ(lp::json_remove_field(escaped, "b"),
                 std::string(R"({"msg":"x,\"b\":9"})"));
    // 值里含其他转义序列时，真实字段仍可删除
    AF_EXPECT_EQ(lp::json_remove_field(std::string(R"({"msg":"x\"y","b":2})"), "b"),
                 std::string(R"({"msg":"x\"y"})"));

    // truncate：短文本不变；长文本截断后 JSON 仍闭合；转义序列整体保留
    const std::string short_msg = R"({"message":"abc"})";
    AF_EXPECT_EQ(lp::json_truncate_string_field(short_msg, "message", 10), short_msg);
    const std::string long_msg =
        std::string(R"({"message":")") + std::string(100, 'z') + R"("})";
    const std::string cut = lp::json_truncate_string_field(long_msg, "message", 10);
    AF_EXPECT(cut.size() < long_msg.size());
    AF_EXPECT(cut[cut.size() - 1] == '}');
    AF_EXPECT(cut[cut.size() - 2] == '"');
    AF_EXPECT(cut.find(std::string(11, 'z')) == std::string::npos);
    const std::string esc_msg = R"({"message":"line1\nline2\nline3"})";
    const std::string esc_cut = lp::json_truncate_string_field(esc_msg, "message", 7);
    AF_EXPECT(esc_cut[esc_cut.size() - 2] == '"');
    AF_EXPECT(esc_cut.find('\\') != std::string::npos);

    // apply_profile 端到端：同一富事件经 lenient / strict 两档处理
    const std::string record =
        std::string(R"({"timestamp":"2026-09-17T00:00:00Z","host_id":"h1",)"
                    R"("collector":"etw_win","priority":"normal","message":")")
        + std::string(1000, 'z')
        + R"(","attrs":{"event_id":"4688","subject_user":"u","subject_domain":"d",)"
          R"("logon_id":"0x1","process_name":"p.exe","raw_xml":"<Event/>",)"
          R"("raw_payload":"PAYLOAD","extra1":"e1","extra2":"e2"}})";
    const std::size_t fields_before = count_json_key_tokens(record);
    AF_EXPECT_EQ(fields_before, (std::size_t)15);  // 14 个叶子字段 + attrs 对象键

    lp::Profile lenient = lp::resolve_profile_json(def, "etw_win");
    const std::string etw_out = lp::apply_profile(record, lenient);
    AF_EXPECT(etw_out.find("raw_xml") != std::string::npos);          // 宽松档保留原始载荷
    AF_EXPECT(etw_out.find(std::string(1000, 'z')) != std::string::npos);  // 8192 上限不截断

    lp::Profile strict_default = lp::resolve_profile_json(def, "file_win");
    const std::string strict_out = lp::apply_profile(record, strict_default);
    AF_EXPECT(strict_out.find("raw_xml") == std::string::npos);       // 严格档丢 raw_xml
    AF_EXPECT(strict_out.find(std::string(1000, 'z')) == std::string::npos);  // 截断到 512

    // AC-3 机制量化：严格档丢弃 4 个字段后，宽松档字段数比严格档多 ≥30%
    lp::Profile strict_custom;
    strict_custom.mode = "strict";
    strict_custom.message_max_len = 8192;  // 只测字段丢弃，排除截断干扰
    strict_custom.drop_fields = {"raw_xml", "raw_payload", "extra1", "extra2"};
    const std::string strict_custom_out = lp::apply_profile(record, strict_custom);
    const std::size_t fields_lenient = count_json_key_tokens(etw_out);
    const std::size_t fields_strict = count_json_key_tokens(strict_custom_out);
    AF_EXPECT_EQ(fields_lenient, (std::size_t)15);
    AF_EXPECT_EQ(fields_strict, (std::size_t)11);  // 宽松/严格字段比 15/11 ≈ 1.36 ≥ 1.3
    AF_EXPECT(static_cast<double>(fields_lenient) >=
              1.3 * static_cast<double>(fields_strict));
}

}  // namespace

int main() {
    std::printf("AuditForwarder unit tests\n");
    test_types_and_string_conversion();
    test_crypto_hash_and_sign();
    test_crypto_aead_roundtrip();
    test_crypto_merkle_proof();
    test_config_load_yaml();
    test_config_load_json();
    test_event_json_roundtrip();
    test_log_meta_contract();
    test_privilege_detection();
    test_thread_pool_priority();
    test_chain_submission_and_signing();
    test_path_utilities();
    test_database_validation_and_crud();
    test_log_filter_profiles();

    std::printf("\nResults: %d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
