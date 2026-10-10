// Unit tests for AuditForwarder core utilities.

// winsock2 必须在 windows.h 之前引入（SyslogAdapter 测试用到 UDP socket）
#ifdef AF_PLATFORM_WINDOWS
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  pragma comment(lib, "ws2_32.lib")
#else
#  include <arpa/inet.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <unistd.h>
#endif

#include "auditforwarder/agent.h"
#include "auditforwarder/build_config.h"
#include "auditforwarder/chain.h"
#include "auditforwarder/collusion.h"
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

// 安全产品适配器
#include "collector/adapters/syslog_adapter.h"
#include "collector/adapters/db_audit_adapter.h"
#include "collector/adapters/bastion_adapter.h"
#include "auditforwarder/processor.h"

// M3: ML 异常检测
#include "auditforwarder/onnx_inference.h"
#include "auditforwarder/feature_extractor.h"

// M4: 轻量级图算法
#include "auditforwarder/behavior_graph.h"

#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstring>
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

void test_chain_super_batch() {
    using namespace af;

    // ---- 测试 1：HMAC 签名的分层 Merkle 超级批次 ----
    auto dir = fs::join(fs::temp_directory(),
                        "af_super_batch_test_" + crypto::random_hex(4));
    (void)fs::create_directories(dir);
    {
        chain::ChainConfig cfg;
        cfg.data_dir       = dir;
        cfg.batch_size     = 4;      // 小批次，快速触发
        cfg.auto_persist   = true;
        cfg.super_batch_k  = 3;      // 每 3 个批次组成一个超级批次
        chain::Chain ch(cfg);
        ch.start();
        ch.set_hmac_key("sb-test-key");

        // 提交 3 个批次（每个 4 事件）→ 触发 1 个超级批次
        for (int bi = 0; bi < 3; ++bi) {
            for (int j = 0; j < 4; ++j) {
                AuditEvent ev;
                ev.category = EventCategory::Process;
                ev.action   = EventAction::Spawn;
                ev.actor.pid = 1000 + bi * 10 + j;
                ev.target.path = "/usr/bin/test";
                ch.submit(ev);
            }
            ch.flush();
        }

        // 验证超级批次根非空且为 64 字符 hex（SHA-256）
        auto sr = ch.last_super_root();
        AF_EXPECT(!sr.empty());
        AF_EXPECT_EQ(sr.size(), (std::size_t)64);

        // 读取持久化的超级批次
        auto sbs = ch.recent_super_batches(10);
        AF_EXPECT(sbs.is_ok());
        AF_EXPECT_EQ(sbs.value().size(), (std::size_t)1);
        auto& sb1 = sbs.value()[0];
        AF_EXPECT_EQ(sb1.super_root, sr);
        AF_EXPECT(sb1.prev_super_root.empty());  // 第一个无前驱

        // HMAC 验签：正确密钥通过，错误密钥失败
        AF_EXPECT(chain::Chain::verify_super_batch(sb1, "sb-test-key"));
        AF_EXPECT(!chain::Chain::verify_super_batch(sb1, "wrong-key"));
        AF_EXPECT(!chain::Chain::verify_super_batch(sb1, ""));  // 空密钥拒绝

        // 再提交 3 个批次 → 触发第二个超级批次
        for (int bi = 0; bi < 3; ++bi) {
            for (int j = 0; j < 4; ++j) {
                AuditEvent ev;
                ev.category = EventCategory::Process;
                ev.action   = EventAction::Spawn;
                ev.actor.pid = 2000 + bi * 10 + j;
                ev.target.path = "/usr/bin/test2";
                ch.submit(ev);
            }
            ch.flush();
        }

        auto sr2 = ch.last_super_root();
        AF_EXPECT(!sr2.empty());
        AF_EXPECT(sr2 != sr);  // 新根不同于旧根

        // 链式锚定验证：第二个的 prev = 第一个的 root
        auto sbs2 = ch.recent_super_batches(10);
        AF_EXPECT(sbs2.is_ok());
        AF_EXPECT_EQ(sbs2.value().size(), (std::size_t)2);
        // recent_super_batches 按文件名逆序返回（最新在前）
        auto& newest = sbs2.value()[0];
        auto& oldest = sbs2.value()[1];
        AF_EXPECT_EQ(newest.prev_super_root, oldest.super_root);
        AF_EXPECT(oldest.prev_super_root.empty());

        ch.stop();
    }
    (void)fs::remove(dir, true);

    // ---- 测试 2：super_batch_k=0 禁用超级批次 ----
    {
        chain::ChainConfig cfg;
        cfg.data_dir       = ".";
        cfg.batch_size     = 2;
        cfg.auto_persist   = false;
        cfg.super_batch_k  = 0;      // 禁用
        chain::Chain ch(cfg);
        ch.start();
        ch.set_hmac_key("disabled-key");

        for (int i = 0; i < 4; ++i) {
            AuditEvent ev;
            ev.actor.pid = 5000 + i;
            ch.submit(ev);
        }
        ch.flush();
        ch.flush();

        // 禁用时超级批次根为空
        AF_EXPECT(ch.last_super_root().empty());
    }

    // ---- 测试 3：Ed25519 签名的超级批次 ----
    auto dir2 = fs::join(fs::temp_directory(),
                         "af_super_batch_ed25519_" + crypto::random_hex(4));
    (void)fs::create_directories(dir2);
    {
        chain::ChainConfig cfg;
        cfg.data_dir       = dir2;
        cfg.batch_size     = 2;
        cfg.auto_persist   = true;
        cfg.super_batch_k  = 2;
        chain::Chain ch(cfg);
        ch.start();

        auto kp_result = crypto::KeyPair::generate(
            crypto::KeyPair::Algorithm::Ed25519);
        AF_EXPECT(kp_result.is_ok());
        auto& kp = kp_result.value();
        // 在 move 前保存私钥 PEM，用于验签时重建 KeyPair
        auto priv_pem_r = kp.private_pem();
        AF_EXPECT(priv_pem_r.is_ok());
        std::string priv_pem = priv_pem_r.value();
        ch.set_signer(std::move(kp));

        // 提交 2 个批次 → 触发 1 个超级批次
        for (int bi = 0; bi < 2; ++bi) {
            for (int j = 0; j < 2; ++j) {
                AuditEvent ev;
                ev.category = EventCategory::File;
                ev.action   = EventAction::Write;
                ev.actor.pid = 7000 + bi * 10 + j;
                ch.submit(ev);
            }
            ch.flush();
        }

        auto sr = ch.last_super_root();
        AF_EXPECT(!sr.empty());

        auto sbs = ch.recent_super_batches(10);
        AF_EXPECT(sbs.is_ok());
        AF_EXPECT_EQ(sbs.value().size(), (std::size_t)1);

        // 用保存的私钥 PEM 重建 KeyPair 进行验签
        auto kp_verify = crypto::KeyPair::load_pem(priv_pem);
        AF_EXPECT(kp_verify.is_ok());
        AF_EXPECT(chain::Chain::verify_super_batch_with_key(
            sbs.value()[0], kp_verify.value()));

        // 用错误的密钥验签应失败
        auto kp_wrong = crypto::KeyPair::generate(
            crypto::KeyPair::Algorithm::Ed25519);
        AF_EXPECT(kp_wrong.is_ok());
        AF_EXPECT(!chain::Chain::verify_super_batch_with_key(
            sbs.value()[0], kp_wrong.value()));

        ch.stop();
    }
    (void)fs::remove(dir2, true);
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

// ---------------- 跨操作员合谋协同检测模块 ----------------

void test_collusion_pure_logic() {
    using namespace af::collusion;
    // 通配符匹配
    AF_EXPECT(wildcard_match("*backup*", "C:/data/db_backup_2026.bin"));
    AF_EXPECT(wildcard_match("*.conf", "/etc/nginx/nginx.CONF"));
    AF_EXPECT(wildcard_match("key-?", "key-A"));
    AF_EXPECT(!wildcard_match("key-?", "key-AB"));
    AF_EXPECT(!wildcard_match("*.sql", "notes.txt"));

    // 资产组归属
    std::vector<AssetGroup> groups = {
        {"backup-group", {"*backup*", "*snapshot*"}},
        {"db-group", {"*.sql", "*mysql*"}},
    };
    AF_EXPECT_EQ(match_asset_group(groups, "/var/backups/db.snap"), std::string("backup-group"));
    AF_EXPECT_EQ(match_asset_group(groups, "dump.sql"), std::string("db-group"));
    AF_EXPECT_EQ(match_asset_group(groups, "readme.md"), std::string(""));

    // 操作子序列匹配（时间有序、允许跳过无关事件、关键词大小写不敏感）
    std::vector<RuleStep> seq = { {{"delete"}}, {{"unmount", "detach"}}, {{"snapshot"}} };
    std::vector<CleanEvent> evs = {
        {"opA", 1000, "h1", "file/write", "x.bak", "", "", ""},
        {"opA", 2000, "h1", "file/delete", "a.bak", "", "", ""},
        {"opB", 3000, "h1", "disk/unmount", "/dev/sdb1", "", "", ""},
        {"opC", 4000, "h1", "snapshot/DELETE", "snap-1", "", "", ""},
    };
    AF_EXPECT(is_subsequence(seq, evs));
    std::vector<CleanEvent> evs_missing = {evs[0], evs[2], evs[3]};  // 缺 delete 步骤
    AF_EXPECT(!is_subsequence(seq, evs_missing));

    // 事件清洗：文档原生字段
    CleanEvent ce;
    AF_EXPECT(clean_event_json(
        R"({"oper_id":"opA","event_timestamp":1789700000000,"server_id":"s1",)"
        R"("op_type":"delete_backup","res_key":"db.bak","op_param":"full",)"
        R"("work_order_id":"WO-1","return_code":0})", ce));
    AF_EXPECT_EQ(ce.oper_id, std::string("opA"));
    AF_EXPECT_EQ(ce.ts_ms, 1789700000000ULL);
    // 兼容现有审计日志字段（actor/host_id/operation_type+event_type/target/message）
    AF_EXPECT(clean_event_json(
        R"({"actor":"opB","client_ts":1789700001000,"host_id":"s1",)"
        R"("operation_type":"file","event_type":"delete","target":"a.bak",)"
        R"("message":"del","outcome":"unknown"})", ce));
    AF_EXPECT_EQ(ce.op_type, std::string("file/delete"));
    AF_EXPECT_EQ(ce.res_key, std::string("a.bak"));
    // 执行失败（return_code!=0 / outcome=failed）与缺关键字段 → 丢弃
    AF_EXPECT(!clean_event_json(
        R"({"oper_id":"opA","event_timestamp":1,"server_id":"s","op_type":"t",)"
        R"("res_key":"r","op_param":"p","return_code":5})", ce));
    AF_EXPECT(!clean_event_json(
        R"({"oper_id":"opA","event_timestamp":1,"server_id":"s","op_type":"t",)"
        R"("res_key":"r","op_param":"p","outcome":"failed"})", ce));
    AF_EXPECT(!clean_event_json(
        R"({"event_timestamp":1,"server_id":"s","op_type":"t","res_key":"r"})", ce));
}

void test_collusion_workorder_and_whitelist() {
    using namespace af::collusion;
    std::vector<WorkOrder> registry = {
        {"WO-OK", "执行中", {"opA", "opB"}, 0, 0},
        {"WO-EXP", "执行中", {"opA", "opB"}, 0, 1000},          // 已过期
        {"WO-CLOSED", "已关闭", {"opA", "opB"}, 0, 0},          // 状态无效
    };
    AF_EXPECT(verify_work_order(registry, registry[0], {"opA", "opB"}, 2000));
    AF_EXPECT(!verify_work_order(registry, registry[0], {"opA", "opX"}, 2000));  // 人员不匹配
    AF_EXPECT(!verify_work_order(registry, registry[1], {"opA", "opB"}, 2000));  // 过期
    AF_EXPECT(!verify_work_order(registry, registry[2], {"opA", "opB"}, 2000));  // 已关闭

    AggSet set;
    set.operator_ids = {"opA", "opB"};
    std::vector<WhitelistGroup> wl = { {"合法组", {"opA", "opB"}, 0} };
    AF_EXPECT(in_whitelist(wl, set, 0));
    std::vector<WhitelistGroup> wl_partial = { {"组", {"opA"}, 0} };
    AF_EXPECT(!in_whitelist(wl_partial, set, 0));   // 集合未全部登记 → 不放行
}

void test_collusion_detect_scoring() {
    using namespace af::collusion;
    EngineConfig cfg;   // 默认：rule_cap=40/profile_cap=25/ticket=40/high=80/mid=40
    std::vector<Rule> rules = {
        {"R-001", "备份销毁合谋", true, "backup-group", 2, 85,
         { {{"delete"}}, {{"unmount"}}, {{"snapshot"}} }},
        {"R-003", "配置篡改链路", true, "sys-config-group", 2, 70,
         { {{"modify"}}, {{"restart"}}, {{"clear"}} }},
    };
    ProfileSnapshot profile;   // 空：全部视为陌生协作(+12)/跨域操作(+12) → 画像 24 分
    std::vector<WorkOrder> wos = { {"WO-OK", "执行中", {"opA", "opB"}, 0, 0} };

    // R-001 完整链路：基础分 85 + 画像 24 → 109 → 钳制 100 高风险
    AggSet set;
    set.asset_group = "backup-group";
    set.operator_ids = {"opA", "opB"};
    set.events = {
        {"opA", 1000, "h", "file/delete", "db.bak", "", "", ""},
        {"opB", 2000, "h", "disk/unmount", "disk0", "", "", ""},
        {"opB", 3000, "h", "snap/delete", "snapshot-1", "", "", ""},
    };
    auto r = detect(set, cfg, rules, profile, wos, 0);
    AF_EXPECT_EQ(r.hit_rules.size(), std::size_t(1));
    AF_EXPECT_EQ(r.total_score, 100);
    AF_EXPECT_EQ(r.level, std::string("HIGH"));

    // 关联有效工单：109 - 40 = 69 中风险
    set.work_order_ids = {"WO-OK"};
    r = detect(set, cfg, rules, profile, wos, 0);
    AF_EXPECT(r.ticket_valid);
    AF_EXPECT_EQ(r.total_score, 69);
    AF_EXPECT_EQ(r.level, std::string("MID"));

    // 伪造工单（未登记）：不减分，画像 +10 封顶 25 → 仍为高风险
    set.work_order_ids = {"WO-FAKE"};
    r = detect(set, cfg, rules, profile, wos, 0);
    AF_EXPECT(r.forged_ticket);
    AF_EXPECT_EQ(r.level, std::string("HIGH"));

    // 白名单命中：直接放行，仅保留线索
    set.work_order_ids.clear();
    cfg.whitelist_groups = { {"组", {"opA", "opB"}, 0} };
    r = detect(set, cfg, rules, profile, wos, 0);
    AF_EXPECT(r.whitelisted);
    AF_EXPECT_EQ(r.level, std::string("LOW"));
    AF_EXPECT_EQ(r.total_score, 0);
    cfg.whitelist_groups.clear();

    // 硬约束：仅画像异常（规则零命中）时不得触发高风险
    AggSet lone;
    lone.asset_group = "db-group";
    lone.operator_ids = {"opX", "opY"};
    lone.events = { {"opX", 1000, "h", "file/write", "n.sql", "", "", ""},
                    {"opY", 2000, "h", "file/read", "n.sql", "", "", ""} };
    r = detect(lone, cfg, rules, profile, wos, 0);
    AF_EXPECT_EQ(r.hit_rules.size(), std::size_t(0));
    AF_EXPECT(r.total_score < cfg.score_high);
    AF_EXPECT_EQ(r.level, std::string("LOW"));

    // 多规则不跨资产组误配：R-003 单命中，70 + 画像 24 = 94 高风险
    AggSet multi = set;
    multi.asset_group = "sys-config-group";
    multi.events = { {"opA", 1000, "h", "cfg/modify", "s.conf", "", "", ""},
                     {"opB", 2000, "h", "svc/restart", "nginx", "", "", ""},
                     {"opA", 3000, "h", "log/clear", "sys.log", "", "", ""} };
    multi.operator_ids = {"opA", "opB"};
    r = detect(multi, cfg, rules, profile, wos, 0);
    AF_EXPECT_EQ(r.hit_rules.size(), std::size_t(1));
    AF_EXPECT_EQ(r.total_score, 94);
    AF_EXPECT_EQ(r.level, std::string("HIGH"));
}

void test_collusion_engine_end_to_end() {
    using namespace af;
    using namespace af::collusion;
    // 独立临时数据目录，验证 接入→聚合→检测→存储→处置 全链路
    auto dir = fs::join(fs::temp_directory(), "af_collusion_test_" + crypto::random_hex(4));
    (void)fs::create_directories(dir);
    {
        Engine::instance().start(dir);
        // 两个"陌生"操作员在 backup-group 上完成备份销毁链路。
        // 时间戳放在历史窗口（已过期）：单次批量接入后立即冲刷并评估。
        u64 ts = (1789700000000ULL / 900000) * 900000 - 7200000;  // 15min 窗口对齐且已过期
        std::ostringstream body;
        body << R"({"events":[)"
             << R"({"oper_id":"opH","event_timestamp":)" << ts << R"(,"server_id":"srv-1",)"
             << R"("op_type":"delete","res_key":"db.bak","op_param":"demo","return_code":0},)"
             << R"({"oper_id":"opI","event_timestamp":)" << ts << R"(,"server_id":"srv-1",)"
             << R"("op_type":"unmount","res_key":"backup-disk0","op_param":"demo","return_code":0},)"
             << R"({"oper_id":"opH","event_timestamp":)" << ts << R"(,"server_id":"srv-1",)"
             << R"("op_type":"delete_snapshot","res_key":"snapshot-9","op_param":"demo","return_code":0}]})";
        AF_EXPECT_EQ(Engine::instance().ingest_native_json(body.str()), 3);
        // 短窗口冲刷 → R-001 命中高风险；长窗口冲刷 → HIGH 降级 MID 线索
        auto overview = Engine::instance().overview_json();
        AF_EXPECT(overview.find("\"HIGH\": 1") != std::string::npos);
        auto events = Engine::instance().events_json("HIGH", "", 10);
        AF_EXPECT(events.find("R-001") != std::string::npos);
        AF_EXPECT(events.find("opH") != std::string::npos);
        // 提取 event_id 并完成处置闭环（"ce-" + 16 位 hex，总长 19）
        auto p = events.find("ce-");
        AF_EXPECT(p != std::string::npos);
        std::string event_id = events.substr(p, 19);
        std::string err;
        AF_EXPECT(Engine::instance().dispose_event(event_id, "合法运维（误报）", "审计员", "演练", err));
        AF_EXPECT(!Engine::instance().dispose_event(event_id, "随便填", "x", "", err));
        auto after = Engine::instance().event_detail_json(event_id);
        AF_EXPECT(after.find("合法运维（误报）") != std::string::npos);
        // 报表应统计到误报
        auto report = Engine::instance().report_json(7);
        AF_EXPECT(report.find("\"misreports\": 1") != std::string::npos);
        Engine::instance().stop();
    }
    (void)fs::remove(dir, true);   // 清理临时目录
}

// ---- 安全产品适配器测试 ----

// UDP 发送辅助：向指定地址端口发送一条 UDP 数据报
static bool send_udp(const std::string& addr, std::uint16_t port, const std::string& msg) {
#ifdef AF_PLATFORM_WINDOWS
    SOCKET s = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (s == INVALID_SOCKET) return false;
#else
    int s = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return false;
#endif
    sockaddr_in dst;
    std::memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    dst.sin_addr.s_addr = ::inet_addr(addr.c_str());
    auto ret = ::sendto(s, msg.c_str(), static_cast<int>(msg.size()), 0,
                        reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
#ifdef AF_PLATFORM_WINDOWS
    ::closesocket(s);
    return ret != SOCKET_ERROR;
#else
    ::close(s);
    return ret >= 0;
#endif
}

void test_syslog_adapter() {
    using namespace af;

    // 打开适配器（端口 0 = OS 分配）
    SyslogAdapter adapter;
    auto r = adapter.open(R"({"port": 0, "bind": "127.0.0.1"})");
    AF_EXPECT(!r.is_err());
    u16 port = adapter.bound_port();
    AF_EXPECT(port > 0);

    // RFC 3164（传统 BSD syslog）：PRI=34 → facility=4(auth) severity=2(critical)
    {
        std::string msg = "<34>Oct 11 22:14:15 myhost su: 'su root' failed";
        AF_EXPECT(send_udp("127.0.0.1", port, msg));
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        AuditEvent captured;
        int n = adapter.poll([&](const AuditEvent& ev) { captured = ev; });
        AF_EXPECT_EQ(n, 1);
        AF_EXPECT(captured.category == EventCategory::Auth);
        AF_EXPECT(captured.severity == Severity::Critical);
        AF_EXPECT_EQ(captured.host, std::string("myhost"));
        AF_EXPECT_EQ(captured.actor.name, std::string("su"));
        AF_EXPECT_EQ(captured.message, std::string("'su root' failed"));
        AF_EXPECT_EQ(captured.attrs["syslog_facility"], std::string("4"));
        AF_EXPECT_EQ(captured.attrs["syslog_severity"], std::string("2"));
        AF_EXPECT_EQ(captured.attrs["collector"], std::string("syslog"));
    }

    // RFC 5424（结构化 syslog）：PRI=165 → facility=20(local4) severity=5(notice)
    {
        std::string msg = "<165>1 2026-10-10T12:00:00Z host1 sshd - ID47 - user admin logged in";
        AF_EXPECT(send_udp("127.0.0.1", port, msg));
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        AuditEvent captured;
        int n = adapter.poll([&](const AuditEvent& ev) { captured = ev; });
        AF_EXPECT_EQ(n, 1);
        AF_EXPECT(captured.severity == Severity::Notice);
        AF_EXPECT_EQ(captured.host, std::string("host1"));
        AF_EXPECT_EQ(captured.actor.name, std::string("sshd"));
        AF_EXPECT_EQ(captured.message, std::string("user admin logged in"));
        AF_EXPECT_EQ(captured.attrs["syslog_severity"], std::string("5"));
    }

    adapter.close();
    std::printf("[info]  syslog adapter: RFC 3164 + RFC 5424 解析验证通过\n");
}

void test_db_audit_adapter() {
    using namespace af;

    // 创建临时 JSONL 审计日志文件
    std::string path = "af_test_db_audit.jsonl";
    {
        std::ofstream f(path);
        f << R"({"user":"app_user","host":"db01","statement":"SELECT * FROM users","command_type":"QUERY","database":"prod"})" << "\n";
        f << R"({"user":"admin","host":"db01","statement":"DROP TABLE temp","command_type":"DDL","database":"prod"})" << "\n";
    }

    DatabaseAuditAdapter adapter;
    auto r = adapter.open(R"({"path": ")" + path + R"("})");
    AF_EXPECT(!r.is_err());

    // 第一次轮询：应读到 2 条记录
    int count = 0;
    AuditEvent ev1, ev2;
    int n = adapter.poll([&](const AuditEvent& ev) {
        if (count == 0) ev1 = ev;
        if (count == 1) ev2 = ev;
        ++count;
    });
    AF_EXPECT_EQ(n, 2);
    AF_EXPECT_EQ(count, 2);
    AF_EXPECT_EQ(ev1.actor.user, std::string("app_user"));
    AF_EXPECT(ev1.action == EventAction::Read);   // QUERY → Read
    AF_EXPECT_EQ(ev1.attrs["db_command_type"], std::string("QUERY"));
    AF_EXPECT_EQ(ev1.attrs["collector"], std::string("db_audit"));
    AF_EXPECT_EQ(ev2.actor.user, std::string("admin"));
    AF_EXPECT(ev2.action == EventAction::Set);     // DDL → Set

    // 第二次轮询：无新增数据，应返回 0
    int n2 = adapter.poll([](const AuditEvent&) {});
    AF_EXPECT_EQ(n2, 0);

    // 追加 1 条新记录
    {
        std::ofstream f(path, std::ios::app);
        f << R"({"user":"guest","host":"db01","statement":"UPDATE users SET active=0","command_type":"DML","database":"prod"})" << "\n";
    }
    // 第三次轮询：增量读取 1 条
    count = 0;
    AuditEvent ev3;
    n = adapter.poll([&](const AuditEvent& ev) { ev3 = ev; ++count; });
    AF_EXPECT_EQ(n, 1);
    AF_EXPECT_EQ(count, 1);
    AF_EXPECT_EQ(ev3.actor.user, std::string("guest"));
    AF_EXPECT(ev3.action == EventAction::Write);  // DML → Write

    adapter.close();
    std::remove(path.c_str());
    std::printf("[info]  db_audit adapter: JSONL 增量读取验证通过\n");
}

void test_bastion_adapter() {
    using namespace af;

    int call_count = 0;
    BastionAdapter::FetchFn mock_fetch = [&](
        const std::string&, const std::string&, const std::string& cursor) -> std::string {
        ++call_count;
        if (call_count == 1) {
            // 首次返回 2 条命令
            return R"({"commands":[{"id":"cmd-001","user":"admin","asset":"web-01","command":"ls -la /etc"},{"id":"cmd-002","user":"admin","asset":"db-01","command":"sudo systemctl restart nginx"}],"next_cursor":"cmd-002"})";
        }
        if (call_count == 2 && cursor == "cmd-002") {
            // 第二次：游标正确推进后返回 1 条
            return R"({"commands":[{"id":"cmd-003","user":"dev","asset":"web-02","command":"cat /etc/shadow"}],"next_cursor":"cmd-003"})";
        }
        return R"({"commands":[],"next_cursor":""})";  // 无更多数据
    };

    BastionAdapter adapter(std::move(mock_fetch));
    auto r = adapter.open(R"({"url":"http://bastion.test/api","token":"tok123"})");
    AF_EXPECT(!r.is_err());

    // 第一次轮询：2 条命令
    int count = 0;
    AuditEvent ev1, ev2;
    int n = adapter.poll([&](const AuditEvent& ev) {
        if (count == 0) ev1 = ev;
        if (count == 1) ev2 = ev;
        ++count;
    });
    AF_EXPECT_EQ(n, 2);
    AF_EXPECT_EQ(count, 2);
    AF_EXPECT(ev1.category == EventCategory::Command);
    AF_EXPECT(ev1.action == EventAction::Execute);
    AF_EXPECT_EQ(ev1.actor.user, std::string("admin"));
    AF_EXPECT_EQ(ev1.target.path, std::string("web-01"));
    AF_EXPECT_EQ(ev1.command, std::string("ls -la /etc"));
    AF_EXPECT_EQ(ev1.attrs["bastion_cmd_id"], std::string("cmd-001"));
    AF_EXPECT_EQ(ev1.attrs["collector"], std::string("bastion"));
    AF_EXPECT_EQ(ev2.command, std::string("sudo systemctl restart nginx"));

    // 第二次轮询：游标推进后 1 条
    count = 0;
    AuditEvent ev3;
    n = adapter.poll([&](const AuditEvent& ev) { ev3 = ev; ++count; });
    AF_EXPECT_EQ(n, 1);
    AF_EXPECT_EQ(count, 1);
    AF_EXPECT_EQ(ev3.actor.user, std::string("dev"));
    AF_EXPECT_EQ(ev3.target.path, std::string("web-02"));
    AF_EXPECT_EQ(ev3.command, std::string("cat /etc/shadow"));

    // 第三次轮询：无数据
    n = adapter.poll([](const AuditEvent&) {});
    AF_EXPECT_EQ(n, 0);

    adapter.close();
    std::printf("[info]  bastion adapter: REST API 增量游标验证通过\n");
}

}  // namespace

void test_normalizer() {
    using namespace af;
    processor::Normalizer nz;

    // 时间规整：ts_micros 为 0 时从 timestamp 补算微秒
    {
        AuditEvent ev;
        ev.timestamp = SysClock::now();
        AF_EXPECT(nz.process(ev));
        AF_EXPECT(ev.ts_micros > 0);
    }
    // 来源标注：缺失时标注为 agent
    {
        AuditEvent ev;
        nz.process(ev);
        AF_EXPECT_EQ(ev.attrs[logmeta::attr::kSource], std::string("agent"));
    }
    // 来源标注：已有来源不被覆盖
    {
        AuditEvent ev;
        ev.attrs[logmeta::attr::kSource] = "syslog";
        nz.process(ev);
        AF_EXPECT_EQ(ev.attrs[logmeta::attr::kSource], std::string("syslog"));
    }
    // action 推断：login
    {
        AuditEvent ev;
        ev.message = "user login from 1.2.3.4";
        nz.process(ev);
        AF_EXPECT(ev.action == EventAction::Login);
    }
    // action 推断：delete（rm 关键词）
    {
        AuditEvent ev;
        ev.command = "rm -rf /tmp/x";
        nz.process(ev);
        AF_EXPECT(ev.action == EventAction::Delete);
    }
    // action 推断：execute
    {
        AuditEvent ev;
        ev.command = "exec /bin/sh";
        nz.process(ev);
        AF_EXPECT(ev.action == EventAction::Execute);
    }
    // action 不覆盖：已有 action 保留
    {
        AuditEvent ev;
        ev.action = EventAction::Write;
        ev.message = "login";  // 即便 message 含 login，也不覆盖已有 action
        nz.process(ev);
        AF_EXPECT(ev.action == EventAction::Write);
    }
    // outcome 标准化：失败关键词 → Failure
    {
        AuditEvent ev;
        ev.message = "authentication failed for root";
        nz.process(ev);
        AF_EXPECT(ev.outcome == EventOutcome::Failure);
    }
    // outcome 标准化：无失败关键词 → Success
    {
        AuditEvent ev;
        ev.message = "command completed";
        nz.process(ev);
        AF_EXPECT(ev.outcome == EventOutcome::Success);
    }
    // severity 提升：Failure → Warning
    {
        AuditEvent ev;
        ev.message = "operation failed";
        nz.process(ev);
        AF_EXPECT(ev.severity == Severity::Warning);
    }
    // severity 提升：Delete → Notice
    {
        AuditEvent ev;
        ev.command = "rm /etc/passwd";
        nz.process(ev);
        AF_EXPECT(ev.severity == Severity::Notice);
    }
    // severity 不覆盖：非 Info 保留
    {
        AuditEvent ev;
        ev.severity = Severity::Error;
        ev.message = "failed";
        nz.process(ev);
        AF_EXPECT(ev.severity == Severity::Error);
    }
    // 字段补全：command 空 + message 非空 → command = message
    {
        AuditEvent ev;
        ev.message = "ls -la";
        nz.process(ev);
        AF_EXPECT_EQ(ev.command, std::string("ls -la"));
    }
    // 字段补全：message 空 + command 非空 → message = command
    {
        AuditEvent ev;
        ev.command = "cat /etc/hosts";
        nz.process(ev);
        AF_EXPECT_EQ(ev.message, std::string("cat /etc/hosts"));
    }
    // 端到端：模拟 syslog 风格事件（无 action/outcome，有 message）
    {
        AuditEvent ev;
        ev.message = "Failed password for invalid user admin";
        nz.process(ev);
        AF_EXPECT(ev.action == EventAction::AuthFail);
        AF_EXPECT(ev.outcome == EventOutcome::Failure);
        AF_EXPECT(ev.severity == Severity::Warning);
    }
}

// ==================== M3: ONNX 推理 + 行为特征工程 测试 ====================

void test_feature_extractor() {
    using namespace af::ml;
    using namespace af::collusion;

    AF_LOG_INFO("=== test_feature_extractor ===");

    // 空事件集合：所有特征为 0
    {
        FeatureExtractor fe;
        ProfileSnapshot profile;
        auto f = fe.extract({}, profile, "test-group");
        auto v = f.to_vector();
        AF_EXPECT_EQ(v.size(), BehaviorFeatures::DIM);
        // 空集合 → 全零
        for (float x : v) { AF_EXPECT(x == 0.f); }
    }

    // 单条事件：无间隔，部分特征有值
    {
        FeatureExtractor fe;
        ProfileSnapshot profile;
        std::vector<CleanEvent> events = {
            {"opA", 1000, "host1", "file/delete", "db.bak", "rm db.bak", "", ""}
        };
        auto f = fe.extract(events, profile, "backup-group");
        auto v = f.to_vector();
        AF_EXPECT_EQ(v.size(), BehaviorFeatures::DIM);
        AF_EXPECT(f.op_count_norm > 0.f);  // 有操作
        AF_EXPECT(f.distinct_op_type_ratio == 1.f);  // 单类型
        AF_EXPECT(f.distinct_server_ratio == 1.f);  // 单服务器
    }

    // 多条事件：间隔、多样性、重复率等
    {
        FeatureExtractor fe;
        ProfileSnapshot profile;
        std::vector<CleanEvent> events = {
            {"opA", 1000,   "host1", "file/delete",  "db.bak",  "rm db.bak",  "", ""},
            {"opB", 61000,  "host1", "disk/unmount", "disk0",   "unmount /disk0", "", ""},
            {"opA", 121000, "host2", "snap/delete",   "snap-1",  "rm db.bak",  "", ""},  // op_param 重复
        };
        auto f = fe.extract(events, profile, "backup-group");
        auto v = f.to_vector();
        AF_EXPECT_EQ(v.size(), BehaviorFeatures::DIM);

        // 间隔均值（60秒归一化）
        AF_EXPECT(f.op_interval_mean > 0.f);
        // 间隔标准差 > 0（两次间隔相同但均值差不为 0？实际相同 60s → std=0）
        // burst_ratio：60 秒间隔 → 不突发
        AF_EXPECT(f.burst_ratio == 0.f);
        // 操作类型多样性：3 种 → 1.0
        AF_EXPECT(f.distinct_op_type_ratio > 0.5f);
        // 服务器多样性：2/3
        AF_EXPECT(f.distinct_server_ratio > 0.5f);
        AF_EXPECT(f.distinct_server_ratio < 1.f);
        // 命令重复率：rm db.bak 出现 2 次 → repeat=1, ratio=1/3
        AF_EXPECT(f.cmd_repeat_ratio > 0.f);
    }

    // 画像协作熟悉度
    {
        FeatureExtractor fe;
        ProfileSnapshot profile;
        profile.pair_counts["opA|opB"] = 10;   // 10 次历史协作
        profile.operator_assets["opA"]["backup-group"] = 15;  // 15 次该资产组操作

        std::vector<CleanEvent> events = {
            {"opA", 1000, "host1", "file/delete", "db.bak", "rm db.bak", "", ""},
            {"opB", 2000, "host1", "file/read",  "db.bak", "cat db.bak", "", ""},
        };
        auto f = fe.extract(events, profile, "backup-group");
        // pair_familiarity = 10/20 = 0.5
        AF_EXPECT(f.pair_familiarity > 0.f);
        AF_EXPECT(f.pair_familiarity <= 0.6f);
        // asset_familiarity = 15/20 = 0.75
        AF_EXPECT(f.asset_familiarity > 0.5f);
    }

    // 跨域操作员比例
    {
        FeatureExtractor fe;
        ProfileSnapshot profile;
        // opA 有历史记录，opB 无
        profile.operator_assets["opA"]["db-group"] = 5;

        std::vector<CleanEvent> events = {
            {"opA", 1000, "host1", "file/delete", "db.bak", "rm", "", ""},
            {"opB", 2000, "host2", "file/read",  "db.bak", "cat", "", ""},
        };
        auto f = fe.extract(events, profile, "db-group");
        // opA 熟悉(db-group 5次), opB 陌生 → cross_domain_ratio = 0.5
        AF_EXPECT(f.cross_domain_ratio > 0.f);
        AF_EXPECT(f.cross_domain_ratio <= 0.6f);
    }

    // 突发操作检测：10 个事件在 1 秒内 → burst
    {
        FeatureExtractor fe;
        ProfileSnapshot profile;
        std::vector<CleanEvent> events;
        for (int i = 0; i < 15; ++i) {
            events.push_back(CleanEvent{"opA", static_cast<af::u64>(1000 + i * 50), "h", "cmd", "r", "c", "", ""});
        }
        auto f = fe.extract(events, profile, "g");
        AF_EXPECT(f.burst_ratio == 1.f);  // 60秒内超过10个操作 → 突发
    }
}

void test_onnx_inference() {
    using namespace af::ml;

    AF_LOG_INFO("=== test_onnx_inference ===");

    // 默认构造：未加载
    {
        OnnxModel model;
        AF_EXPECT(!model.is_loaded());
        // 推理返回空向量（优雅降级）
        auto result = model.infer({0.1f, 0.2f, 0.3f});
        AF_EXPECT(result.empty());
        // last_error 有内容
        AF_EXPECT(!model.last_error().empty());
    }

    // 加载不存在的模型文件：失败但不崩溃
    {
        OnnxModel model;
        bool ok = model.load("models/nonexistent_model.onnx");
        AF_EXPECT(!ok);
        AF_EXPECT(!model.is_loaded());
        AF_EXPECT(!model.last_error().empty());
        // 推理仍返回空
        auto result = model.infer(std::vector<float>(20, 0.5f));
        AF_EXPECT(result.empty());
    }

    // 加载空路径：失败
    {
        OnnxModel model;
        bool ok = model.load("");
        AF_EXPECT(!ok);
        AF_EXPECT(!model.is_loaded());
    }
}

void test_collusion_ml_integration() {
    using namespace af::collusion;

    AF_LOG_INFO("=== test_collusion_ml_integration ===");

    EngineConfig cfg;   // 默认 ml_enabled=false
    std::vector<Rule> rules;
    ProfileSnapshot profile;
    std::vector<WorkOrder> wos;

    AggSet set;
    set.asset_group = "backup-group";
    set.operator_ids = {"opA", "opB"};
    set.events = {
        {"opA", 1000, "h", "file/delete", "db.bak", "rm db.bak", "", ""},
        {"opB", 2000, "h", "disk/unmount", "disk0", "unmount", "", ""},
    };

    // ml_enabled=false：ml_factor=0，ml_notes 为空
    {
        auto r = detect(set, cfg, rules, profile, wos, 0);
        AF_EXPECT_EQ(r.ml_factor, 0);
        AF_EXPECT(r.ml_notes.empty());
    }

    // ml_enabled=true 但无模型指针：优雅降级，ml_notes 有提示
    {
        EngineConfig cfg2 = cfg;
        cfg2.ml_enabled = true;
        auto r = detect(set, cfg2, rules, profile, wos, 0);
        AF_EXPECT_EQ(r.ml_factor, 0);  // 降级为 0
        AF_EXPECT(!r.ml_notes.empty());  // 有降级提示
    }

    // ml_enabled=true 且传入未加载的 OnnxModel：优雅降级
    {
        EngineConfig cfg2 = cfg;
        cfg2.ml_enabled = true;
        af::ml::OnnxModel model;  // 未加载
        auto r = detect(set, cfg2, rules, profile, wos, 0, &model);
        AF_EXPECT_EQ(r.ml_factor, 0);
        AF_EXPECT(!r.ml_notes.empty());
    }

    // 硬约束：规则零命中 + ML 开启 → 总分不触发 HIGH
    {
        EngineConfig cfg2 = cfg;
        cfg2.ml_enabled = true;
        af::ml::OnnxModel model;
        auto r = detect(set, cfg2, rules, profile, wos, 0, &model);
        AF_EXPECT_EQ(r.hit_rules.size(), std::size_t(0));
        AF_EXPECT(r.total_score < cfg2.score_high);
    }
}

// ==================== M4: 图算法模块测试 ====================

void test_behavior_graph_basic() {
    using namespace af::graph;
    AF_LOG_INFO("=== test_behavior_graph_basic ===");

    BehaviorGraph g;

    // 空图测试
    AF_EXPECT_EQ(g.node_count(), std::size_t(0));
    AF_EXPECT_EQ(g.edge_count(), std::size_t(0));

    // 添加节点
    auto op1 = g.add_node(NodeType::Operator, "opA");
    auto op2 = g.add_node(NodeType::Operator, "opB");
    auto ast1 = g.add_node(NodeType::Asset, "host1");
    auto ast2 = g.add_node(NodeType::Asset, "host2");
    auto t1 = g.add_node(NodeType::OpType, "file/delete");

    AF_EXPECT_EQ(g.node_count(), std::size_t(5));
    AF_EXPECT(op1 != op2);
    AF_EXPECT(ast1 != ast2);
    AF_EXPECT(op1 != ast1);

    // 重复添加同 label+type 应返回既有 ID
    auto op1_again = g.add_node(NodeType::Operator, "opA");
    AF_EXPECT_EQ(op1_again, op1);
    AF_EXPECT_EQ(g.node_count(), std::size_t(5));

    // 查找节点
    AF_EXPECT_EQ(g.find_node(NodeType::Operator, "opA"), op1);
    AF_EXPECT_EQ(g.find_node(NodeType::Asset, "host2"), ast2);
    AF_EXPECT_EQ(g.find_node(NodeType::Operator, "opZ"), BehaviorGraph::INVALID_NODE);

    // 添加边
    g.add_edge(op1, ast1);
    g.add_edge(op1, t1);
    g.add_edge(op2, ast2);
    g.add_edge(op2, t1);   // opB 也操作了 t1（共同操作类型）
    g.add_edge(op1, op2);  // 协作边
    g.add_edge(op2, op1);  // 双向

    AF_EXPECT_EQ(g.edge_count(), std::size_t(6));

    // 边权重累加
    g.add_edge(op1, ast1, 2.0);
    // op1→ast1 应只有一条边，权重=3.0
    const auto& nb = g.neighbors(op1);
    double w_ast1 = 0;
    for (const auto& e : nb) {
        if (e.to == ast1) w_ast1 = e.weight;
    }
    AF_EXPECT(w_ast1 > 2.9 && w_ast1 < 3.1);

    // 度数
    AF_EXPECT(g.degree(op1) >= 3);   // 出度3（ast1,t1,op2）+ 入度1（op2→op1）
}

void test_behavior_graph_analyze() {
    using namespace af::graph;
    AF_LOG_INFO("=== test_behavior_graph_analyze ===");

    // 构建一个有异常的图：opA 操作大量资产，其他操作员度数低
    BehaviorGraph g;
    auto opA = g.add_node(NodeType::Operator, "opA");
    auto opB = g.add_node(NodeType::Operator, "opB");
    auto opC = g.add_node(NodeType::Operator, "opC");
    auto opD = g.add_node(NodeType::Operator, "opD");
    auto opE = g.add_node(NodeType::Operator, "opE");
    auto opF = g.add_node(NodeType::Operator, "opF");

    // opA 连接 5 个资产（高度数异常）
    for (int i = 0; i < 5; ++i) {
        auto ast = g.add_node(NodeType::Asset, "host" + std::to_string(i));
        g.add_edge(opA, ast);
    }
    // opB~opF 各连接 1 个资产
    g.add_edge(opB, g.add_node(NodeType::Asset, "hostB"));
    g.add_edge(opC, g.add_node(NodeType::Asset, "hostC"));
    g.add_edge(opD, g.add_node(NodeType::Asset, "hostD"));
    g.add_edge(opE, g.add_node(NodeType::Asset, "hostE"));
    g.add_edge(opF, g.add_node(NodeType::Asset, "hostF"));

    // 无基线分析
    BehaviorGraph empty_baseline;
    auto result = g.analyze(empty_baseline);

    // 应有度中心性异常（opA 度数远高于均值+2σ）
    AF_EXPECT(result.degree_anomaly > 0.f);
    AF_EXPECT(!result.notes.empty());

    // 全对称图不应有度异常
    BehaviorGraph sym;
    auto s1 = sym.add_node(NodeType::Operator, "s1");
    auto s2 = sym.add_node(NodeType::Operator, "s2");
    auto s3 = sym.add_node(NodeType::Operator, "s3");
    auto a1 = sym.add_node(NodeType::Asset, "a1");
    auto a2 = sym.add_node(NodeType::Asset, "a2");
    auto a3 = sym.add_node(NodeType::Asset, "a3");
    sym.add_edge(s1, a1); sym.add_edge(s1, a2);
    sym.add_edge(s2, a2); sym.add_edge(s2, a3);
    sym.add_edge(s3, a3); sym.add_edge(s3, a1);
    auto sym_result = sym.analyze(empty_baseline);
    // 对称图度数差异小，sigma 可能极小 → degree_anomaly 接近 0
    AF_EXPECT(sym_result.degree_anomaly <= result.degree_anomaly);
}

void test_behavior_graph_similarity() {
    using namespace af::graph;
    AF_LOG_INFO("=== test_behavior_graph_similarity ===");

    // 构建基线图
    BehaviorGraph baseline;
    auto b_opA = baseline.add_node(NodeType::Operator, "opA");
    auto b_opB = baseline.add_node(NodeType::Operator, "opB");
    auto b_ast1 = baseline.add_node(NodeType::Asset, "host1");
    auto b_ast2 = baseline.add_node(NodeType::Asset, "host2");
    baseline.add_edge(b_opA, b_ast1);
    baseline.add_edge(b_opB, b_ast2);

    // 当前图与基线完全一致 → Jaccard=1.0，不触发相似度异常
    BehaviorGraph same;
    auto s_opA = same.add_node(NodeType::Operator, "opA");
    auto s_opB = same.add_node(NodeType::Operator, "opB");
    auto s_ast1 = same.add_node(NodeType::Asset, "host1");
    auto s_ast2 = same.add_node(NodeType::Asset, "host2");
    same.add_edge(s_opA, s_ast1);
    same.add_edge(s_opB, s_ast2);
    auto r1 = same.analyze(baseline);
    AF_EXPECT(r1.similarity_anomaly < 0.01f);   // 相似度=1，不异常

    // 当前图与基线完全不同 → Jaccard=0，触发相似度异常
    BehaviorGraph diff;
    auto d_opX = diff.add_node(NodeType::Operator, "opX");
    auto d_opY = diff.add_node(NodeType::Operator, "opY");
    auto d_ast9 = diff.add_node(NodeType::Asset, "host9");
    auto d_ast8 = diff.add_node(NodeType::Asset, "host8");
    diff.add_edge(d_opX, d_ast9);
    diff.add_edge(d_opY, d_ast8);
    auto r2 = diff.analyze(baseline);
    AF_EXPECT(r2.similarity_anomaly > 0.1f);   // Jaccard=0 < 0.3 → 异常 0.15
}

void test_collusion_graph_integration() {
    using namespace af::collusion;
    AF_LOG_INFO("=== test_collusion_graph_integration ===");

    EngineConfig cfg;   // 默认 graph_enabled=false
    std::vector<Rule> rules;
    ProfileSnapshot profile;
    std::vector<WorkOrder> wos;

    AggSet set;
    set.asset_group = "backup-group";
    set.operator_ids = {"opA", "opB"};
    set.events = {
        {"opA", 1000, "h1", "file/delete", "db.bak", "rm db.bak", "", ""},
        {"opB", 2000, "h2", "disk/unmount", "disk0", "unmount", "", ""},
    };

    // graph_enabled=false：graph_factor=0，graph_notes 为空
    {
        auto r = detect(set, cfg, rules, profile, wos, 0);
        AF_EXPECT_EQ(r.graph_factor, 0);
        AF_EXPECT(r.graph_notes.empty());
    }

    // graph_enabled=true 但无基线：图分析执行，graph_notes 有输出
    {
        EngineConfig cfg2 = cfg;
        cfg2.graph_enabled = true;
        auto r = detect(set, cfg2, rules, profile, wos, 0);
        AF_EXPECT_EQ(r.graph_factor, 0);   // 2操作员对称图，无度异常 → factor=0
        // 但 graph_notes 可能有"未超阈值"提示或为空（取决于图结构）
        AF_EXPECT(r.graph_factor <= cfg2.graph_max_factor);
    }

    // 硬约束：规则零命中 + graph 开启 → 总分不触发 HIGH
    {
        EngineConfig cfg2 = cfg;
        cfg2.graph_enabled = true;
        auto r = detect(set, cfg2, rules, profile, wos, 0);
        AF_EXPECT_EQ(r.hit_rules.size(), std::size_t(0));
        AF_EXPECT(r.total_score < cfg2.score_high);
    }

    // 传入基线图指针：不崩溃，正常分析
    {
        EngineConfig cfg2 = cfg;
        cfg2.graph_enabled = true;
        af::graph::BehaviorGraph baseline;
        baseline.add_node(af::graph::NodeType::Operator, "opA");
        baseline.add_node(af::graph::NodeType::Operator, "opB");
        auto b_ast = baseline.add_node(af::graph::NodeType::Asset, "h1");
        auto opA = baseline.find_node(af::graph::NodeType::Operator, "opA");
        baseline.add_edge(opA, b_ast);
        auto r = detect(set, cfg2, rules, profile, wos, 0, nullptr, &baseline);
        AF_EXPECT(r.graph_factor <= cfg2.graph_max_factor);
    }
}

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);  // 无缓冲输出：崩溃时也能看到最后一条断言
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
    test_chain_super_batch();
    test_path_utilities();
    test_database_validation_and_crud();
    test_log_filter_profiles();
    test_collusion_pure_logic();
    test_collusion_workorder_and_whitelist();
    test_collusion_detect_scoring();
    test_collusion_engine_end_to_end();
    test_syslog_adapter();
    test_db_audit_adapter();
    test_bastion_adapter();
    test_normalizer();
    test_feature_extractor();
    test_onnx_inference();
    test_collusion_ml_integration();
    test_behavior_graph_basic();
    test_behavior_graph_analyze();
    test_behavior_graph_similarity();
    test_collusion_graph_integration();

    std::printf("\nResults: %d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
