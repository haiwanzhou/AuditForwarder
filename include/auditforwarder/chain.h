#pragma once
// AuditForwarder - 证据链：将事件链接到哈希链中，批量构建
// Merkle 树，并对批次签名。

#include "auditforwarder/event.h"
#include "auditforwarder/crypto.h"
#include <atomic>
#include <functional>
#include <mutex>
#include <string>

namespace af::chain {

using EventBatch = af::EventBatch;

// 链配置
struct ChainConfig {
    std::string data_dir;            // 签名批次的本地存储
    std::size_t batch_size { 256 };  // 每批次事件数
    bool        sign_batches { true };
    bool        auto_persist { true };
    std::size_t super_batch_k { 8 };  // 每 K 个批次组成一个超级批次（0=禁用）
};

// 当新批次构建并持久化后调用的回调函数。
// 用于桥接到传输模块。
using BatchCallback = std::function<void(const EventBatch&)>;

// 超级批次：跨批次分层 Merkle 树的聚合单元。
// 每 K 个 EventBatch 的 merkle_root 作为叶子，构建上层 Merkle 树，
// 生成 super_root，并通过 prev_super_root 链式锚定前一个超级批次。
struct SuperBatch {
    std::string                id;                // 超级批次 ID
    std::vector<std::string>   batch_ids;         // 包含的批次 ID 列表
    std::vector<std::string>   batch_roots;      // 各批次 merkle_root 列表
    std::string                super_root;        // 超级批次 Merkle 根
    std::string                prev_super_root;   // 前一个超级批次根（链式锚定）
    u64                        created_at_us;    // 创建时间（微秒粒度）
    std::string                signature;        // 签名（HMAC 或 Ed25519）
};

// 处理原始事件：分配 ID、计算哈希、链接 prev_hash、追加到批次。
class Chain {
public:
    explicit Chain(ChainConfig cfg);
    ~Chain();

    void start();
    void stop();

    // 设置用于签名批次的密钥。如未设置，则使用 HMAC-SHA256。
    void set_signer(crypto::KeyPair kp);
    void set_hmac_key(const std::string& key);

    // 注册每次成功构建批次后调用的回调。
    void on_batch(BatchCallback cb);

    // 提交单个事件进行哈希计算并添加到当前批次。
    void submit(AuditEvent& ev);

    // 强制刷新当前批次。
    Result<EventBatch> flush();

    // 读取最近 N 个已签名批次（用于审计）。
    Result<std::vector<EventBatch>> recent_batches(std::size_t n = 10) const;

    // 设置超级批次容量（多少个 EventBatch 组成一个 SuperBatch）。
    // 0 = 禁用超级批次功能。
    void set_super_batch_size(std::size_t k) { super_batch_k_ = k; }

    // 获取当前超级批次根（最近一个 SuperBatch 的 super_root）。
    std::string last_super_root() const { return last_super_root_; }

    // 读取最近 N 个已签名超级批次（用于审计验证）。
    Result<std::vector<SuperBatch>> recent_super_batches(std::size_t n = 10) const;

    // 统计信息
    u64  total_events() const   { return total_events_.load(); }
    u64  total_batches() const  { return total_batches_.load(); }
    u64  last_event_seq() const { return last_seq_.load(); }
    std::string last_batch_id() const;
    std::string last_merkle_root() const;

    // 验证批次的签名和哈希链。
    static bool verify_batch(const EventBatch& b, const std::string& hmac_key = {});
    static bool verify_batch_with_key(const EventBatch& b, const crypto::KeyPair& kp);

    // 验证超级批次的签名和分层 Merkle 结构（HMAC）。
    static bool verify_super_batch(const SuperBatch& sb, const std::string& hmac_key = {});

    // 验证超级批次的签名和分层 Merkle 结构（Ed25519 公钥）。
    static bool verify_super_batch_with_key(const SuperBatch& sb, const crypto::KeyPair& kp);

private:
    void persist_batch(const EventBatch& b);
    EventBatch build_batch(std::vector<AuditEvent>&& events);

    // 构建超级批次：将多个批次的 merkle_root 作为叶子构建上层 Merkle 树。
    SuperBatch build_super_batch(std::vector<std::string>&& batch_ids,
                                  std::vector<std::string>&& batch_roots);
    // 持久化超级批次到 data_dir/super_batches/<id>.json。
    void persist_super_batch(const SuperBatch& sb);

    // 超级批次签名 payload：与微秒粒度保持一致，含 prev_super_root 实现链式锚定。
    static std::string super_batch_payload(const SuperBatch& sb);

    ChainConfig                cfg_;
    std::mutex                 mtx_;
    std::vector<AuditEvent>    pending_;
    crypto::KeyPair            signer_;
    std::string                hmac_key_;
    bool                       has_signer_  { false };
    bool                       has_hmac_    { false };
    BatchCallback              batch_cb_;
    std::atomic<bool>          running_     { false };
    std::atomic<u64>           total_events_{ 0 };
    std::atomic<u64>           total_batches_{ 0 };
    std::atomic<u64>           last_seq_    { 0 };
    std::string                last_batch_id_;
    std::string                last_merkle_;
    std::string                last_event_hash_;

    // 超级批次相关
    std::size_t                super_batch_k_         { 8 };   // 每 K 个批次组成一个超级批次
    std::vector<std::string>   pending_batch_ids_;              // 待聚合的批次 ID
    std::vector<std::string>   pending_batch_roots_;            // 待聚合的批次 merkle_root
    std::string                last_super_root_;                 // 最近超级批次根（链式锚定）
};

}  // namespace af::chain
