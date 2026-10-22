#pragma once
// AuditForwarder - 事件处理器：过滤、增强、聚合。

#include "auditforwarder/agent.h"
#include <atomic>
#include <chrono>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace af::processor {

// 丢弃匹配给定字段正则表达式的事件。
class RegexFilter : public Processor {
public:
    enum class Field { ActorName, ActorPath, ActorUser, TargetPath, Command, Message, Any };
    RegexFilter(Field f, std::string pattern, bool allow_when_match = false);
    ~RegexFilter() override;
    bool process(AuditEvent& ev) override;
    std::string name() const override { return "regex_filter"; }
private:
    Field f_;
    std::string pattern_;
    bool allow_;
    void* re_ { nullptr }; // 编译后的正则表达式（不透明）
};

// 对高流量调试流丢弃一定比例的事件。
class Sampler : public Processor {
public:
    explicit Sampler(double keep_ratio);
    bool process(AuditEvent& ev) override;
    std::string name() const override { return "sampler"; }
private:
    double keep_;
    std::atomic<u64> counter_{0};
};

// 在短时间窗口内去重相同事件。
class Deduper : public Processor {
public:
    explicit Deduper(std::chrono::milliseconds window = std::chrono::milliseconds(50));
    bool process(AuditEvent& ev) override;
    std::string name() const override { return "deduper"; }
private:
    std::chrono::milliseconds window_;
    std::mutex mtx_;
    std::unordered_map<std::string, TimePoint> seen_;
};

// 用主机名 / agent_id / OS 信息增强事件。
class Enricher : public Processor {
public:
    // operator_id/name 非空时写入事件 attrs（操作员身份贯通，M5）。
    Enricher(std::string host, std::string agent_id,
             std::string operator_id = {}, std::string operator_name = {});
    bool process(AuditEvent& ev) override;
    std::string name() const override { return "enricher"; }
private:
    std::string host_;
    std::string agent_id_;
    std::string operator_id_;
    std::string operator_name_;
};

// 将重复的低严重性事件聚合为单个摘要事件。
class Aggregator : public Processor {
public:
    Aggregator(std::chrono::seconds window = std::chrono::seconds(10),
               std::size_t max_per_window = 100);
    bool process(AuditEvent& ev) override;
    std::string name() const override { return "aggregator"; }
    // 立即清空所有待处理的聚合，每个桶发出一个摘要事件
    void flush(std::function<void(AuditEvent&&)> emit);
private:
    struct Bucket { std::vector<AuditEvent> events; TimePoint first; TimePoint last; };
    std::chrono::seconds window_;
    std::size_t max_;
    std::mutex mtx_;
    std::map<std::string, Bucket> buckets_;
};

// 在命令行 / 消息中屏蔽敏感值（密码、令牌）。
class PIIMasker : public Processor {
public:
    PIIMasker();
    ~PIIMasker() override;
    bool process(AuditEvent& ev) override;
    std::string name() const override { return "pii_masker"; }
private:
    void* re_ { nullptr };
};

// 数据清洗与标准化：统一不同来源（Syslog/DB审计/堡垒机/本机采集器）的事件字段格式。
// 职责：时间规整（微秒粒度）、来源标注、action/outcome/severity 推断、command/message 互补补全。
// 为后续特征工程与 ONNX 异常检测提供规范化输入。
class Normalizer : public Processor {
public:
    bool process(AuditEvent& ev) override;
    std::string name() const override { return "normalizer"; }
};

// 事件模型 Schema 映射（M6-1）：把通用审计事件映射为 OCSF 子集字段。
// 输出 actor / activity_name / object / outcome / severity_id / target_system / metadata，
// 全部写入 attrs 保留键（logmeta::attr::kSchema*），不改 AuditEvent / EventBatch 结构。
// 部署位置：Normalizer 之后、PIIMasker 之前，使脱敏能覆盖映射出的元数据。
class SchemaMapper : public Processor {
public:
    bool process(AuditEvent& ev) override;
    std::string name() const override { return "schema_mapper"; }
};

}  // namespace af::processor
