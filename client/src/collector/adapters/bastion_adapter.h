#pragma once
// 堡垒机适配器：通过 REST API 轮询堡垒机会话/命令日志，
// 使用增量游标（last_seen_id）实现分页拉取，转为标准 AuditEvent。

#include "auditforwarder/security_adapter.h"
#include "auditforwarder/types.h"
#include <functional>
#include <string>

namespace af {

class BastionAdapter : public SecurityAdapter {
public:
    // HTTP 拉取函数类型：传入 URL + token + 游标，返回响应体 JSON 字符串。
    // 可注入自定义实现（如 HTTPS 客户端）；默认使用简易 HTTP GET。
    using FetchFn = std::function<std::string(const std::string& url,
                                              const std::string& token,
                                              const std::string& cursor)>;

    BastionAdapter();
    explicit BastionAdapter(FetchFn fetcher);  // 注入自定义拉取器（测试用）
    ~BastionAdapter() override;

    Result<void> open(const std::string& config_json) override;
    void         close() override;
    int          poll(std::function<void(const AuditEvent&)> emit) override;

    std::string  name() const override;
    std::string  source_type() const override { return "bastion"; }

private:
    std::string  url_     ;            // API 端点
    std::string  token_   ;            // 认证令牌
    std::string  cursor_  ;            // 增量游标（last_seen_id）
    bool         opened_   { false };
    FetchFn      fetcher_;             // 拉取实现
};

}  // namespace af
