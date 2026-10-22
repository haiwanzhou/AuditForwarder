#pragma once
// AuditForwarder - 受管系统资产画像（M6-2）。
//
// 一个受管系统一份 YAML 画像，实现方案通用化（图书系统只是实例）：
//   系统标识 / 访问方式（HTTP/DB/终端）/ 资源类型枚举 / 敏感度分级 /
//   角色基线（哪些角色可执行哪些 action）/ 操作员角色归属。
// 服务端加载画像后，规则引擎与合谋图谱按画像解释事件的 object 与 target_system。

#include "auditforwarder/config.h"
#include "auditforwarder/types.h"

#include <map>
#include <string>
#include <vector>

namespace af::asset {

// ---- 访问方式 ----
enum class AccessMode : u8 {
    Unknown  = 0,
    Http     = 1,   // Web/HTTP 接口
    Db       = 2,   // 数据库
    Terminal = 3,   // 终端/堡垒机
};

const char* to_string(AccessMode m) noexcept;
AccessMode  access_mode_from_string(const std::string& s) noexcept;

// ---- 资源类型（画像中的资源枚举）----
enum class ResourceType : u8 {
    Other       = 0,
    DataRecord  = 1,   // 业务数据记录（如 /books?id=7）
    Table       = 2,   // 数据库表/集合
    Backup      = 3,   // 备份文件/快照
    Credential  = 4,   // 凭据/密钥
    Config      = 5,   // 配置/管理接口
    Log         = 6,   // 日志/审计文件
    System      = 7,   // 系统资源（磁盘/服务/主机）
};

const char*  to_string(ResourceType t) noexcept;
ResourceType resource_type_from_string(const std::string& s) noexcept;

// ---- 敏感度分级 ----
enum class Sensitivity : u8 {
    Public       = 0,
    Internal     = 1,
    Confidential = 2,
    Secret       = 3,
};

const char*  to_string(Sensitivity s) noexcept;
Sensitivity  sensitivity_from_string(const std::string& s) noexcept;

struct ResourceRule {
    std::string   pattern;                              // 通配符（* / ?，大小写不敏感）
    ResourceType  type        { ResourceType::Other };
    Sensitivity   sensitivity { Sensitivity::Internal };
};

struct RoleBaseline {
    std::string              role;
    std::vector<std::string> allowed_actions;   // 支持通配符；"*" 表示全部
    std::vector<std::string> denied_actions;    // 优先级高于 allowed
};

struct AssetProfile {
    std::string              system_id;                    // 系统标识（如 book_system）
    std::string              display_name;
    AccessMode               access_mode { AccessMode::Unknown };
    std::vector<std::string> target_systems;               // 事件 target_system 别名（host:port 等）
    Sensitivity              default_sensitivity { Sensitivity::Internal };
    ResourceType             default_resource_type { ResourceType::Other };
    std::vector<ResourceRule> resources;
    std::vector<RoleBaseline> roles;
    std::map<std::string, std::string> operator_roles;     // operator_id -> role
    std::string              source;                        // 来源文件（排障用）

    const RoleBaseline* find_role(const std::string& role) const;
    // 操作员角色；未登记返回空串
    std::string role_of(const std::string& operator_id) const;
};

// ---- 解释结果 ----
struct ResourceMatch {
    bool          matched     { false };
    ResourceType  type        { ResourceType::Other };
    Sensitivity   sensitivity { Sensitivity::Internal };
    std::string   pattern;      // 命中的资源规则模式；未命中为空
};

enum class RoleVerdict : u8 {
    UnknownRole = 0,   // 画像未登记该角色 → 不做判定
    Allowed     = 1,
    Denied      = 2,
};

struct ActionVerdict {
    RoleVerdict verdict { RoleVerdict::UnknownRole };
    std::string role;
    std::string reason;   // allowed_action / denied_action / unknown_role
};

// YAML -> 画像：system_id 必填；解析失败返回 Error::Code::Parse。
Result<AssetProfile> parse_asset_profile(const std::string& yaml, const std::string& source = {});

// 画像注册表：服务端启动时加载目录下所有 .yaml/.yml（一个文件一个系统）。
class AssetProfileRegistry {
public:
    // 加载目录下所有 .yaml/.yml；返回成功加载数量，errors 收集解析失败说明。
    std::size_t load_directory(const std::string& dir, std::vector<std::string>* errors = nullptr);
    // 直接加载单份 YAML 文本（测试/热加载用）。
    Result<void> add_yaml(const std::string& yaml, const std::string& source = {});
    void clear() { profiles_.clear(); }

    std::size_t size() const { return profiles_.size(); }
    const std::vector<AssetProfile>& profiles() const { return profiles_; }

    // 按系统标识查找（大小写不敏感）
    const AssetProfile* find_system(const std::string& system_id) const;
    // 按事件的 target_system 查找（大小写不敏感精确匹配）
    const AssetProfile* find_for_target(const std::string& target_system) const;

    // 解释 object：按资源规则顺序匹配，未命中返回画像默认值
    ResourceMatch classify(const AssetProfile& profile, const std::string& object) const;

    // 角色基线判定：denied 优先，其次 allowed（支持通配符）；角色未登记返回 UnknownRole
    ActionVerdict check_action(const AssetProfile& profile, const std::string& role,
                               const std::string& action) const;
    // 便捷：由 operator_id 查角色后判定
    ActionVerdict check_operator_action(const AssetProfile& profile, const std::string& operator_id,
                                        const std::string& action) const;

    // 全部画像的 JSON（供 /asset-profiles 展示）
    std::string to_json() const;

private:
    std::vector<AssetProfile> profiles_;
};

// 单份画像 JSON（供解析/API 复用）
std::string to_json(const AssetProfile& profile);

// 通配符匹配（* 与 ?，大小写不敏感）
bool wildcard_match(const std::string& pattern, const std::string& text);

}  // namespace af::asset
