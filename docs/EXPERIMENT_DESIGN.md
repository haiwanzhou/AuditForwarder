# AuditForwarder 合谋攻击检测能力验证实验方案

> 版本：v1.0 | 日期：2026-10-10 | 适用模块：server/src/collusion/ 跨操作员合谋协同检测引擎

---

## 一、合谋检测模块技术实现路径

### 1.1 核心架构

合谋检测引擎位于 [server/src/collusion/collusion.cpp](file:///c:/Users/30952/Desktop/AuditForwarder_ovo1102/server/src/collusion/collusion.cpp)，作为服务端并行扩展层，数据流如下：

```
操作日志流（/agent/operation-logs 或 /collusion/ingest）
  → 事件清洗（clean_event_json：提取 oper_id/ts/server_id/op_type/res_key/work_order_id）
  → 资产组匹配（match_asset_group：通配符 pattern 匹配 res_key）
  → 时间窗口聚合（AggSet：asset_group + window_kind + operator_ids + events 升序）
  → 双路检测：
      路径A 规则引擎（is_subsequence 子序列匹配 + min_operator_cnt 校验 → base_score）
      路径B 行为画像（pair_counts 协作关系 + operator_assets 资产域分布 → 异常评分）
  → 风险评分合成（total_score = rule_factor + profile_factor ± 工单调整）
  → 分级告警（HIGH ≥80 / MID ≥40 / LOW >0 / NONE=0）
  → 输出：events.jsonl 留存 + HIGH/MID 推送平台告警
```

### 1.2 关键判定节点与技术指标

| 节点 | 实现位置 | 判定逻辑 | 关键参数 |
|------|----------|----------|----------|
| 资产组匹配 | collusion.cpp L519-L588 | `match_asset_group()` 通配符 `*`/`?` 匹配 res_key | 5 个资产组（backup/key-mgmt/sys-config/db/general） |
| 规则子序列匹配 | collusion.cpp L519-L588 | `is_subsequence()` 按时序匹配 any_of 关键词 | 5 条规则 R-001~R-005 |
| 最小操作员数 | collusion.cpp L627-L745 | `distinct_op_count() >= rule.min_operator_cnt` | R-001/003/004: 2人, R-002/005: 3人 |
| 工单核验 | collusion.cpp L627-L745 | 有效工单扣 40 分，伪造工单加 10 分 | work_order_deduct=40, forged_ticket_bonus=10 |
| 行为画像异常 | collusion.cpp L627-L745 | pair_counts 历史协作频次 + operator_assets 资产域偏离 | profile_max_factor=25 |
| 风险总分阈值 | collusion.cpp L741-L743 | total_score ≥ score_high → HIGH；≥ score_mid → MID | score_high=80, score_mid=40 |
| 长窗口降级 | collusion.cpp L1022-L1024 | long 窗口 HIGH 自动降为 MID（弱关联线索） | — |
| 应急模式降级 | collusion.cpp L1029-L1030 | emergency_mode 下等级自动降一级 | emergency_mode 可配 |
| 告警降噪 | collusion.cpp L1039-L1043 | 同 aggregate_key 在 alert_dedup_seconds 内只报一次 | alert_dedup_seconds=300 |

### 1.3 检测规则明细（policies/collusion_rules.json）

| 规则ID | 名称 | 资产组 | 最少操作员 | 基础分 | 操作子序列 |
|--------|------|--------|-----------|--------|-----------|
| R-001 | 备份销毁合谋 | backup-group | 2 | 85 | 删除→卸载→快照 |
| R-002 | 密钥权限拆分绕过 | key-mgmt-group | 3 | 80 | 生成→分发→清理 |
| R-003 | 配置篡改链路 | sys-config-group | 2 | 70 | 修改→重启→清除 |
| R-004 | 数据批量外泄 | db-group | 2 | 82 | 提权→导出→清除 |
| R-005 | 权限晋升合谋 | *（任意） | 3 | 75 | 创建角色→加入→提权 |

### 1.4 API 接口（manager_server.cpp L3123-L3204）

| 路由 | 方法 | 用途 |
|------|------|------|
| `/collusion/overview` | GET | 检测概览（事件计数 HIGH/MID/LOW） |
| `/collusion/events` | GET | 事件列表（支持 level 过滤） |
| `/collusion/events/detail` | GET | 事件详情（含证据链） |
| `/collusion/events/export` | GET | 导出事件 NDJSON |
| `/collusion/events/dispose` | POST | 处置事件（标记已处理） |
| `/collusion/config` | GET/PUT | 读取/更新引擎配置（热加载） |
| `/collusion/rules` | GET/PUT | 读取/更新规则（热加载） |
| `/collusion/workorders` | GET/PUT | 读取/更新工单 |
| `/collusion/emergency` | POST | 启动/停止应急模式 |
| `/collusion/report` | GET | 生成检测报告 |
| `/collusion/ingest` | POST | 直接注入事件（测试入口） |

---

## 二、外部参考依据

### 2.1 公开测试数据集

| 数据集 | 规模 | 适用场景 | 获取方式 |
|--------|------|----------|----------|
| CERT Insider Threat r5.2 | 2000 用户 / 8000 万记录 / 10328 异常 | 内部威胁基线 | https://doi.org/10.1184/R1/12841247.v1 |
| CERT r6.2 | 22.18GB | 大规模合谋场景 | 同上 |
| LANL Unified Host+Network | 58 天企业日志 | 真实协同攻击参照 | https://csr.lanl.gov/data/ |
| SAGA（arXiv:2411.13138） | 可配置 APT 链 | 合成攻击注入 | 基于 Caldera，本地可复现 |
| BGL/HDFS/Thunderbird | 474 万~1117 万条 | 日志异常检测基准 | 公开免费 |

### 2.2 同类开源项目验证方法论

- **Wazuh/OSSEC**：`wazuh-logtest` 验证规则，`frequency`+`timeframe`+`same_source_ip` 组合规则触发复合告警；提供 SQL 注入、DoS、暴力破解合成用例
- **MITRE CALDERA**（Apache 2.0）：自动化对手仿真，ATT&CK 映射，Sandcat agent 按 tactic 顺序执行 abilities，导出 JSON 事件日志
- **Atomic Red Team**（MIT）：1400+ ATT&CK 技术实现，可被 CALDERA 调用

### 2.3 学术评估指标参考

- CERT r5.2 SOTA：AUC 98.62, DR 100%, FPR 0.05
- CERT r6.2 SOTA：AUC 88.48, DR 80.15%, FPR 0.15
- GroupGuard（arXiv:2603.13940）：群组合谋检测率 88%
- ColludeBench-v0：误报预算校准 10⁻³

---

## 三、分层验证实验方案

### L1 — 基础功能连通性验证

**目标**：确认服务端启动、API 可达、检测引擎初始化、事件注入链路通畅。

| 编号 | 测试项 | 输入 | 操作步骤 | 预期输出 | 判定标准 | 采集维度 |
|------|--------|------|----------|----------|----------|----------|
| L1-1 | 服务端启动 | `auditforwarder-server --config config/server_windows.yaml` | 启动后等待 5 秒，检查日志 | 控制台输出 "manager listening on 127.0.0.1:8443" | 日志含 listening 且无 ERROR | 启动耗时(ms)、错误计数 |
| L1-2 | 登录鉴权 | POST /auth/login `{username, password_sha256}` | 用 admin 账号登录 | HTTP 200 + `{token}` | token 非空且后续请求可用 | 响应延迟(ms) |
| L1-3 | 引擎概览 | GET /collusion/overview（带 Bearer token） | 调用概览接口 | HTTP 200 + `{event_counts:{HIGH:0,MID:0,LOW:0}}` | 计数为 0（空初始态） | 响应延迟(ms) |
| L1-4 | 单事件注入 | POST /collusion/ingest，1 条 CleanEvent | 注入后等窗口到期再查概览 | events.jsonl 出现该事件 | 概览计数 +1 | 注入到落盘延迟(ms) |
| L1-5 | 规则热加载 | PUT /collusion/rules，新增一条测试规则 | 更新后 GET /collusion/rules | 返回含新规则 | 规则列表含新条目 | 响应延迟(ms) |
| L1-6 | 配置热更新 | PUT /collusion/config，修改 short_window_minutes | 更新后 GET /collusion/config | 返回新值 | 配置值匹配 | 响应延迟(ms) |

### L2 — 正常场景功能基准测试

**目标**：在无攻击的正常运维流量下，确认误报率基线（FAR 基线）。

| 编号 | 测试项 | 输入 | 操作步骤 | 预期输出 | 判定标准 | 采集维度 |
|------|--------|------|----------|----------|----------|----------|
| L2-1 | 单人正常操作 | 1 名操作员，10 条单资产组操作（不匹配规则子序列） | 注入后等待 2 个短窗口周期 | 0 条告警 | HIGH=0, MID=0 | 误报数、误报率 |
| L2-2 | 双人合法协同（白名单） | 2 名操作员在白名单组内，20 条协作操作 | 注入后等窗口到期 | 0 条告警（白名单扣分） | 告警数=0 | 误报数 |
| L2-3 | 双人合法协同（有工单） | 2 名操作员，有有效工单，命中 R-003 子序列但工单扣分后 <40 | 注入 + 等窗口 | LOW 或 NONE（工单 deduct 40 拉低） | 无 MID/HIGH | 误报数 |
| L2-4 | 正常基线流量注入 | 500 条随机正常操作（10 操作员 × 50 条/人），持续 30 分钟 | 批量注入 + 等待窗口刷新 | FAR < 5% | 误报/总事件 < 0.05 | 误报率、事件总数 |
| L2-5 | 长窗口正常基线 | 同 L2-4 但持续 4 小时（长窗口） | 注入 + 等 4h 或调长窗口缩短 | 无 HIGH（长窗口 HIGH 降 MID） | HIGH=0 | 误报数 |

### L3 — 合谋攻击场景注入测试（梯度化）

**目标**：验证 5 条规则在不同攻击强度下的检测率（DR）。

#### L3-A 规则单命中测试（基础检测能力）

| 编号 | 规则 | 攻击场景 | 操作员数 | 输入事件序列 | 预期 | 判定标准 |
|------|------|----------|----------|-------------|------|----------|
| L3-A1 | R-001 | 备份销毁：2 人协作删除备份→卸载→快照 | 2 | delete(backup.bak)→unmount(disk)→snapshot(vm) | HIGH（85≥80） | level=HIGH, rule_id=R-001 |
| L3-A2 | R-002 | 密钥拆分：3 人生成→分发→清理密钥 | 3 | generate(key.pem)→distribut(cert)→clean(secret) | HIGH（80≥80） | level=HIGH, rule_id=R-002 |
| L3-A3 | R-003 | 配置篡改：2 人修改→重启→清除 | 2 | modify(app.conf)→restart(service)→clean(logs) | MID（70≥40,<80） | level=MID, rule_id=R-003 |
| L3-A4 | R-004 | 数据外泄：2 人提权→导出→清除 | 2 | grant(db.sql)→dump(mysql)→clean(audit) | HIGH（82≥80） | level=HIGH, rule_id=R-004 |
| L3-A5 | R-005 | 权限晋升：3 人创建角色→加入→提权 | 3 | useradd(role)→assign(member)→exec(admin) | MID（75≥40,<80） | level=MID, rule_id=R-005 |

#### L3-B 梯度化攻击强度测试

**梯度轴**：攻击规模（操作员数）、行为复杂度（规则命中数）、时间跨度（窗口类型）

| 编号 | 梯度 | 场景描述 | 操作员数 | 命中规则数 | 时间跨度 | 预期等级 | 采集指标 |
|------|------|----------|----------|-----------|----------|----------|----------|
| L3-B1 | 极低 | 单人单规则（应不触发合谋） | 1 | 1 | 短窗口 | NONE（min_operator_cnt 不满足） | 漏报检查 |
| L3-B2 | 低 | 2 人单规则，恰好满足 | 2 | 1 | 短窗口 | HIGH/MID | 检测延迟 |
| L3-B3 | 中 | 3 人单规则，超额满足 | 3 | 1 | 短窗口 | HIGH + 画像异常加分 | 检测延迟、score |
| L3-B4 | 高 | 2 人双规则链（R-003+R-004） | 2 | 2 | 短窗口 | 多告警 | 告警数、score |
| L3-B5 | 极高 | 4 人三规则链（R-001+R-002+R-005） | 4 | 3 | 跨窗口 | 多 HIGH 告警 | 告警数、score_sum |
| L3-B6 | 慢合谋 | 2 人单规则，跨 4 小时长窗口 | 2 | 1 | 长窗口 | MID（长窗口降级） | 等级降级验证 |
| L3-B7 | 混合 | 2 人 R-001 + 3 人 R-002，同时注入 | 5 | 2 | 短+长混合 | 2 条独立告警 | 告警隔离性 |
| L3-B8 | 伪造工单 | 2 人 R-003 + 伪造工单 ID | 2 | 1 | 短窗口 | MID+10 分 forged_bonus | 工单核验逻辑 |
| L3-B9 | 有效工单 | 2 人 R-003 + 真实有效工单 | 2 | 1 | 短窗口 | NONE/LOW（-40 分） | 工单扣分验证 |
| L3-B10 | 应急模式 | 2 人 R-001 + emergency_mode=true | 2 | 1 | 短窗口 | MID（HIGH 降级） | 应急降级验证 |

#### L3-C 行为画像异常测试

| 编号 | 场景 | 输入 | 预期 | 判定标准 |
|------|------|------|------|----------|
| L3-C1 | 新协作对首次出现 | 2 名从未协作的操作员，在同一资产组操作 | 画像 pair_counts 异常 | profile_factor > 0 |
| L3-C2 | 资产域偏离 | 操作员突然访问历史从未访问的资产组 | operator_assets 偏离 | profile_factor > 0 |
| L3-C3 | 高频协作（刷量） | 2 人在 1 小时内协作 50 次（超出历史基线） | 画像异常评分上升 | profile_factor 随频次增长 |

### L4 — 边界异常容错测试

**目标**：验证异常输入下的鲁棒性与不崩溃能力。

| 编号 | 测试项 | 输入 | 操作步骤 | 预期 | 判定标准 | 采集维度 |
|------|--------|------|----------|------|----------|----------|
| L4-1 | 空事件注入 | POST /collusion/ingest，body 为 `{}` | 注入 | HTTP 400 或静默丢弃 | 无崩溃、无告警 | 错误码 |
| L4-2 | 字段缺失 | oper_id 为空的事件 | 注入 | 丢弃并记录 | 无崩溃 | 错误日志 |
| L4-3 | 时间戳乱序 | 10 条事件，ts 随机打乱 | 注入 | flush_grace 内容错 | 乱序事件被正确聚合 | 聚合正确率 |
| L4-4 | 超长字段 | res_key 10KB 字符串 | 注入 | 截断处理 | 无崩溃、截断记录 | 处理结果 |
| L4-5 | 高并发注入 | 1000 条/秒，持续 10 秒 | 并发 POST | 全部落盘 | 丢失率 < 1% | 丢失率、延迟P99 |
| L4-6 | 窗口边界 | 事件恰好卡在 short_window 边界 | 精确时间注入 | 正确归入对应窗口 | 窗口归属正确 | 边界正确率 |
| L4-7 | 规则配置错误 | rules.json 格式损坏 | 热加载 | 保留旧规则 + 错误日志 | 无崩溃、配置不变 | 错误日志 |
| L4-8 | 服务端重启恢复 | 注入 100 条后重启服务端 | 重启 + 恢复 | events.jsonl 完整 | 数据零丢失 | 数据完整性 |

---

## 四、评估体系

### 4.1 核心量化指标

| 指标 | 符号 | 计算公式 | 目标值 |
|------|------|----------|--------|
| 检测率（召回率） | DR / Recall | TP / (TP + FN) | ≥ 95%（单规则命中） |
| 误报率 | FAR / FPR | FP / (FP + TN) | ≤ 5%（正常基线） |
| 精确率 | Precision | TP / (TP + FP) | ≥ 90% |
| F1 分数 | F1 | 2·P·R / (P+R) | ≥ 0.92 |
| 首报延迟 | Latency | 从攻击注入到首条告警生成的时间差 | 短窗口 ≤ 15min + flush_grace |
| 风险评分准确度 | Score Accuracy | 命中规则 base_score 与实际 total_score 偏差 | 偏差 ≤ ±5 分 |
| 吞吐量 | Throughput | 每秒正确处理事件数 | ≥ 1000 events/s（L4-5） |
| 数据完整性 | Integrity | 重启后 events.jsonl 行数 / 注入数 | = 100% |

### 4.2 混淆矩阵定义

```
                实际合谋攻击    实际正常操作
检测为合谋攻击      TP              FP
检测为正常          FN              TN
```

- **TP**：注入的合谋攻击被检测为 HIGH/MID
- **FN**：注入的合谋攻击未被检测（LOW/NONE 或规则未命中）
- **FP**：正常操作被误报为 HIGH/MID
- **TN**：正常操作正确判为 LOW/NONE

### 4.3 评估分级标准

| 等级 | DR | FAR | F1 | 延迟 | 结论 |
|------|-----|-----|-----|------|------|
| 优秀 | ≥95% | ≤2% | ≥0.95 | ≤15min | 可投产 |
| 合格 | ≥85% | ≤5% | ≥0.85 | ≤20min | 可上线 |
| 不合格 | <85% | >5% | <0.85 | >20min | 需优化 |

---

## 五、梯度化攻击强度测试用例明细

### 5.1 梯度设计矩阵

| 强度等级 | 操作员数 | 命中规则数 | 时间窗口 | 资产组数 | 工单状态 | 预期难度 |
|----------|----------|-----------|----------|----------|----------|----------|
| L0-极低 | 1（不满足） | 1 | 短 | 1 | 无 | 不应触发 |
| L1-低 | 2（恰好） | 1 | 短 | 1 | 无 | 基础检测 |
| L2-中 | 3（超额） | 1 | 短 | 1 | 无 | 画像加分 |
| L3-高 | 2 | 2 | 短 | 2 | 无 | 多告警 |
| L4-极高 | 4 | 3 | 跨窗口 | 3 | 伪造 | 复合场景 |
| L5-慢合谋 | 2 | 1 | 长 | 1 | 无 | 降级验证 |
| L6-混合 | 5 | 2 | 混合 | 2 | 混合 | 隔离性 |
| L7-反检测 | 3 | 1 | 短 | 1 | 有效 | 工单扣分 |

### 5.2 反检测对抗测试用例

| 编号 | 对抗手法 | 输入特征 | 预期 | 验证目标 |
|------|----------|----------|------|----------|
| L5-A1 | 工单伪装 | 合谋 + 伪造工单 ID（不在 workorders.json） | forged_ticket_bonus +10 → 等级更高 | 伪造检测能力 |
| L5-A2 | 白名单伪装 | 合谋 + 使用白名单内操作员 ID | 白名单预检跳过 → 不检测 | 白名单严格性 |
| L5-A3 | 资产组伪装 | 合谋目标匹配 general-group 而非精确组 | base_score 不触发规则 | 资产组精确性 |
| L5-A4 | 时序打散 | R-001 三步操作分散到 14 分 59 秒 | 短窗口内应触发 | 窗口边界鲁棒 |
| L5-A5 | 时序打散 | R-001 三步分散到 15 分 1 秒 | 跨窗口应漏报或走长窗口 | 窗口边界 |
| L5-A6 | 操作员伪装 | 1 人用 2 个 oper_id 轮流操作 | distinct_op_count=2 → 触发 | 身份识别能力 |

---

## 六、实验环境配置

### 6.1 硬件与软件环境

| 项目 | 配置 |
|------|------|
| OS | Windows 10/11 或 Linux |
| 编译器 | MSYS2 ucrt64 g++ 16.1.0 或 GCC 9+ |
| 构建 | CMake 3.16+ + Ninja |
| 测试框架 | Google Test（ctest 用 mingw64 版） |
| 服务端 | auditforwarder-server --config config/server_windows.yaml |
| 端口 | 8443（默认） |
| 数据目录 | data/server/（events.jsonl, policies/） |

### 6.2 测试工具

| 工具 | 用途 | 命令示例 |
|------|------|----------|
| curl / Invoke-WebRequest | API 调用 | `curl -X POST http://127.0.0.1:8443/collusion/ingest -H "Authorization: Bearer $TOKEN" -d @event.json` |
| Python 脚本 | 批量注入与结果采集 | `python scripts/test_collusion_inject.py` |
| jq | JSON 结果解析 | `curl ... \| jq '.event_counts'` |
| ctest | 单元测试 | `C:\msys64\mingw64\bin\ctest.exe --test-dir build` |

### 6.3 事件注入模板（CleanEvent JSON）

```json
{
  "oper_id": "op_test_001",
  "ts_ms": 1696953600000,
  "server_id": "host_test_01",
  "op_type": "delete",
  "res_key": "backup_2026.bak",
  "op_param": "rm -f /backup/2026.bak",
  "work_order_id": "",
  "raw": "{\"original\":\"...\"}"
}
```

---

## 七、实验验证报告模板

### 7.1 实验基本信息

| 项目 | 内容 |
|------|------|
| 实验编号 | EXP-YYYYMMDD-NNN |
| 实验日期 | YYYY-MM-DD |
| 执行人员 | ________ |
| 环境版本 | AuditForwarder v1.2.0 + commit hash |
| 服务端配置 | config/server_windows.yaml（附 diff） |
| 引擎配置 | policies/collusion_config.json（附快照） |
| 规则版本 | policies/collusion_rules.json（附快照） |

### 7.2 测试用例执行记录表

| 用例编号 | 层级 | 测试项 | 输入摘要 | 操作步骤 | 实际输出 | 预期输出 | 结果(P/F) | 延迟(ms) | 备注 |
|----------|------|--------|----------|----------|----------|----------|-----------|----------|------|
| L1-1 | L1 | 服务端启动 | — | 启动 | listening on 8443 | 同左 | P | 3200 | — |
| L1-2 | L1 | 登录 | admin | POST /auth/login | 200+token | 200+token | P | 45 | — |
| ... | ... | ... | ... | ... | ... | ... | ... | ... | ... |
| L3-A1 | L3 | R-001 单命中 | 2人3事件 | 注入+等窗口 | HIGH | HIGH | P | 901000 | — |
| L3-B6 | L3 | 慢合谋 | 2人长窗口 | 注入+等4h | MID | MID | P | — | 降级验证 |
| L4-5 | L4 | 高并发 | 10000条 | 并发POST | 丢失0 | 丢失<1% | P | — | P99=12ms |

### 7.3 量化指标汇总表

| 指标 | L1 | L2 | L3 | L4 | 综合 | 目标 | 达标 |
|------|----|----|----|----|----|----|------|
| 检测率 DR(%) | — | — | ___ | — | ___ | ≥95 | ___ |
| 误报率 FAR(%) | — | ___ | — | — | ___ | ≤5 | ___ |
| 精确率(%) | — | — | ___ | — | ___ | ≥90 | ___ |
| F1 | — | — | ___ | — | ___ | ≥0.92 | ___ |
| 首报延迟(ms) | — | — | ___ | — | ___ | ≤900000 | ___ |
| 吞吐量(ev/s) | — | — | — | ___ | ___ | ≥1000 | ___ |
| 数据完整性(%) | — | — | — | ___ | ___ | 100 | ___ |

### 7.4 混淆矩阵

```
                实际合谋    实际正常
检测为合谋      TP=___      FP=___
检测为正常      FN=___      TN=___
```

### 7.5 问题定位与分析

| 问题编号 | 关联用例 | 现象描述 | 根因分析 | 影响等级 | 修复建议 | 状态 |
|----------|----------|----------|----------|----------|----------|------|
| ISS-001 | L3-A3 | R-003 预期 MID 实际 LOW | base_score=70 但 profile_factor=0，总分 70<80 且≥40 应 MID | 中 | 检查 score_mid 阈值或 rule_factor 计算 | 待修 |
| ... | ... | ... | ... | ... | ... | ... |

### 7.6 实验结论

| 评估维度 | 结果 | 达标 | 说明 |
|----------|------|------|------|
| 基础连通性 | ___/6 通过 | ___ | L1 层 |
| 正常基线 | FAR=___% | ___ | L2 层 |
| 攻击检测 | DR=___% | ___ | L3 层 |
| 边界容错 | ___/8 通过 | ___ | L4 层 |
| 综合评定 | ___ 级 | ___ | 优秀/合格/不合格 |

### 7.7 可复现性声明

- [ ] 所有测试事件模板已归档至 `tests/fixtures/collusion/`
- [ ] 注入脚本已归档至 `scripts/test_collusion_inject.py`
- [ ] 引擎配置快照已留存（config + rules + workorders）
- [ ] 服务端 commit hash 已记录
- [ ] 实验步骤可在干净环境独立执行，不依赖私有数据

---

## 八、实验执行流程

### 8.1 前置准备

```powershell
# 1. 构建项目
cmake --build build

# 2. 启动服务端（后台）
.\build\auditforwarder-server.exe --config config\server_windows.yaml

# 3. 登录获取 token
$loginRsp = Invoke-WebRequest -Uri "http://127.0.0.1:8443/auth/login" -Method POST `
  -Body '{"username":"admin","password_sha256":"<sha256>"}' -ContentType "application/json"
$token = ($loginRsp.Content | ConvertFrom-Json).token
$headers = @{ Authorization = "Bearer $token" }
```

### 8.2 L1 连通性验证

```powershell
# L1-3: 引擎概览
Invoke-WebRequest -Uri "http://127.0.0.1:8443/collusion/overview" -Headers $headers

# L1-4: 单事件注入
$body = '{"events":[{"oper_id":"op_test","ts_ms":1696953600000,"server_id":"h01","op_type":"delete","res_key":"backup.bak","op_param":"rm","work_order_id":"","raw":""}]}'
Invoke-WebRequest -Uri "http://127.0.0.1:8443/collusion/ingest" -Method POST -Headers $headers -Body $body -ContentType "application/json"
```

### 8.3 L3 攻击注入（以 R-001 为例）

```powershell
# L3-A1: R-001 备份销毁合谋，2 人 3 事件
$events = @{
  events = @(
    @{ oper_id="op_a"; ts_ms=1696953600000; server_id="h01"; op_type="delete";   res_key="backup.bak";   op_param="rm"; work_order_id="" },
    @{ oper_id="op_b"; ts_ms=1696953605000; server_id="h01"; op_type="unmount";  res_key="disk_lvm";    op_param="umount"; work_order_id="" },
    @{ oper_id="op_a"; ts_ms=1696953610000; server_id="h01"; op_type="snapshot"; res_key="vm_snap_01";  op_param="snapshot create"; work_order_id="" }
  )
} | ConvertTo-Json -Depth 5
Invoke-WebRequest -Uri "http://127.0.0.1:8443/collusion/ingest" -Method POST -Headers $headers -Body $events -ContentType "application/json"

# 等待短窗口到期（15 分钟）+ flush_grace（10 秒）后查询
Start-Sleep -Seconds 910
$overview = Invoke-WebRequest -Uri "http://127.0.0.1:8443/collusion/overview" -Headers $headers
# 预期：event_counts.HIGH >= 1
```

### 8.4 结果采集

```powershell
# 导出全部事件用于离线分析
Invoke-WebRequest -Uri "http://127.0.0.1:8443/collusion/events/export" -Headers $headers -OutFile "results/collusion_events.ndjson"

# 用 jq 统计
# cat collusion_events.ndjson | jq -s 'group_by(.level) | map({level: .[0].level, count: length})'
```

---

## 九、可复现性保障

1. **测试数据全部合成**：所有攻击事件均为构造的 CleanEvent JSON，不依赖 CERT/LANL 等外部数据集（外部数据集仅作校准参考）
2. **脚本化注入**：所有测试用例封装为可重复执行的脚本，输入参数明确
3. **配置快照**：每次实验前留存 collusion_config.json + collusion_rules.json + collusion_workorders.json 快照
4. **独立可执行**：每个用例编号（L1-1~L4-8）可独立运行，无需前置依赖（除 L1 连通性外）
5. **结果可追溯**：events.jsonl 含完整证据链（raw 字段保留原始 JSON），支持事后审计
6. **环境无特殊依赖**：Windows + MSYS2 标准构建环境，服务端单机即可完成全部实验

---

## 十、附录：测试用例输入模板库

### A. R-001 备份销毁合谋事件模板

```json
[
  {"oper_id":"op_attacker_a","ts_ms":1696953600000,"server_id":"host_victim","op_type":"delete","res_key":"backup_daily.bak","op_param":"rm -f /backup/daily.bak","work_order_id":"","raw":"{}"},
  {"oper_id":"op_attacker_b","ts_ms":1696953605000,"server_id":"host_victim","op_type":"unmount","res_key":"disk_lvm_01","op_param":"umount /dev/lvm_01","work_order_id":"","raw":"{}"},
  {"oper_id":"op_attacker_a","ts_ms":1696953610000,"server_id":"host_victim","op_type":"snapshot","res_key":"vm_snap_destroy","op_param":"snapshot delete vm_snap","work_order_id":"","raw":"{}"}
]
```

### B. R-002 密钥拆分合谋事件模板（3 人）

```json
[
  {"oper_id":"op_key_gen","ts_ms":1696953600000,"server_id":"host_kms","op_type":"generate","res_key":"server_cert.pem","op_param":"openssl genrsa","work_order_id":"","raw":"{}"},
  {"oper_id":"op_key_dist","ts_ms":1696953610000,"server_id":"host_kms","op_type":"distribut","res_key":"client_secret.key","op_param":"grant to app","work_order_id":"","raw":"{}"},
  {"oper_id":"op_key_clean","ts_ms":1696953620000,"server_id":"host_kms","op_type":"clean","res_key":"audit_trail.log","op_param":"rm /var/log/audit","work_order_id":"","raw":"{}"}
]
```

### C. 正常基线操作模板（L2-4）

```json
[
  {"oper_id":"op_dba1","ts_ms":1696953600000,"server_id":"host_db","op_type":"query","res_key":"customer_db.sql","op_param":"SELECT * FROM orders","work_order_id":"WO-2026-001","raw":"{}"},
  {"oper_id":"op_dba2","ts_ms":1696953605000,"server_id":"host_db","op_type":"backup","res_key":"customer_db.sql","op_param":"pg_dump","work_order_id":"WO-2026-001","raw":"{}"}
]
```

### D. 高并发注入脚本（L4-5，伪代码）

```python
import concurrent.futures, requests, time
URL = "http://127.0.0.1:8443/collusion/ingest"
HEADERS = {"Authorization": "Bearer <token>", "Content-Type": "application/json"}
def inject(batch_id):
    events = [{"oper_id": f"op_{i}", "ts_ms": int(time.time()*1000)+i,
               "server_id":"h_stress","op_type":"read","res_key":"general.log",
               "op_param":"cat","work_order_id":"","raw":""} for i in range(100)]
    return requests.post(URL, json={"events": events}, headers=HEADERS).status_code
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
    results = list(pool.map(inject, range(100)))  # 10000 条
print(f"成功: {sum(1 for r in results if r==200)}/{len(results)}")
```

---

> 本方案所有测试用例可在 Windows + MSYS2 标准构建环境下独立执行，不依赖特殊私有环境。外部数据集（CERT/LANL/SAGA）仅作为校准参考，核心验证全部使用合成构造的攻击事件模板。
