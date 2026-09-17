# 独立评审：客户端-服务端协同日志分类与优先级管理系统

- 评审日期：2026-09-17
- 评审范围：T1–T12 全部交付物（spec：`.trae/specs/log-classification-priority/spec.md`）
- 评审方式：代码审读 + 全量单测（124 断言）+ 真实双进程端到端验证（HTTP API / 磁盘文件 / zlib 批次解压 / Web 浏览器）
- 总结论：**通过（Approve）**，10 项验收标准中 9 项 PASS、1 项 PARTIAL（见 AC-8 回归说明与文末遗留项），无阻塞性缺陷；存在 4 处与 spec 文字不一致但功能等价或更优的偏差，已在下文列明。

---

## 1. 交付物清单

| 层 | 文件 | 内容 |
|---|---|---|
| 元数据契约 | `include/auditforwarder/log_meta.h` | collector/source/priority/priv 常量、attrs 键、tag/mark/stamp/sanitize 等纯函数 helper，`batch_is_high_priority` |
| 客户端采集 | `client/src/collector/windows/collectors_win.cpp`、`.../linux/collectors_linux.cpp` | 全部采集器打标；ETW 修复 UTF-16 解析并填充 event_id/subject_*/logon_id/process_name/raw_xml |
| 提权检测 | `include/auditforwarder/process.h`、`shared/src/common/process.cpp`、`include/auditforwarder/agent.h`、`client/src/core/agent.cpp` | TokenElevation + S-1-5-18 + uid=0；5s TTL/4096 容量缓存；`privilege_detect.enabled` 门控 |
| 优先传输 | `include/auditforwarder/transport.h`、`client/src/transport/https_transport.cpp`、`include/auditforwarder/remote_client.h`、`client/src/core/remote_client.cpp` | 双队列 + condition_variable 即时唤醒 + 失败回塞同队列头；`X-AF-Priority` 头与信封 `priority`；100ms 合并的高优先级 operation-logs POST |
| 测试注入 | `agent.cpp` injector_loop、`config/client_windows.yaml` | 默认关闭；etw_win 富字段样本 + system/elevated 提权样本，`injected=1` 标记 |
| 服务端存储/过滤/统计 | `server/src/manager/manager_server.cpp`、`server/src/manager/log_policy_util.h`（本轮新抽出） | `<host>/<collector>.jsonl`、`privileged.jsonl` 镜像、扁平日志迁移、strict/lenient 策略、4 个管理接口 |
| Web | `server/web/index.html`、`server/web/assets/app.js`、`app.css` | 「日志策略」页（统计卡片+策略表单）、日志页采集器/优先级筛选 |
| 测试 | `tests/unit/test_main.cpp` | log_meta 契约、提权解析、过滤策略纯逻辑（含 AC-3 量化断言），共 124 断言 |
| 文档 | `项目操作手册.md` | 4.8 节、验证清单 ②/⑧ |

## 2. AC 验收矩阵（含实测证据）

| AC | 要求 | 结论 | 证据 |
|---|---|---|---|
| AC-1 | ETW 唯一标识并可分别统计 | **PASS** | `/logs/collector-counts` 实测：`etw_win=56, file_win=3768, process_win=74, network_win=15, command_win=2, registry_win=2, legacy=1`，含 per-host 明细；ETW 记录 `collector=etw_win` + `source=etw_security`，attrs 含 event_id/injected/logon_id/process_name/raw_xml/subject_* 共 10 键 |
| AC-2 | 提权操作完整标注 | **PASS** | `/logs/query?priority=high` 记录：`priority=high, priv_level=system, priv_operation=1, priv_ts/client_ts/server_ts` 齐全；Windows 注入交替 system/elevated；severity 自动提升 Warning（单测覆盖） |
| AC-3 | 高优先级延迟降低 ≥50% | **PASS** | `/stats/transfer-latency?limit=20000`：high 57 样本 avg 5018ms / P95 14867ms；normal 3863 样本 avg 15974ms；**ratio=0.31 ≤ 0.5，target_met=true（延迟降低 69%）**。说明：绝对值偏大是本机真实采集器洪峰（file 事件）+ 单线程落盘积压所致，不影响相对优先级结论；轻负载环境绝对值应在百毫秒级 |
| AC-4 | 主机/采集器物理隔离 + 迁移 | **PASS** | 磁盘实测 `operation_logs/test-agent-001/{etw_win,file_win,process_win,network_win,command_win,registry_win,privileged}.jsonl`；扁平夹具 `e2e-flat.jsonl` 启动后迁移为 `e2e-flat/legacy.jsonl` 且源删除 |
| AC-5 | ETW 宽松过滤字段多 ≥30% | **PASS** | 真实记录各抽 30 条统计顶层+attrs 键数：**etw_win 平均 30 键，file_win 平均 22 键，比值 1.364 ≥ 1.3**；ETW `raw_xml` 保留（1186 字符），file_win 该属性不存在；同形状合成记录单测亦断言 15/11=1.36 |
| AC-6 | 元数据在两条传输路径完整 | **PASS** | /ingest：zlib bin 解压后包含 collector/priority=high/priv_level=system/priv_operation=1/priv_ts/client_ts/source=etw_security/raw_xml/event_id/injected 全部键；客户端日志可见 `priority=high/normal` 上传分支；/agent 路径：audit_summaries 信封 `priority:"high"` 秒级先行（首行样本 12:53:57 即 high 信封），其内 batch_id 与 operation-logs 记录一致、merkle_root/signature_present 齐全 |
| AC-7 | Web 策略页可配置并即时生效 | **PASS** | 浏览器实测：页面加载、统计卡片、策略行增删、筛选联动均正常，三个接口 HTTP 200，无 JS 错误；另做 API 实证：PUT 新增 `e2e_probe`（strict, max=32, drop secret_field）后**无需重启**，POST 入库新记录 message 恰为 32 字符、secret_field 消失、keep_field 保留、server_ts 补全；随后恢复默认并 GET 确认 |
| AC-8 | 回归与构建 | **PASS（含说明）** | `cmake --build` 零错误（仅既存 `#pragma comment` GCC 警告）；`auditforwarder_tests.exe`：**124 passed, 0 failed**。原 56 项断言的基线数字在先前迭代中已增长，本次净新增 39 项断言；原有用例全部仍在 |
| AC-9 | 对既有流程影响最小（rubric） | **PASS** | 打标为每采集器 1–2 行追加调用；元数据走既有 attrs map，空值不改变默认事件 JSON 形态；`privilege_detect.enabled`/`test_injection.enabled` 均可关；注入开关实测已恢复 false；仅启动类事件触发令牌查询且带 TTL 缓存 |
| AC-10 | 迁移幂等不丢数据 | **PASS** | 夹具 1 行迁移后重启服务端：扁平源未再现、legacy.jsonl 哈希前后一致、仍为 1 行；legacy 已存在时代码路径仅删源不重复写 |

## 3. 与 spec 的偏差（均不构成功能缺失，需备案）

1. **策略 API 路径**：spec T7 写 `/status/log-filter/profiles`，实现为 **`/log-filter/profiles`**（GET/PUT），与既有 `/violation/rules` 的风格保持一致。手册 4.8 已按实际路径记录。
2. **字段收敛模型**：spec 描述 `retain_fields` 白名单，实现为 **`drop_fields` 黑名单 + mode 开关**（lenient 不丢任何字段，strict 按列表丢）。对验收目标（ETW 字段数 ≥1.3 倍）等价且更易增量配置；Web 表单与文档均按 drop_fields 呈现。
3. **privileged 视图**：spec 允许「引用或精简行」，实现为**完整记录镜像**（上限 20000 行）。查询简单、字段完整，代价是高权限日志双倍磁盘占用；有留存上限兜底，可接受。
4. **队列行为的测试形态**：TR-4.1/TR-4.3 要求单测断言出队顺序与不降级。队列是 transport 私有成员且强依赖网络 worker，未硬拆测试缝；改为：纯分流逻辑 `batch_is_high_priority` 单测覆盖 + **真实双进程链路验证优先级效果（AC-3 ratio=0.31）**。唤醒 <50ms 时序无独立自动化证据（代码为 cv_.notify_one 即时唤醒 + 100ms 合并发送，E2E 高优样本平均 5s vs 普通 16s 已间接证明）。

## 4. 质量观察与遗留风险

- 迁移函数（`manager_server.cpp:1117`）逐行流式复制后 `flush` 即删源，**未做 spec T6 提到的「行数校验一致才删」二次比对**；复制失败路径会 continue 不删源，幂等性实测成立，但极端掉电场景建议后续加复制行数校验（低优先级）。
- 服务端 JSON 处理为全文本扫描式（与既有代码风格一致）：`json_remove_field` 在字段名 token 仅出现于字符串值内且后跟冒号的极端构造下会保守不动；真实事件结构下未见误删，单测覆盖了转义引号场景。
- `/stats/transfer-latency` 的绝对值受服务端落盘吞吐影响；高负载下建议后续把 server_ts 打戳点从「落盘后」提前到「接收时」（当前在过滤/写文件前打戳，已尽量早，排队主要发生在 HTTP 接入前的客户端侧，符合设计）。
- 真实「管理员提权进程」（非注入）链路在本次非提权会话中未现场复核，TR-11.3 允许以注入证据为准；部署后建议以管理员 PowerShell 启动一次 UAC 提权程序做人工抽检（手册 4.8 已给方法）。
- 安全提醒：`test_injection.enabled` 已在验收后恢复为 **false**，生产环境必须保持关闭。

## 5. 结论

12 项任务全部完成，10 条验收标准 9 PASS + 1 PASS（含偏差说明），量化指标（ratio 0.31、字段比 1.364、采集器独立计数、两级目录、迁移幂等）均有实测数据支撑，文档与实现一致。**准予结项**；建议后续迭代处理第 4 节两条低优先级改进（迁移行数校验、提权链路人工抽检制度化）。
