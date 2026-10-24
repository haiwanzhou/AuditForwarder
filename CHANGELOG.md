# 更新日志

本项目的改动记录。日期倒序。

---

## 2026-10-24 · 跨机器合谋检测闭环 + 可复现实验靶场

这一版的重心是**让「两个管理员、两台机器」这个真实场景真的能判出来**。
在此之前，系统在单机单进程（两个浏览器会话走同一个采集器）下是正常的，
一旦换成两台机器各跑一个采集端，判定会**静默失败**——日志看着都到了，
告警却一条都不出，而且不报任何错。下面两条修复对应的就是这个。

### 修复

#### 1. 事件按「发生时间」排序，而不是「到达顺序」（`server/src/collusion/collusion.cpp`）

规则的 `op_sequence` 描述的是先后顺序（先改配置 → 再重启服务 → 再清日志），
匹配时顺着事件数组往下比对。原实现用 `push_back` 追加：

- 单机时代客户端按操作顺序逐条上报，追加顺序恰好等于时间顺序，所以一直没暴露；
- 多机上报时，到达顺序由网络与批次节奏决定，**A 机先操作、后上报**很常见。
  队列变成 `[第2步, 第3步, 第1步]`，三步序列判不成立 → **告警直接丢失，日志无任何报错**。

修复：新增 `append_event_ordered()`，按 `ts_ms` 有序插入。
`ingest_json`、`ingest_native_json`、`evaluate_correlation_locked` 三处全部改用它
（关联规则的 `timespan` 与 prune 的「最旧/最新」判断同样假定队列按时间升序，否则会误删未过期事件）。

验证方式：故意倒序灌入（先清日志、再重启、最后改配置），仍能命中 HIGH。

#### 2. 上报队列整批 swap 导致永久发不出去（`client/src/core/remote_client.cpp`）

`send_audit_summaries` 原来把队列整体 swap 出来一次性发送。队列积到上千条时，
body 做到几十 MB → 发送超时 → 整批塞回队列 → 下次更大，形成死锁。

现象极具迷惑性：**心跳一直 ok、chain 通道的批次一直 200，但 operation-logs 一条都到不了服务端**，
合谋检测自然是空的。只看「服务端能收到日志」很容易误判为已经打通。

修复：单次最多取 40 批发送，队列不可能再堆成巨型 body。同时补了诊断日志
（`operation-logs sent batches=N logs=M`），以后这类问题在日志里能直接看见。

#### 3. 清空画像后规则分不够，HIGH 掉成 MID

清算画像后，首次判定没有任何画像加分，规则基础分是唯一来源。
`R-003`（70）/`R-005`（75）低于 `score_high=80`，命中了也显示成 MID，看起来像「没检测到」。
已提到 85。

#### 4. 实验控制台跨机器点击 404（`lab/book_system/backend/templates/console.html`）

控制台把「当前操作对象」存在页面级变量里。一台机器一个标签页时没问题；
**两个人两台机器时**，A 页面存下的卷 id、B 页面根本没有，路径被替换成
`/__MISSING_vol__/` 然后 404。

修复：每一步执行前自己查一次目标（卷查「当前已挂载的」、备份/快照查「最新的」，主键优先 `id`、
没有则用 `name`），B 那台不需要知道 A 那边造了什么名字。

顺带修掉「操作流水永远只显示一条」——日志行的时间戳也用了 `class="t"`，
与清理占位符的判断撞了，导致每记一条就把历史全清掉。

### 新增

#### 操作员身份提取（`client/src/collector/http_proxy_collector.*`、`client/src/core/agent.*`）

跨操作员检测的前提是「日志里能区分是谁」。原先 HTTP 事件的操作员取客户端配置写死的
`operator.id`，同一台机器上所有账号登录都是同一个人，`distinct_op_count >= 2` 永远不成立。

现在从每个请求里解析身份，优先级依次为：

1. `x-af-operator` 请求头（脚本 / 网关注入）
2. `af_operator` Cookie（业务系统登录后下发）
3. `Authorization: Bearer <token>` 的 payload `username`
4. 请求体里的 `username`（登录请求兜底）
5. 仍取不到才回落到配置的 `operator.id`

#### 动作归一化 `<verb>.<object>`（`ActionNormalizer`）

不同来源的动作统一归一成 `delete.backup` / `delete.book` / `clear.logs` / `restart.service`
/ `update.config` 这类二元形式，写入 `attrs["ozsf.action_norm"]`，随 `operation-logs` 以顶层
`action_norm` 上送。

解决的问题：规则原先用裸子串匹配 `delete`，「删除一本书」和「删除备份」分不开，
正常业务也会命中备份销毁剧本。归一化后规则写 `delete.backup` 精确命中；
带 `action_norm` 的事件要求规则关键词必须含 `.`，没有该字段的老事件仍走原子串匹配，保持兼容。

部署位置在 Normalizer 之后、SchemaMapper 之前——必须早于 SchemaMapper，
否则它用 `set_attr_if_empty` 写的值会把归一化结果盖掉。

#### `eager_eval` 增量评估（`config/collusion_config.example.json`）

每接入一条事件就对所属窗口评估一次，不必等 15 分钟窗口结束。只影响「何时评估」，
不影响判定规则本身；LOW 结果不落库，避免刷屏。现场演示必需。

#### 实验靶场 `lab/`

一套可复现的「受管系统 + 双操作员 + 三机部署」环境，用来验证跨操作员合谋检测：

| 路径 | 用途 |
|---|---|
| `lab/book_system/` | 受管系统靶场（Flask + SQLite 图书管理），含管理员操作台与合谋剧本卡片 |
| `lab/verify.py` | 单机自检，11 项 |
| `lab/verify_lan.py` | 局域网双机自检，15 项；含「这个 IP 会不会被采集」探针与 15 分钟窗口边界提醒 |
| `lab/clear_alerts.py` | 清空告警与画像，回到干净基线（默认只重启服务端，不动客户端） |
| `lab/open_lab.bat` / `open_lan.bat` | 单机 / 局域网 一键起环境并打开控制台 |
| `lab/run_scenario.py` | 按剧本批量注入操作 |

靶场本身来自 [karthik5603/Library-Inventory-System](https://github.com/karthik5603/Library-Inventory-System)，
在其上增加了系统类接口（配置 / 重启 / 清日志 / 备份 / 快照 / 数据卷 / 密钥分发）
和供实验点击的操作台。

#### 文档

- `docs/EXPERIMENT_MANUAL.md` — 单人实验手册
- `docs/EXPERIMENT_MANUAL_2P.md` — **双人三机实验手册**（拓扑、配置改哪几行、四个场景逐步操作、
  结果判据、故障排查、答辩问答、现场速查卡）
- `docs/CODE_CHANGE_PLAN.md` — 本次改造的动机与逐项方案
- `docs/EXPERIMENT_PLAN_TASK4.md`、`docs/EXPERIMENT_RESULT_2026-10-24.md` — 实验计划与结果记录

#### 配置

- `config/asset_profiles/book_system.yaml` — 图书系统资产画像（角色基线 + 敏感资源分级）
- `config/collusion_config.example.json` / `collusion_rules.example.json` — 合谋检测配置与规则示例
- `config/client_lab.yaml` / `client_lab_peer.yaml` — 双机部署的两份客户端配置（`host_id` / `data_dir`
  / `listen_port` 分离）

### 变更

- `config/client_windows.yaml` 改为**脱敏模板**（占位符 `<SERVER_IP>`）。原本仓库里这份文件带着
  真实服务器地址，已替换；真实配置保留在本地，开发机通过 `git update-index --skip-worktree`
  使其不参与提交。多机部署要点（`host_id` 必须唯一、`target_hosts` 不支持 CIDR）写进了文件头注释。
- `.gitignore` 增加 Python 缓存、靶场数据库与 `runtime/` 目录（可自动重建）、
  客户端分发包目录（exe/dll 体积大，走 Release 分发）。

### 已知限制

- **`host_allowed()` 会丢掉端口、只比主机名，且不支持 CIDR**：写 `192.168.1.0/24` 不生效，
  必须逐个列 IP。
- **15 分钟固定窗口有硬边界**：`ws = ts - (ts % win)`，跨 `:00/:15/:30/:45` 会把一次合谋
  切成两半，判不出来。`verify_lan.py` 会打印距边界剩余时间。
- **客户端刚启动有预热期**：这期间带 body 的 POST/PUT 会被静默丢弃（GET 不受影响），
  而合谋实验每一步都是 POST/PUT/DELETE。根因尚未完全定位，目前靠「演示前只重启服务端」规避。
- **`process_win` 拿不到命令行**：需 ETW 4688 或 WMI，取决于审计策略是否开启。
- **HTTPS 走 CONNECT 看不到 URL 路径**：只能记到主机与端口，`res_key` 粒度不足。
- `R-002` / `R-005` 的 `min_operator_cnt = 3`，双人场景凑不齐三个操作员。

### 实测结果

局域网双机（两个客户端实例、两个 `host_id`、两个管理员账号）：

```
verify_lan.py                15/15 通过
R-003 配置篡改链路           100 分  admin + admin2   lab-pc + lab-pc2
R-001 备份销毁合谋           100 分  admin + admin2   6 步全部 200/201
R-004 数据批量外泄           100 分  admin + admin2
对照组（单人删书）            无 HIGH
```
