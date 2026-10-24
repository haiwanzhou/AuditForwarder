# 代码修改规划（修订版 v2）

> 核对基准：`b6e4f32`（2026-10-24 实测）
> 修订说明：v1 的方向是对的，但有 **4 处技术判断错误** 和 **3 个会直接卡死实验的遗漏**。
> 本版把每一处都落到具体代码行，并给出修正后的实施顺序。

---

## 零、先说结论

### 0.1 v1 说对的部分（已逐条核对，可以直接信）

| v1 的判断 | 核实结果 |
|-----------|----------|
| 规则匹配用 `op_type + res_key + op_param` 拼字符串（`collusion.cpp:629/668`） | ✅ 准确 |
| `res_key` 只有 URI、没有 host（`remote_client.cpp:655` 三元表达式只取 `target.path`） | ✅ 准确 |
| `activity_name` 只是 `read/create/delete` 粗粒度（`processor.cpp:381`） | ✅ 准确 |
| `/ingest` 只落 `.bin`、不写 events 表；events 唯一写入点是 `/agent/operation-logs`（`manager_server.cpp:3200`） | ✅ 准确，v1 对工作总结第五节「跨通道双写」的纠正是对的 |
| 存储是 `<host>/<collector>.jsonl` + `retention_lines` 截断（`manager_server.cpp:3179-3181`） | ✅ 准确 |
| `/db/query` 只有 `host_id`/`table`，无分类过滤（`manager_server.cpp:3608`） | ✅ 准确 |
| `collector_filter.cpp` 213 行、`index.html` 898 行、sim 默认场景 `cert_r42` | ✅ 准确 |

### 0.2 必须修正的 4 处错误

#### 错误 1（最关键）：`op_type` 不是 "恒为 network"，而且 HTTP 方法名会被匹配 → 问题不是"漏报"而是"误报+漏报"

v1 说「`op_type` 恒为 `network`，只有 URL 里恰好出现 `delete` 才命中」。

实际链路是三段叠加，v1 只看了第一段：

1. `clean_event_json` 把 `operation_type` 和 `event_type` **拼起来**（`collusion.cpp:755-762`）：
   ```cpp
   out.op_type = ot.empty() ? et : (et.empty() ? ot : ot + "/" + et);
   ```
   HTTP DELETE 事件 → `operation_type=network`、`event_type=delete` → **`op_type = "network/delete"`**
2. 采集器把 HTTP 方法写进 `message`（`http_proxy_collector.cpp:788`）：
   ```
   message = "DELETE bookhost:18080/admin/backup/1 status=200 req_len=0"
   ```
3. `clean_event_json` 的 `op_param` **回退读 `message`**（`collusion.cpp:768-770`），关键词匹配又**大小写不敏感**（`any_keyword_hit` 用 `to_lower_copy`，`:614`）。

所以真实搜索文本是：
```
network/delete /admin/backup/1 DELETE bookhost:18080/admin/backup/1 status=200 req_len=0
```

**后果一（误报，v1 完全没提）**：任何 `DELETE` 请求都能命中 R-001 第一步的 `delete` 关键词——**包括正常删一本书**（`DELETE /books/123`）。两个编辑各删一本书，就把 R-001 的前两步消耗掉了。

**后果二（漏报，但机制和 v1 说的不一样）**：真正漏的不是"URL 没 delete 字母"，而是**用 POST 做删除**的系统（`POST /api/storage/purge`）——`message` 里只有 `POST`，`op_type=network/create`，`purge` 又不在 R-001 的 `any_of` 里，整条操作完全隐形。

> 结论不变：**靠关键词子串匹配是不可用的**，但理由要改成"方法名污染 + 命名不可控"，而不是 v1 说的"op_type 太粗"。

#### 错误 2：内置规则的关键词写错了

v1 写「`collusion.cpp:284` 的 `default_rules_json()`：`delete_backup` / `unmount` / `snapshot` / `export` / `dump`」。

实际 `default_rules_json()` 在 `:289` 起，内置 **7 条**规则（R-001~R-007，不是注释里说的 5 条），R-001 的 `any_of` 是：

```json
[{ "any_of": ["delete", "remove", "删除"] },
 { "any_of": ["unmount", "detach", "卸载", "取消挂载"] },
 { "any_of": ["snapshot", "快照"] }]
```

即：**没有 `delete_backup` 这个词**，`delete` 是裸关键词。这正是错误 1 里误报的根源。

#### 错误 3：`ActionNormalizer` 放在 `SchemaMapper` **之后**会写不进去

v1 的 1.2 写「SchemaMapper 之后加一个 ActionNormalizer」。

但 `SchemaMapper` 写 `activity_name` 用的是 **`set_attr_if_empty`**（`processor.cpp:381`，实现见 `:300-304`：`if (it == end() || it->second.empty())` 才赋值）。

也就是说 `SchemaMapper` 一跑，`ocsf.activity_name` 就变成 `delete` 了，后面再放归一化层，用同样的写法改不动。

**修正**：`ActionNormalizer` 必须排在 `SchemaMapper` **之前**（处理器链在 `agent.cpp:277-280`：`Normalizer → SchemaMapper → PIIMasker → Deduper`），插到 `Normalizer` 和 `SchemaMapper` 中间；或者留在后面但**直接覆盖** `attrs[kSchemaActivityName]`，不能用 `set_attr_if_empty`。

#### 错误 4：`638 项通过` 这个基线在 MSVC 下复现不了

`tests/unit/test_main.cpp:616` 和 `:619` 在 MSVC 19.41 下**直接编译失败**：

```
error C2017: 非法的转义序列
error C3688: 文本后缀"b"/"y"无效
```

原因是这两行把含 `\"` 的 JSON 写成了 `R"(...)"` 形式，MSVC 没按 raw string 解析。实测 `cmake --build --target auditforwarder_tests` 直接失败，**根本产不出 `auditforwarder_tests.exe`**。

所以：
- 「638 项通过」是 MinGW/`ninja` 环境的数字（工作总结第八节的构建命令就是 `C:\msys64\...\ninja.exe`），**不是 MSVC**
- 本机现在这套 MSVC 构建里，第八节那条验收项**无法执行**
- 静态 `AF_EXPECT` 计数是 **615**，运行时 638 应该包含循环内重复计数——但这个数当前验证不了

> 要么先修这 2 行（改成 `R"JSON({...})JSON"` 自定义分隔符），要么验收时明确改用 MinGW 构建。

### 0.3 v1 完全没提、但会直接卡死实验的 3 个硬阻塞

#### 阻塞 1（比归一化更前置）：进程命令行根本没进可匹配字段 → R-001 第 2、3 步在真实日志下永远命不中

| 环节 | 代码位置 | 实际行为 |
|------|----------|----------|
| 进程采集器 | `collectors_win.cpp:478` | `ev.message = "process start: " + name` —— **只有进程名** |
| ETW 4688 命令行 | `collectors_win.cpp:684-686` | 命令行写进 `attrs["command_line"]`，**不进 message** |
| 服务端取参数字段 | `collusion.cpp:768-770` | `op_param` 只回退读 `message`，**不读 `attrs.command_line`** |

推演一条真实操作 `mountvol X: /D`：
```
op_type = "command/execute"
res_key  = ""（进程事件没有 target.path，会命中 target.address，通常也是空）
op_param = "process start: mountvol.exe"
搜索文本 = "command/execute  process start: mountvol.exe"
```
→ 里面**没有** `unmount` / `detach` / `卸载` / `取消挂载` → R-001 第 2 步**不可能命中**。

`vssadmin delete shadows` 同理：`message` 里只有 `vssadmin.exe`，没有 `snapshot` / `快照`。

**这意味着：即使把动作归一化做得再完美，只要命令行进不了解析字段，`备份销毁` 这个最核心的剧本就跑不出来。** 这是第一优先级，必须排在归一化之前（或同批）。

补充：ETW 4688 那条路还需要管理员权限订阅 Security 日志——本机普通权限运行实测报 `etw: failed to subscribe to Security log`，采不到。

#### 阻塞 2：`operator_id` 与资产画像的角色表对不上 → 画像整体不生效

- `config/asset_profiles/book_system.yaml:50-52` 写的是 `op_sjg: admin` / `op_guest: reader`
- 实际部署的 `config/client_windows.yaml` 里 `operator.id` 是客户端写死的固定标识

画像里的 `operator_roles` 一个都对不上，于是：
- `denied_actions: [delete_backup]` 不会触发
- `allowed_actions` 越权判断不会触发
- `profile_max_factor` 那一路加分全部为 0

**这是"实验做了但没有画像证据"的直接原因**，v1 只说「画像与规则对齐」，没指出对不上的具体位置。

#### 阻塞 3：两个配置加载路径的坑 + 受管系统本身还没部署

1. `config/asset_profiles/book_system.yaml` **放在仓库里不会被读取**。服务端读的是 `<data_dir>/asset_profiles/`（`manager_server.cpp:1954-1961`），必须**复制过去**。
2. `target_systems` 必须和 `ocsf.target_system` 完全一致。实测解析规则（`processor.cpp:349-356`）：取 `http.host`，**端口非 0 就拼上 `host:port`**。所以访问 `bookhost:18080` 得到 `bookhost:18080`；若走 80 端口则变成 `bookhost:80`——画像里两个都要留，或统一端口。
3. **图书管理系统本身还没有**（工作总结第三节已标"未做：需要你朋友提供系统"）。这是所有代码改动的前置，没有它整套实验无从谈起。

> **已解决（2026-10-24）**：受管系统已选定并落地到 `lab/book_system`，见 0.4。

### 0.4 受管系统已选定，但 5 条规则里 4 条演不出来（第 4 个硬阻塞）

#### 实验边界：只做**管理员之间的合谋**（高权限内部人）

这条必须先钉死，否则剧本会跑偏：

| 项 | 规定 |
|---|---|
| 参与者 | **全部是管理员级账号**（super_admin / admin1 / admin2，或 admin + librarian 这种有管理权的员工） |
| 普通用户 | **不作为合谋主体**，只在业务数据层面出现（被删的书、被改的借阅记录） |
| 单步合规 | 每个管理员的每一步都在 `allowed_actions` 内，权限校验全部通过，单条审计全绿 |
| 检测依据 | 只能靠**跨人聚合 + 时序组合**，不能靠"权限不足" |
| 天然对照组 | **单个管理员做完同样的全套操作不会告警**——聚合入口要求 `distinct_op_count >= 2`（`collusion.cpp:372`），单人集合直接丢弃。这正好证明检测的是合谋，不是越权 |

**推论**：`R-006 同一操作员导出后清除` 是**单人规则**，不属于本项目定义的范围。它有 80 分基础分，会在实验里制造"单人也能 HIGH"的假象，必须单独标注为负样本，不能计入合谋检出率。

#### 选型

`karthik5603/Library-Inventory-System`，已落在 `lab/book_system`（269 KB）：

- **跨平台无绑定**：`database.py:2-7` 用 `pathlib` + `__file__` 定位数据库；前端 `fetch` 走同源相对路径；依赖只有 Flask / Werkzeug
- 自带 `admin` / `librarian` / `member` 三角色和 REST 接口，`admin` 与 `librarian` 正好是"两个有管理权的员工"

#### 规则覆盖矩阵（按现有系统能力实测）

| 规则 | 资产组 | 需要的高权限动作 | 现有系统 | 结论 |
|---|---|---|---|---|
| R-001 备份销毁 | backup-group | 删备份 → 卸载卷 → 删快照 | 无这三个概念 | ❌ 需加运维面 |
| R-002 密钥拆分 | key-mgmt-group | 生成密钥 → 分发 → 清审计 | 无密钥管理 | ❌ 需加密钥模块（可选） |
| R-003 配置篡改 | sys-config-group | 改配置 → 重启服务 → 清日志 | 无系统配置接口 | ❌ 需加 |
| R-004 数据外泄 | db-group | 授予导出权 → 批量导出 → 清审计 | 有图书数据，无提权/导出接口 | ⚠️ 需补两口 |
| R-005 权限晋升 | `*` | 建高权角色 → 加人 → 新账号操作 | **已有** user/role 接口 | ✅ 唯一可直接演 |
| R-006 单人导出清除 | operator | 导出 → 清日志 | — | ⛔ 单人规则，排除 |
| R-007 同对象提权外泄 | object | 提权 → 导出 | 缺提权接口 | ⚠️ 需补一口 |

**结论**：纯图书 CRUD 只能演 R-005。要演"不止一种"，必须给系统补一个**运维面**（备份 / 快照 / 存储卷 / 系统配置 / 审计日志）。这不是为演示硬凑——真实管理系统都有"备份与恢复""系统设置"页面，缺了反而不可信。

#### 资产组匹配的隐藏门槛

`collusion.cpp:697-703` 用 `asset_groups[].patterns` 对 `res_key` 做通配匹配，而 `res_key` 来自上报的 `target`，值是 **URL 路径**（`http_proxy_collector.cpp:776` 写 `target.path`；`remote_client.cpp:656` 上报时优先 path）：

| 请求 | target | 匹配结果 |
|---|---|---|
| `DELETE /api/backup/bk_01` | `/api/backup/bk_01` | 命中 `*backup*` → backup-group ✅ |
| `PATCH /api/storage/volume/1/unmount` | 不含 backup/snapshot | 落到 `general-group` ❌ |

而规则要求 `asset_group == "backup-group"`。**三个动作只要不在同一资产组，聚合集合就凑不齐，规则永不命中。** 必须在 collusion 配置里把 `*storage*`、`*volume*`、`*unmount*` 并入 backup-group（配置热加载，不用改代码）。

#### 第 4 个阻塞：一台客户端只能报一个操作员

- `remote_client.cpp:641-644`：`operator_id` 优先取事件 attrs，缺失回退 `cfg_.operator_id`（客户端配置的固定值）
- `http_proxy_collector.cpp`：grep `operator_id` / `Authorization` / `username` **零命中**——根本不提取操作员

后果：**同一台机器上，不管用 admin 还是 librarian 登录，日志里的操作员都是同一个固定的 `operator.id`**，"跨操作员"从根上不成立。

最小改法：HTTP 采集器解析 `Authorization: Bearer <token>`，base64 解 payload 取 `username`，写入 `attrs[kOperatorId]`。两个浏览器会话就成了两个真实操作员，改动不足 30 行，且对任何"token 里带用户"的系统通用。

---

## 一、你现在准确要做的事

用户的目标是：**基于新的采集器 + 合谋检测模块，在一个真实管理系统上跑合谋实验，并拿出证据链。**

拆成三层，顺序不能乱：

### 第 1 层：前置（不做完，后面全是空跑）

- [x] **1.1 给图书系统补运维面**（✅ 已完成）：`lab/book_system/backend/ops.py` 新增 24 个管理员级接口，覆盖备份 / 快照 / 存储卷 / 系统配置 / 审计日志 / 密钥 / 导出 / 账号编排。冒烟测试 28/28 通过，普通读者访问一律 403。
- [x] **1.2 建管理员账号**（✅ 已完成）：`admin`、`admin2`（role=admin）、`librarian1`、`librarian2`（role=librarian）。`member1` 只是业务对象，不进任何剧本。
- [x] **1.3 把采集打通**：已新增 `config/client_lab.yaml`，`http_proxy.enabled=true`、`target_hosts=[127.0.0.1:18080, localhost:18080]`；实测 `data/server/operation_logs/lab-pc/http_proxy.jsonl` 持续落盘。
- [x] **1.4 把画像落到服务端**（已完成，见 `data/server/asset_profiles/book_system.yaml`）：`config/asset_profiles/book_system.yaml` 复制到 `<data_dir>/asset_profiles/`，`operator_roles` **只映射这三个管理员**；`allowed_actions` 必须覆盖剧本里的每一步、`denied_actions` 一条都不放。这一步是"单步合规"的书面证据——否则告警会被解释成越权拦截，而不是合谋检出。
- [x] **1.5 资产组映射**（✅ 已完成）：`data/server/policies/collusion_config.json` 已把 `*storage*` / `*volume*` / `*unmount*` 并入 backup-group，`*system*` / `*restart*` / `*logs*` 并入 sys-config-group，`*books*` / `*users*` / `*export*` / `*audit*` 并入 db-group。不配这一步，除了 R-005 之外全部哑火。模板存 `config/collusion_config.example.json`（`data/` 被 gitignore，换机器要复制过去）。

### 第 2 层：代码（P0，让"真实日志"能被检测到）

- [x] **2.0 采集器识别操作员身份**：`http_proxy_collector.cpp` 新增 `extract_operator()`，按 显式头 → `af_operator` Cookie → `Authorization: Bearer` 里的 username → 请求体 username 顺序解析，命中即写入 `attrs[operator_id]`（Enricher 不再覆盖）。实测同一台机器三个管理员被正确区分。
- [x] **2.1 让命令行可匹配**：服务端 `clean_event_json()` 把 `process.command_line` 并入 `op_param`，Windows 上 `mountvol`/`vssadmin` 不再只剩进程名。
- [x] **2.2 动作归一化**：新增 `processor::ActionNormalizer`（插在 `Normalizer` 之后、`SchemaMapper` 之前），产出 `ozsf.action_norm = <verb>.<object>`；服务端 `step_hit()` 进入严格匹配（带 `.` 的关键词精确匹配，裸词忽略）。实测 `delete.book` 与 `delete.backup` 彻底分开，对照组不再误报。
- [x] **2.3 入库幂等**：已核实 `/ingest` 只落 `.bin` 原始批次、不写 events 表；真正入库只有 `/agent/operation-logs` 一条路径，不存在重复入库。原文档此条为误判，无需改动代码。

### 第 3 层：实验（全部由管理员执行）

- [x] 3.1 **单管理员基线**：admin1 独自把某剧本全套做完 → 不告警。这是最有力的反证，证明系统抓的是合谋而非越权。
- [x] 3.2 **双管理员剧本**：R-001 备份销毁 / R-003 配置篡改 / R-004 数据外泄 / R-007 提权外泄
- [x] 3.3 **三管理员剧本**：R-002 密钥拆分 / R-005 后门账号（A 建高权角色 → B 把账号加进去 → C 用该账号操作）
- [ ] 3.4 **合法运维对照组**：管理组按真实工单协同做同样的事 → 有工单减分，不升级为 HIGH
- [x] 3.5 导出 `GET /collusion/incident-report` 并逐条核对证据链（操作员、主机、时间、动作、命中步骤）
- [ ] 3.6 统计：检出率 / 误报率 / 证据完整率 / 平均检测时延

---

## 二、P0-1｜让命令行/URI 真正进入检测视野

这是本版相对 v1 新增的**最高优先级**。

### 2.1 服务端：`op_param` 扩成"可匹配文本"

`collusion.cpp:768-770` 目前只读 `op_param → message`。改为依次尝试：

```cpp
op_param = json_string_field(json,"op_param");
if (op_param.empty()) op_param = json_string_field(json,"command_line");  // 新增
if (op_param.empty()) op_param = json_string_field(json,"message");
```

因为客户端把 `attrs` 里的 `command_line` 平铺成了字面键（`remote_client.cpp:669-673` 把 attrs 原样输出），服务端的字符串查找函数**能直接命中**，不需要递归解析 JSON。

### 2.2 客户端：进程事件补命令行（拿不到时降级并标记）

- `process_win`（`collectors_win.cpp:478`）：能取到命令行就写 `message`，同时置 `attrs["command_line"]`；取不到时保留进程名 + 打 `attrs["cmd_line_missing"]="1"`。
- ETW 4688 那条路保持写 `attrs`，但要保证同一进程不会因为两路采集产生两条（正好被 2.3 的幂等键覆盖）。

### 2.3 规则侧兜底：关键词补进程名

即使命令行拿不到，也应让规则能命中"程序本身"：

- R-001 第二步 `any_of` 补 `mountvol`、`diskpart`（卸载卷常用）
- R-001 第三步 `any_of` 补 `vssadmin`、`wbadmin`
- R-004 第二步补 `mysqldump`、`pg_dump`、`mongodump`

**验收**：手工执行 `mountvol X: /D`，`/db/query` 能查到该事件，且 `searchable` 文本里含 `unmount` 或 `mountvol`。

---

## 三、P0-2｜动作归一化（原 v1 第一节，修正位置与字段）

### 3.1 配置文件 `config/action_norm.yaml`

按通道分三类，`pattern → action`：

```yaml
version: 1
http:
  - { action: delete_backup,   methods: [DELETE, POST], uri: "(?i)^/admin/backups?/\\d+" }
  - { action: export_data,     methods: [GET],          uri: "(?i)^/admin/(export|download)" }
  - { action: clear_data,      methods: [POST],         uri: "(?i)/maintain/(clear|truncate|purge)" }
  - { action: grant_role,      methods: [PUT, POST],    uri: "(?i)^/admin/users?/\\d+/roles?" }
  - { action: delete_snapshot, methods: [DELETE],       uri: "(?i)/snapshot" }
process:
  - { action: unmount_volume,  cmd: "(?i)\\bmountvol\\b.*/D" }
  - { action: delete_snapshot, cmd: "(?i)\\bvssadmin\\b.*delete.*shadows" }
  - { action: export_dump,     cmd: "(?i)\\b(mysqldump|pg_dump)\\b" }
file:
  - { action: delete_backup_file, actions: [delete, unlink], path: "(?i)/(backup|bak)/" }
```

### 3.2 实现位置（关键修正）

- **客户端**：新增 `ActionNormalizer`，插在 **`Normalizer` 之后、`SchemaMapper` 之前**（`agent.cpp:277` 那一行前面）。它负责写 `attrs["ocsf.action_norm"]`（新键，避免和 `activity_name` 抢），**或**直接写 `activity_name`——若写后者，必须保证在 SchemaMapper 之前执行。
- **服务端**：`clean_event_json()` 的 `op_type` 改为**优先**读 `ocsf.action_norm`，没有再回退现有链路。
- `res_key` 合成改为 `target_system + "|" + object`，多系统同名 URI 不撞车。

### 3.3 为什么必须放配置

老师的要求是"换一个受管系统只换配置"。归一化表就是受管系统的**动作字典**，和 `asset_profiles/*.yaml` 同层，应支持热加载。

**验收**：给 5 条真实日志样例（HTTP 删备份 / `vssadmin delete shadows` / `mountvol /D` / 文件删除 / 导出），单测断言各自得到预期规范动作名。

---

## 四、P0-3｜入库幂等（原 v1 第二节，保留）

v1 的纠正是对的（`/ingest` 不写 events 表），重复来自**重试重发**。补充一点：幂等键里建议加上 `message` 或 `http.uri` 的哈希——同一秒内两次不同对象的删除，如果 `target` 恰好一样会被误去重。

- [ ] 4.1 幂等键：`(host_id, operator_id, collector, client_ts, operation_type, target, sha256(message))`
- [ ] 4.2 服务端内存 LRU（最近 N 万条）+ events 表唯一索引
- [ ] 4.3 同一操作只产生 1 条 jsonl + 1 行 sqlite
- [ ] 4.4 断网 3 秒后恢复，实测重发

**验收**：制造一次重发，库里仍然只有 1 条。

---

## 五、P1｜日志存储分片与分类（原 v1 第三、四节，合并）

- [ ] 5.1 目录分片：`<host>/<YYYYMMDD>/<collector>.jsonl`（读路径兼容旧布局）
- [ ] 5.2 分块阈值可配：超过 N MB 或 M 分钟换新文件（`<collector>-HHMMSS.jsonl`）
- [ ] 5.3 跨文件检索：`read_jsonl_filtered()` 支持按日期范围遍历分片
- [ ] 5.4 保留期策略化：按 `collector`/`priority` 配 `retention_days`，替代按行数截断
- [ ] 5.5 `/db/query` 增加 `collector`/`category`/`target_system`/`risk_level` 过滤
- [ ] 5.6 `/db/archive` + `/db/import`
- [ ] 5.7 界面显示"当前占用 / 最早记录时间"
- [ ] 5.8 每条事件补 `target_system` / `category`（来源就是第三节归一化结果，不重复造轮子）
- [ ] 5.9 高危动作打标：`delete_backup / delete_snapshot / unmount_volume / export_data / grant_role` → `risk=high`

**验收**：灌 10 万条事件，单文件不超阈值，带筛选查询 p95 < 200ms。

---

## 六、P1｜采集器收尾（原 v1 第五节，保留 + 补充）

- [ ] 6.1 ETW 4688 命令行提取：未开审计策略时要**降级并告警**，不能静默无数据（本机实测就是静默失败）
- [ ] 6.2 HTTP 代理 URI 归一：去 query，`/books/123?t=x` 收敛成 `/books/123`
- [ ] 6.3 采集范围收敛：`http_proxy.target_hosts` 白名单（**现在是空 = 采全部流量**，噪音会淹掉证据）
- [ ] 6.4 传输层：按 `client_ts` 断点续传、失败重发上限、批量大小可配
- [ ] 6.5 筛选逻辑集中到 `collector_filter`

---

## 七、P2｜服务端页面（原 v1 第六节，保留）

- [ ] 7.1 主机列表（在线状态、新接入动态）
- [ ] 7.2 操作员台账
- [ ] 7.3 日志查询（采集器 / 受管系统 / 动作类 / 风险等级四筛选）
- [ ] 7.4 风险事件 + 证据链详情
- [ ] 7.5 危害定级报告导出
- [ ] 7.6 配置中心：页面暴露的代码/JSON 改表单
- [ ] 7.7 主机管理 + 连接请求合并（白名单加 IP）

---

## 八、实施顺序（修正版）

```
⓪ 系统运维面 + 3 个管理员账号（前置，决定能演几条规则）
① 采集器识别操作员身份（P0，没有它就没有"跨操作员"）
② 命令行可匹配（P0）──┬─→ ④ 归一化 ─→ ⑥ 分类/筛选
                        └─→ ⑤ 规则关键词兜底
③ 幂等（P0）──────────→ ⑦ 存储分片
资产组配置映射业务路径（改 collusion 配置，不改代码）
                        ↓
⑧ 剧本：单管理员基线 → 双人 → 三人 → 合法工单对照组
```

三处调整：

- **新增 ⓪（运维面）**：不补这套接口，`R-001/002/003/004` 连触发条件都凑不齐，能演的只剩 `R-005`。
- **新增 ①（操作员身份）**：这是"跨操作员"的前提。缺了它，一台机器上两个管理员登录在日志里是同一个人，聚合集合永远只有 1 个操作员，`distinct_op_count >= 2` 直接丢弃。
- **剧本顺序改了**：先跑"单个管理员做完全套不告警"，再跑双人、三人。这条基线是回应"你怎么证明抓到的是合谋而不是越权"的唯一硬证据。

---

## 九、验收清单（修正版）

- [ ] `AF_EXPECT` 全绿。**注意**：MSVC 下 `test_main.cpp:616/619` 编译失败，需先修 raw string 分隔符，否则这条无法执行（v1 写的"638 项"是 MinGW 基线）
- [ ] `auditforwarder-sim --scenario cert_r42 --operators 4 --normal-events 8` 生成 42 条；投递后分级不得劣化（原基线 HIGH=6 / MID=2 / LOW=3，此数字需在修好测试后重新确认）
- [ ] 一条真实 HTTP 删备份：入库后 `operation_type=delete_backup`，`res_key=bookhost:18080|/admin/backup/3`
- [ ] 一条 `mountvol X: /D`：`searchable` 文本含命令行，能进入同一资产组聚合
- [ ] 一条 `DELETE /books/123`（**正常删书**）：**不得**产生 HIGH 风险事件 —— 这条是新增的误报回归项，v1 没有
- [ ] 画像命中：`operator.id` 的角色在 `book_system.yaml` 里能查到，`denied_actions` 生效

---

## 十、待确认

1. `docs/M5_M8_工作总结与合谋实验方案.md` 第五节说"跨通道双写"，v1 已证伪。那份文档要不要一并更正？
2. 测试的 raw string 编译错误，是我顺手修掉，还是保持原样改用 MinGW 做验收？
3. 图书管理系统选哪个？这决定 `action_norm.yaml` 里 URI 规则的实际写法。
