# 跨操作员合谋实验 · 操作手册

> 目标：让监管端在**不读取业务系统代码、不修改业务系统**的前提下，
> 仅凭采集到的操作日志，把"几个管理员各做一步、单看都合规"的行为判定为合谋，
> 并给出可逐条核对的证据链。

本手册对应代码状态：`main` 分支（动作归一化 + 身份提取 + eager 评估已合入）。
实测结论见第 8 节。

> 两个人、两台管理员电脑 + 一台监管端的局域网实验，看
> **`EXPERIMENT_MANUAL_2P.md`**（分工、点击顺序、现场速查卡）。
> 本手册负责讲原理和五个剧本，那一份负责讲双人怎么配合。

---

## 1. 实验要证明什么

一句判断标准：

> **三个管理员各做一件本职工作以内的事，服务端能把它们串成一次攻击，并指出是谁、哪台机器、什么时间、哪一步。**

| 必须成立的对照 | 判据 |
|---|---|
| 正常业务不误报 | 只删一本书 / 只看列表 → 不产生任何 HIGH |
| 单人不告警 | 同一个人把整条链做完 → 不产生 HIGH（聚合要求 ≥2 个操作员） |
| 跨操作员才告警 | 拆给不同管理员 → 产生 HIGH，且证据链里操作员不同 |
| 动作可区分 | "删一本书"与"删备份"不能混为一谈（靠动作归一化） |
| 证据可回溯 | 每条告警能列出每一步的原始日志（时间/操作员/主机/动作/对象/参数） |

---

## 2. 环境构成

| 组件 | 地址 | 作用 |
|---|---|---|
| 监管服务端 | `127.0.0.1:8443` | 接收日志、聚合判定、出告警与报告 |
| 受管图书系统 | `127.0.0.1:18080` | 被监控的真实业务系统（Flask + SQLite） |
| 采集客户端 | 代理 `127.0.0.1:8888` | 截获对图书系统的 HTTP 操作并上送 |
| 客户端数据目录 | `data/client/` | 本地日志、哈希链批次 |
| 服务端数据目录 | `data/server/` | 操作日志、合谋事件、规则与配置 |

### 2.1 目录约定

```
AuditForwarder/
├─ build/Release/              可执行文件（auditforwarder-server.exe / -client.exe）
├─ config/
│  ├─ client_lab.yaml          实验用客户端配置（服务端指向本机、开启 HTTP 采集）
│  ├─ asset_profiles/          资产画像母本
│  └─ collusion_*.example.json 规则/配置模板
├─ data/
│  ├─ server/                  服务端运行数据
│  │  ├─ policies/             collusion_config.json / collusion_rules.json（热加载）
│  │  ├─ asset_profiles/       服务端实际读取的画像（必须放这里）
│  │  ├─ operation_logs/<host>/<collector>.jsonl
│  │  └─ collusion/events.jsonl
│  └─ client/                  客户端运行数据
└─ lab/
   ├─ book_system/             受管系统源码
   ├─ start_lab.bat            一键启动（Windows）
   ├─ stop_lab.bat             一键停止
   ├─ _srv.bat / _book.bat / _client.bat   单组件启动（explorer 拉起更稳）
   ├─ run_scenario.py          剧本执行器（推荐用于演示）
   └─ reset_lab.py             重置到干净基线
```

### 2.1.1 Python 解释器约定

本机自带的 `python` 不一定装了 Flask，手册统一用托管解释器：

```bat
set PY=%USERPROFILE%\.workbuddy\binaries\python\versions\3.13.12\python.exe
%PY% -c "import flask, werkzeug; print('ok')"
```

下面的命令里出现 `%PY%` 都指这个解释器。

### 2.2 账号

| 账号 | 密码 | 角色 | 用途 |
|---|---|---|---|
| `admin` | `admin123` | 管理员 | 剧本第一步 |
| `admin2` | `admin123` | 管理员 | 剧本第二步 |
| `admin3` | `admin123` | 管理员 | 剧本第三步 / 清审计 |
| `librarian1` / `librarian2` | `lib123` | 馆员（管理级） | 可选，替换 admin2/3 |
| `member1` | `member123` | 普通读者 | **只做业务对象，不参与任何剧本** |

> 实验边界：合谋主体只有管理员。普通读者账号不参与，也不该被判定为合谋方。

---

## 3. 一次性准备

```bat
:: 1. 编译（首次或改代码后）—— 用 PowerShell，不要用 Git Bash
::    1.1 先停掉在跑的 exe：lab\stop_lab.bat（否则 LNK1104 无法覆盖）
::    1.2 清空代理变量（否则 MSBuild 报 MSB6001 字典键冲突）：
::        $env:http_proxy=$null; $env:https_proxy=$null; $env:all_proxy=$null
::    1.3 调 VS2022 自带的 cmake（不在 PATH 里）：
::        $cmake = "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
::        & $cmake --build "D:\桌面\AuditForwarder\build" --config Release --parallel
::    1.4 首次配置（build 目录不存在时才需要）：
::        & $cmake -S "D:\桌面\AuditForwarder" -B "D:\桌面\AuditForwarder\build" -G "Visual Studio 17 2022" -A x64 -DBUILD_TESTING=ON -DOPENSSL_ROOT_DIR="C:/Program Files/OpenSSL-Win64" -DOPENSSL_SSL_LIBRARY="C:/Program Files/OpenSSL-Win64/lib/VC/x64/MD/libssl.lib" -DOPENSSL_CRYPTO_LIBRARY="C:/Program Files/OpenSSL-Win64/lib/VC/x64/MD/libcrypto.lib" -DZLIB_INCLUDE_DIR="C:/zlib-install2/include" -DZLIB_LIBRARY="C:/zlib-install2/lib/zlib.lib"
::    1.5 冒烟：build\Release\auditforwarder-server.exe --help 有输出即成功
::    1.6 回归（可选）：build\Release\auditforwarder_tests.exe  → 期望 694 passed, 0 failed

:: 2. Python 侧只依赖 Flask
set PY=%USERPROFILE%\.workbuddy\binaries\python\versions\3.13.12\python.exe
%PY% -c "import flask, werkzeug; print('ok')"

:: 3. 确认这两份配置在位（换机器必须重新放）
::    data\server\policies\collusion_config.json      含 eager_eval: true
::    data\server\policies\collusion_rules.json       含 R-001~R-005（R-006/R-007 默认禁用）
::    data\server\asset_profiles\book_system.yaml     operator_roles 必须是上面那几个账号
```

若 `data\server` 是空的（新克隆），把 `config\` 下的母本复制过去：

```bat
mkdir data\server\policies data\server\asset_profiles
copy config\collusion_config.example.json data\server\policies\collusion_config.json
copy config\collusion_rules.example.json  data\server\policies\collusion_rules.json
copy config\asset_profiles\book_system.yaml data\server\asset_profiles\
```

---

## 4. 启动与停止

### 4.1 一键启动

```bat
lab\start_lab.bat
```

或分别拉起（脚本窗口被关掉时更可靠）：

```bat
start "" lab\_srv.bat        :: 服务端 8443
start "" lab\_book.bat       :: 图书系统 18080
start "" lab\_client.bat     :: 采集客户端 + 代理 8888
```

### 4.2 确认三件套在线

```bat
netstat -ano | findstr "8443 18080 8888"
curl http://127.0.0.1:8443/health
curl http://127.0.0.1:18080/
```

`/health` 返回 `running: true` 才算服务端就绪。

### 4.3 停止与重置

```bat
lab\stop_lab.bat
%PY% lab\reset_lab.py --restart
```

`reset_lab.py` 会重建图书库（books / 备份 / 快照 / 密钥全部复原）、
清空合谋事件与画像、清空采集日志。**跑完 R-005 必须重置**，因为那一步会清空图书表。

---

## 5. 五个剧本

每个剧本都是"三步、三个人、每步都在职权内"。

### R-001 备份销毁合谋（最推荐用来演示）

| 步 | 谁 | 做什么 | 归一化动作 |
|---|---|---|---|
| 1 | admin | 删除一个备份文件 | `delete.backup` |
| 2 | admin2 | 卸载存储卷 | `unmount.volume` |
| 3 | admin3 | 删除快照 | `delete.snapshot` |

为什么是攻击：备份没了、卷卸载了、快照也没了 —— 数据无法恢复、操作无法追溯。

### R-002 密钥权限拆分绕过

| 步 | 谁 | 做什么 | 归一化动作 |
|---|---|---|---|
| 1 | admin | 生成密钥 | `create.key` |
| 2 | admin2 | 分发密钥 | `distribute.key` |
| 3 | admin3 | 清空密钥审计 | `clear.key_audit` |

### R-003 配置篡改链路

| 步 | 谁 | 做什么 | 归一化动作 |
|---|---|---|---|
| 1 | admin | 修改系统配置 | `update.config` |
| 2 | admin2 | 重启服务 | `restart.service` |
| 3 | admin3 | 清空系统日志 | `clear.logs` |

### R-004 数据批量外泄

| 步 | 谁 | 做什么 | 归一化动作 |
|---|---|---|---|
| 1 | admin | 给某账号追加导出权限 | `grant.user` |
| 2 | admin2 | 批量导出全部图书 | `export.book` |
| 3 | admin3 | 清空数据域审计 | `clear.book_audit` |

### R-005 权限晋升合谋

| 步 | 谁 | 做什么 | 归一化动作 |
|---|---|---|---|
| 1 | admin | 创建一个新账号 | `create.user` |
| 2 | admin2 | 把该账号提升为管理员 | `assign.user` |
| 3 | 该新账号 | 执行清库动作 | `exec.purge_books` |

为什么是攻击：任何一步单独看都合理，合起来是"两个人合伙造了一个后门，再用后门清数据"。

### 对照组（必须做）

| 场景 | 操作 | 预期 |
|---|---|---|
| 正常业务 | admin 删除一本书 | 无告警 |
| 单人独做 | admin 独自完成 R-001 三步 | 无告警（聚合要求 ≥2 人） |
| 不经采集 | `--no-proxy` 跑同一剧本 | 无告警（证明结论来自日志而非业务系统） |

---

## 6. 两种执行方式

### 6.1 脚本执行（推荐用于演示，稳定不出错）

```bat
:: 单个剧本
%PY% lab\run_scenario.py --scenario r001

:: 全部剧本 + 对照组
%PY% lab\run_scenario.py --scenario all

:: 对照组（不经采集器）
%PY% lab\run_scenario.py --scenario control --no-proxy
```

脚本做的事：真实登录（拿 token）→ 真实 HTTP 请求（经 8888 代理）→ 打印每一步的状态码与期望动作。
没有合成事件，没有直接调检测接口。

### 6.2 浏览器手工操作（老师要看"真人点击"时用）

1. 浏览器代理设为 `127.0.0.1:8888`（HTTP 与 HTTPS 都填；HTTPS 会退化成 CONNECT 隧道，看不到路径，所以**用 http 直接访问**）。
2. 打开 `http://127.0.0.1:18080/ui`。
3. 用 `admin` 登录 → 执行第一步。
4. **换一个浏览器或无痕窗口**用 `admin2` 登录 → 执行第二步。
5. 再换一个窗口用 `admin3` 登录 → 执行第三步。

> 关键：不同管理员必须用**不同的浏览器会话**。同一浏览器切账号会把身份 Cookie
> `af_operator` 覆盖掉，日志里就只剩最后登录的那个人，跨操作员聚合也就不成立。

对应的界面路径：

| 动作 | 页面 / 请求 |
|---|---|
| 删备份 | `DELETE /api/backup/<name>`（先 POST 建一个） |
| 卸载卷 | `PATCH /api/storage/volume/<id>/unmount` |
| 删快照 | `DELETE /api/snapshot/<name>` |
| 改配置 | `PUT /api/system/config` |
| 重启服务 | `POST /api/system/service/restart` |
| 清日志 | `DELETE /api/system/logs/clear` |
| 生成/分发密钥 | `POST /api/key`、`POST /api/key/<id>/distribute` |
| 提权 / 导出 / 清审计 | `PATCH /api/users/<id>/privilege`、`GET /api/books/export`、`DELETE /api/books/audit/clear` |
| 建号 / 授权 / 执行 | `POST /api/admin/user`、`POST /api/admin/user/<id>/assign-admin`、`POST /api/admin/exec` |

---

## 7. 看结果

### 7.1 三个查询入口

```bat
:: 总览
curl http://127.0.0.1:8443/collusion/overview
:: 告警列表（可按等级过滤）
curl "http://127.0.0.1:8443/collusion/events?level=HIGH"
:: 危害定级报告（Markdown，可直接贴进实验报告）
curl http://127.0.0.1:8443/collusion/incident-report
```

Web 界面在 `http://127.0.0.1:8443/` 的"合谋协同"页。

### 7.2 一条告警怎么看

以 R-001 为例：

```
event_id       ce-718c8f23e08c8198
risk_level     HIGH          ← 高危
risk_score     100           ← 规则 90 + 画像 13，封顶 100
matched_rules  R-001 备份销毁合谋
operators      admin, admin2, admin3      ← 三个不同操作员，这是"合谋"的核心证据
asset_group    backup-group
window         06:15:00 ~ 06:30:00
```

证据链表（`incident-report` 里的表格）：

| 时间 | 操作员 | 主机 | 动作 | 对象 | 参数 |
|---|---|---|---|---|---|
| 06:15:58 | admin | lab-pc | network/delete | /api/backup/lab_r001.db | DELETE ... status=200 |
| 06:15:58 | admin2 | lab-pc | network/write | /api/storage/volume/1/unmount | PATCH ... status=200 |
| 06:15:58 | admin3 | lab-pc | network/delete | /api/snapshot/lab_r001.snap | DELETE ... status=200 |

这三行就是老师要的"日志里确实有这条事件"。

### 7.3 分数怎么来的

| 组成 | 上限 | 说明 |
|---|---|---|
| 规则分 | 首条规则基础分（70~85）+ 多规则附加（≤40） | 命中即计 |
| 画像分 | 25 | 陌生协作 +12、跨域操作 +6/人、伪造工单 +10 |
| ML / 图谱 | 0（默认关闭） | 线索性质，不单独触发 HIGH |

`score_high = 80`：≥80 为 HIGH，≥40 为 MID。
规则分不够时，画像分会补上去（R-003 就是 70+18=88）。

---

## 8. 实测结果（本机 2026-10-24 运行）

```
HIGH 6 条：
  R-001 备份销毁合谋      backup-group     100 分  admin,admin2,admin3
  R-002 密钥权限拆分绕过   key-mgmt-group    98 分  admin,admin2,admin3
  R-003 配置篡改链路      sys-config-group  88 分  admin,admin2,admin3
  R-004 数据批量外泄      db-group         100 分  admin,admin2,admin3
  R-005 权限晋升合谋      general-group     98 分  admin,admin2,admin3,+后门账号

对照组（删一本书）：HIGH 数量不变 → 无新增告警
```

同一台机器上三个管理员轮流登录，日志里的 `operator_id` 分别是 `admin` / `admin2` / `admin3`，
**不是客户端配置里写死的 `operator.id`** —— 这就是"跨操作员"能成立的原因。

---

## 9. 常见故障排查

| 现象 | 原因 | 处理 |
|---|---|---|
| `/collusion/overview` 404 | 连的是 18080（图书系统）而不是 8443 | 换端口 |
| 三步都做了但没有告警 | 三个操作员没区分开 | 看 `data/server/operation_logs/lab-pc/http_proxy.jsonl` 的 `operator_id`；必须用不同浏览器会话或脚本 |
| 有日志但动作是 `xxx.unknown` | 请求没经代理（直连） | 确认脚本带了 `--proxy`，浏览器配了 8888 |
| 告警要等 15 分钟才出 | `eager_eval` 没开 | `data/server/policies/collusion_config.json` 设 `"eager_eval": true`，服务端会热加载 |
| 服务端起不来 / exe 被占用 | 旧进程还在 | `lab\stop_lab.bat` 后重启；编译前必须先停 |
| 编译报 MSB6001 或找不到编译器 | 代理变量 + 用了 Bash 跑 cmake | 用 PowerShell 跑 VS 自带 cmake，并清空 `*_proxy` 变量 |
| 图书系统 500 / 表为空 | 跑过 R-005 清库 | `%PY% lab\reset_lab.py --restart` |
| 身份全是 `admin` | 配置里 `operator.id` 兜底生效了 | 检查登录是否成功、Cookie `af_operator` 是否下发 |

---

## 10. 设计要点（被问到时怎么答）

**1. 为什么不能只靠关键词匹配？**
原始实现用裸词 `delete` 做子串匹配，"删一本书"和"删备份"都会命中，正常业务直接误报。
现在每条日志都带一个归一化动作 `<verb>.<object>`（`delete.book` / `delete.backup`），
规则只认精确动作名，两者彻底分开。

**2. 为什么必须有动作归一化？**
它把三种完全不同的来源统一成同一个语义坐标：
HTTP 路径（`DELETE /api/backup/3`）、命令行（`vssadmin delete shadows`）、文件路径（`*.bak`）。
没有它，跨系统、跨协议的行为根本无法放进同一条规则里比较。

**3. 单人为什么不算合谋？**
聚合入口先看集合里不同操作员的个数，少于 2 直接丢弃。
这是"合谋"的定义边界，也顺带给出最有说服力的负样本：同一个人把整套动作做完，系统不报。

**4. 为什么日志里能看出是谁？**
采集器从每个 HTTP 请求里解析真实身份：显式身份头 → `af_operator` Cookie →
`Authorization: Bearer` 里的 username → 请求体 username。
解析到了就覆盖客户端配置的 `operator.id`。一台机器上换人，日志立刻跟着换。

**5. 证据链凭什么可信？**
每条事件在客户端就进了哈希链（批次 merkle 摘要 + 可选 HMAC 签名），
服务端只做聚合判定，原始 JSON 单行完整留档，报告里的每一步都能回查原文。

---

## 11. 演示流程（5 分钟版）

1. **打开图书系统**，正常增删改查几下（30 秒）—— 让老师看到这是真系统。
2. **打开合谋总览页**，指出当前 0 告警。
3. **跑对照组**：`%PY% lab\run_scenario.py --scenario control` —— 无告警。
4. **跑 R-001**：`%PY% lab\run_scenario.py --scenario r001`。
5. **刷新告警页**：HIGH 出现，点开证据链，逐行念"谁在什么时候做了什么"。
6. **强调三个人不同**：`admin` / `admin2` / `admin3`，任何一个人单做都不报。
7. **打开 incident-report** 展示评分构成与规则汇总。
8. （可选）跑一次 `--no-proxy` 对照组，证明结论来自采集日志而非业务系统。

---

## 12. 还没做的（如实交代）

| 项 | 现状 |
|---|---|
| HTTPS 明文路径 | CONNECT 隧道看不到 URL，只能看到 host:port。演示请用 http 访问 |
| 进程命令行（Windows） | `process_win` 用 Toolhelp 拿不到命令行，只有 ETW 4688 有；服务端已把 `process.command_line` 并入匹配域 |
| R-006 / R-007 | 已禁用：R-006 是单人规则（与实验边界冲突），R-007 按对象分组不可达。作为负样本保留定义 |
| ML / 图谱引擎 | 默认关闭，不影响本实验结论 |
| 多主机 | 当前实验在单机做（同一 host_id）。跨机部署只需把客户端配置的 server 地址改成监管端 IP |
