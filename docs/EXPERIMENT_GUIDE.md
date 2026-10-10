# AuditForwarder 合谋检测验证实验 · 全流程操作指引

> 适用场景：首次独立完成项目验证实验的新手操作者
> 配套文档：[docs/EXPERIMENT_DESIGN.md](file:///c:/Users/30952/Desktop/AuditForwarder_ovo1102/docs/EXPERIMENT_DESIGN.md)（完整实验方案）
> 预计耗时：L1 约 10 分钟 · L2 约 40 分钟 · L3 约 90 分钟 · L4 约 30 分钟

---

## 第〇章 开始前的准备清单

### 0.1 你需要准备的东西

| 物品 | 说明 | 怎么检查已就绪 |
|------|------|---------------|
| 项目代码 | 位于 `c:\Users\30952\Desktop\AuditForwarder_ovo1102` | 打开终端能 `git log` 看到提交历史 |
| MSYS2 编译环境 | ucrt64 的 g++ 和 cmake | 终端输入 `g++ --version` 有版本号输出 |
| 构建产物 | `build\auditforwarder-server.exe` 存在 | 文件存在且非 0 字节 |
| 配置文件 | `config\server_windows.yaml` 存在 | 能用记事本打开，含 `manager:` 段 |
| 策略文件 | `data\server\policies\collusion_*.json` 三个文件 | `collusion_config.json` / `collusion_rules.json` / `collusion_workorders.json` 都在 |
| 密码哈希 | 配置里 `login_password_sha256` 已设 | 当前是 `admin123` 的哈希，本地调试可用 |
| 一个干净的终端 | PowerShell 或 MSYS2 终端 | 能执行 `cd` 到项目目录 |

### 0.2 如果构建产物不存在，先构建

**做什么**：用 CMake 编译项目生成服务端可执行文件。

**怎么做**：在项目根目录打开 MSYS2 ucrt64 终端，执行：

```bash
cmake --build build
```

**怎么判断做对了**：终端最后一行显示 `[100%] Built target auditforwarder-server`，且 `build\auditforwarder-server.exe` 文件存在、大小非零。

**踩坑提醒**：
- 如果报 "cmake: command not found"，说明你不在 ucrt64 环境，用 `C:\msys64\ucrt64\mingw32.exe` 打开终端重试
- 如果报 "Could not find ninja"，执行 `pacman -S ninja` 安装
- 如果 SQLite 报链接错误，确认 `third_party/sqlite3/sqlite3.c` 存在（约 9MB 大文件）

### 0.3 清理旧数据（重要！）

**为什么要做**：上次实验残留的 `events.jsonl` 会让计数不为零，导致 L1-3 概览检查失败。

**怎么做**：删除数据目录下的合谋事件文件：

```bash
# 在项目根目录
rm -f data/server/collusion/events.jsonl
rm -rf data/server/collusion/
```

**怎么判断做对了**：`data/server/collusion/` 目录不存在或为空。

---

## 第一章 L1 — 基础功能连通性验证

**这一层的目的**：确认服务端能启动、能登录、合谋检测引擎能收到事件。就像盖房子前先确认地基是稳的。

### 步骤 1：启动服务端

**做什么**：在后台启动服务端程序。

**怎么做**：打开一个 PowerShell 窗口，执行：

```powershell
cd c:\Users\30952\Desktop\AuditForwarder_ovo1102
.\build\auditforwarder-server.exe --config config\server_windows.yaml
```

**怎么判断做对了**：
- 终端输出类似 `manager listening on 0.0.0.0:8443` 或 `合谋检测引擎已初始化`
- 没有出现 `ERROR` 或 `FATAL` 字样
- 窗口没有自动关闭（服务端在前台运行）

**注意事项**：
- 这个窗口要保持开着，不要关！关了服务端就停了
- 如果窗口一闪就关了，说明启动失败，看 `data/server/server.log` 找错误原因
- 如果 8443 端口被占用（提示 "address already in use"），先杀掉旧进程：`Get-Process auditforwarder* | Stop-Process`

### 步骤 2：登录获取 Token

**做什么**：用管理员账号登录，拿到一个"通行证"（Token），后续所有操作都要带它。

**怎么做**：另开一个 PowerShell 窗口（服务端那个别动），执行：

```powershell
# 先算密码的 SHA256 哈希（密码是 admin123）
$passwordSha256 = [BitConverter]::ToString(
    [System.Security.Cryptography.SHA256]::Create().ComputeHash(
        [Text.Encoding]::UTF8.GetBytes("admin123")
    )
).Replace("-","").ToLower()

# 登录
$loginRsp = Invoke-WebRequest -Uri "http://127.0.0.1:8443/auth/login" `
    -Method POST `
    -Body "{`"username`":`"admin`",`"password_sha256`":`"$passwordSha256`"}" `
    -ContentType "application/json"

$token = ($loginRsp.Content | ConvertFrom-Json).token
Write-Host "Token: $token"

# 后续所有请求都要带这个
$headers = @{ Authorization = "Bearer $token" }
```

**怎么判断做对了**：
- 输出的 Token 是一串字母数字（非空）
- HTTP 状态码 200

**踩坑提醒**：
- 如果返回 401 "账号或密码不正确"，说明密码哈希不对。检查 `config/server_windows.yaml` 里的 `login_password_sha256` 值，应该是 `240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9`
- 如果连续失败 3 次，账号会被锁定 15 分钟，等一会再试或重启服务端

### 步骤 3：查看合谋检测概览（L1-3）

**做什么**：确认合谋检测引擎已初始化，当前没有事件。

**怎么做**：

```powershell
$overview = Invoke-WebRequest -Uri "http://127.0.0.1:8443/collusion/overview" -Headers $headers
Write-Host $overview.Content
```

**怎么判断做对了**：
- 返回 JSON 含 `"event_counts": {"HIGH": 0, "MID": 0, "LOW": 0}`
- 三个计数都是 0（因为我们刚清理过数据）

**如果不为 0**：说明有旧数据残留，回到第 0.3 步重新清理。

### 步骤 4：注入第一个测试事件（L1-4）

**做什么**：往合谋引擎塞一条事件，确认它能收到并存储。

**怎么做**：

```powershell
# 构造一条事件（一个操作员删除了一个备份文件，单独一条不会触发合谋）
$event = @{
    events = @(
        @{
            oper_id = "op_test_001"
            ts_ms = 1696953600000
            server_id = "host_test_01"
            op_type = "delete"
            res_key = "backup_test.bak"
            op_param = "rm -f /backup/test.bak"
            work_order_id = ""
            raw = "{}"
        }
    )
} | ConvertTo-Json -Depth 5

# 注入
$injectRsp = Invoke-WebRequest -Uri "http://127.0.0.1:8443/collusion/ingest" `
    -Method POST -Headers $headers -Body $event -ContentType "application/json"
Write-Host "注入结果: $($injectRsp.StatusCode)"
```

**怎么判断做对了**：
- 返回 200
- 等几秒后查概览，LOW 计数应该 +1（单条事件不满足合谋的"至少 2 人"条件，只会产生 LOW 级别线索）

```powershell
# 等 2 秒后查
Start-Sleep -Seconds 2
Invoke-WebRequest -Uri "http://127.0.0.1:8443/collusion/overview" -Headers $headers | Select-Object -ExpandProperty Content
```

### 步骤 5：验证规则热加载（L1-5）

**做什么**：确认能通过 API 动态修改检测规则（不用重启服务端）。

**怎么做**：

```powershell
# 读取当前规则
$rules = Invoke-WebRequest -Uri "http://127.0.0.1:8443/collusion/rules" -Headers $headers
Write-Host "当前规则数: $(($rules.Content | ConvertFrom-Json).rules.Count)"

# 应该是 5 条（R-001 到 R-005）
```

**怎么判断做对了**：返回 5 条规则（R-001 到 R-005）。

### L1 交付物与合格标准

| 验证项 | 合格标准 | 实际结果 |
|--------|----------|----------|
| 服务端启动 | listening 日志、无 ERROR | ________ |
| 登录获取 Token | 200 + token 非空 | ________ |
| 概览接口 | 200 + 计数全为 0 | ________ |
| 事件注入 | 200 + 落盘成功 | ________ |
| 规则读取 | 200 + 5 条规则 | ________ |

**L1 通过判据**：5 项全部合格。如果任何一项失败，先看下方"常见问题排查"再继续。

---

## 第二章 L2 — 正常场景功能基准测试

**这一层的目的**：在没有攻击的正常情况下，确认系统不会乱喊"狼来了"（误报率要低）。

**通俗解释**：就像 burglar alarm（防盗警报器）在你正常开关门时不应该响。我们注入一些"正常的运维操作"，确认合谋检测引擎不会把它们误判为攻击。

### 步骤 1：单人正常操作（L2-1）

**做什么**：一个操作员做 10 条正常操作（不构成合谋，因为只有 1 人）。

**怎么做**：

```powershell
# 10 条单人操作，操作类型是 query（查询），不匹配任何规则的子序列
$events = @{ events = @(1..10 | ForEach-Object {
    @{
        oper_id = "op_solo"
        ts_ms = 1696953600000 + $_ * 1000
        server_id = "host_normal"
        op_type = "query"
        res_key = "app_config.yaml"
        op_param = "cat /etc/app/config.yaml"
        work_order_id = "WO-NORMAL-$_"
        raw = "{}"
    }
})} | ConvertTo-Json -Depth 5

Invoke-WebRequest -Uri "http://127.0.0.1:8443/collusion/ingest" `
    -Method POST -Headers $headers -Body $events -ContentType "application/json"
```

**怎么判断做对了**：
- 等短窗口到期（默认 15 分钟）+ 10 秒宽限期后，概览的 HIGH 和 MID 计数不增加
- 可能有 LOW 线索（正常），但不应该有 HIGH/MID

**等不及 15 分钟怎么办**：临时把短窗口改短！

```powershell
# 把短窗口改成 30 秒（实验用，生产环境别这么短）
$config = '{"short_window_minutes":0,"long_window_hours":0,"flush_grace_seconds":5,"score_high":80,"score_mid":40}'
# 注意：short_window_minutes 设 0 会用毫秒级短窗口，实际等于约 1 秒
# 更安全的做法是保持 15 分钟，用 Start-Sleep 等待
```

**推荐做法**：保持 15 分钟窗口，期间可以做其他准备工作。或把 `short_window_minutes` 改为 1（1 分钟），加速实验。

### 步骤 2：双人合法协同 + 白名单（L2-2）

**做什么**：两名操作员协作，但他们登记在白名单里，系统应该放行。

**怎么做**：

```powershell
# 先确认白名单配置（policies/collusion_config.json 里有 "示例-数据库协同组"）
# 两名操作员 op_dba1 和 op_dba2 在白名单内

$events = @{ events = @(
    @{ oper_id="op_dba1"; ts_ms=1696953600000; server_id="host_db"; op_type="query"; res_key="customer_db.sql"; op_param="SELECT"; work_order_id="WO-001"; raw="{}" },
    @{ oper_id="op_dba2"; ts_ms=1696953605000; server_id="host_db"; op_type="backup"; res_key="customer_db.sql"; op_param="pg_dump"; work_order_id="WO-001"; raw="{}" }
)} | ConvertTo-Json -Depth 5

Invoke-WebRequest -Uri "http://127.0.0.1:8443/collusion/ingest" `
    -Method POST -Headers $headers -Body $events -ContentType "application/json"
```

**怎么判断做对了**：等窗口到期后，概览不增加 HIGH/MID（白名单预检会跳过）。

### L2 交付物与合格标准

| 验证项 | 合格标准 | 实际结果 |
|--------|----------|----------|
| 单人正常操作 | HIGH=0, MID=0 | ________ |
| 双人白名单协同 | HIGH=0, MID=0 | ________ |
| 正常基线误报率 | FAR ≤ 5% | ________ |

---

## 第三章 L3 — 合谋攻击场景注入测试（核心实验）

**这一层的目的**：往系统里注入"合谋攻击事件"，确认引擎能检测出来、告警级别正确。

**通俗解释**：就像消防演习——我们故意"放火"（注入假的合谋攻击），确认"烟感器"（检测引擎）能响、响得对。

### 3A 规则单命中测试（5 条规则各测一次）

#### 实验 L3-A1：触发 R-001 备份销毁合谋

**做什么**：模拟 2 名攻击者协作执行"删除→卸载→快照"三步操作。

**预期结果**：HIGH 级别告警（基础分 85 ≥ 80 阈值）。

**怎么做**：

```powershell
# 构造 R-001 合谋攻击事件
$attack = @{ events = @(
    # 第一步：op_a 删除备份文件
    @{ oper_id="op_attacker_a"; ts_ms=1696953600000; server_id="host_victim"; op_type="delete"; res_key="backup_daily.bak"; op_param="rm -f /backup/daily.bak"; work_order_id=""; raw="{}" },
    # 第二步：op_b 卸载磁盘
    @{ oper_id="op_attacker_b"; ts_ms=1696953605000; server_id="host_victim"; op_type="unmount"; res_key="disk_lvm_01"; op_param="umount /dev/lvm_01"; work_order_id=""; raw="{}" },
    # 第三步：op_a 删除快照
    @{ oper_id="op_attacker_a"; ts_ms=1696953610000; server_id="host_victim"; op_type="snapshot"; res_key="vm_snap_destroy"; op_param="snapshot delete vm_snap"; work_order_id=""; raw="{}"
    }
)} | ConvertTo-Json -Depth 5

# 注入
Invoke-WebRequest -Uri "http://127.0.0.1:8443/collusion/ingest" `
    -Method POST -Headers $headers -Body $attack -ContentType "application/json"

Write-Host "攻击事件已注入，等待窗口到期..."
```

**怎么判断做对了**：

```powershell
# 等待窗口到期（如果你把 short_window_minutes 改成了 1，等 70 秒即可）
Start-Sleep -Seconds 70

# 查看概览
$overview = Invoke-WebRequest -Uri "http://127.0.0.1:8443/collusion/overview" -Headers $headers
Write-Host $overview.Content

# 查看事件详情
$events = Invoke-WebRequest -Uri "http://127.0.0.1:8443/collusion/events?level=HIGH" -Headers $headers
Write-Host $events.Content
```

**判定标准**：
- 概览 `HIGH` 计数 ≥ 1
- 事件列表含 `rule_id: "R-001"` 的事件
- 事件的 `risk_score` 约为 85（允许 ±5 偏差）

**如果没触发**：排查清单见下方"常见问题"。

#### 实验 L3-A2~A5：其余 4 条规则

按相同方法，替换事件内容即可。完整事件模板见 [EXPERIMENT_DESIGN.md 附录](file:///c:/Users/30952/Desktop/AuditForwarder_ovo1102/docs/EXPERIMENT_DESIGN.md)。

| 实验 | 规则 | 操作员数 | 操作序列关键词 | 预期等级 | 预期分数 |
|------|------|----------|---------------|----------|----------|
| L3-A1 | R-001 | 2 | delete→unmount→snapshot | HIGH | 85 |
| L3-A2 | R-002 | 3 | generate→distribut→clean | HIGH | 80 |
| L3-A3 | R-003 | 2 | modify→restart→clean | MID | 70 |
| L3-A4 | R-004 | 2 | grant→dump→clean | HIGH | 82 |
| L3-A5 | R-005 | 3 | useradd→assign→exec | MID | 75 |

### 3B 梯度化攻击强度测试

**通俗解释**：从"最简单的攻击"到"最复杂的攻击"，一步步加码，看检测引擎在不同难度下的表现。

#### 实验 L3-B1：单人单规则（应不触发）

**做什么**：只有 1 名攻击者，不满足"最少 2 人"的条件。

**预期**：不触发告警（NONE）。这验证引擎不会冤枉单独干活的人。

```powershell
$attack = @{ events = @(
    @{ oper_id="op_solo_attacker"; ts_ms=1696953600000; server_id="host_v"; op_type="delete"; res_key="backup.bak"; op_param="rm"; work_order_id=""; raw="{}" },
    @{ oper_id="op_solo_attacker"; ts_ms=1696953605000; server_id="host_v"; op_type="unmount"; res_key="disk"; op_param="umount"; work_order_id=""; raw="{}" },
    @{ oper_id="op_solo_attacker"; ts_ms=1696953610000; server_id="host_v"; op_type="snapshot"; res_key="snap"; op_param="snap delete"; work_order_id=""; raw="{}"
    }
)} | ConvertTo-Json -Depth 5

Invoke-WebRequest -Uri "http://127.0.0.1:8443/collusion/ingest" -Method POST -Headers $headers -Body $attack -ContentType "application/json"
```

**判定**：等窗口到期后，HIGH/MID 不增加（只有 1 人，distinct_op_count=1 < 2）。

#### 实验 L3-B6：慢合谋（长窗口降级验证）

**做什么**：2 名攻击者在 4 小时长窗口内分散操作。

**预期**：长窗口检测到 HIGH 后自动降为 MID（弱关联线索）。

**怎么做**：注入事件时把时间戳拉开到 4 小时内，并等长窗口到期。**实验加速**：把 `long_window_hours` 改为 0.001（约 4 秒）。

### L3 交付物与合格标准

| 实验 | 合格标准 | 实际结果 |
|------|----------|----------|
| L3-A1~A5 | 5 条规则各触发对应等级 | ________ |
| L3-B1 | 单人不触发（NONE） | ________ |
| L3-B3 | 3 人超额触发 + 画像加分 | ________ |
| L3-B6 | 长窗口 HIGH 降 MID | ________ |
| L3-B8 | 伪造工单 +10 分 | ________ |
| L3-B9 | 有效工单 -40 分 | ________ |

**L3 整体合格判据**：检测率 DR ≥ 95%（即该触发的都触发了）。

---

## 第四章 L4 — 边界异常容错测试

**这一层的目的**：给系统喂"垃圾数据"和"极端情况"，确认它不崩溃、不丢数据。

**通俗解释**：就像测试一辆车不仅要看正常行驶，还要看撞墙后安全气囊弹不弹、涉水后熄不熄火。

### 实验 L4-1：空事件注入

**做什么**：发一个空 JSON，看系统怎么处理。

```powershell
try {
    $rsp = Invoke-WebRequest -Uri "http://127.0.0.1:8443/collusion/ingest" `
        -Method POST -Headers $headers -Body "{}" -ContentType "application/json"
    Write-Host "状态码: $($rsp.StatusCode)"
} catch {
    Write-Host "被拒绝: $($_.Exception.Response.StatusCode.value__)"
}
```

**判定**：返回 400 或静默丢弃，服务端不崩溃。

### 实验 L4-5：高并发注入

**做什么**：1 秒内发 1000 条事件，看系统扛不扛得住。

```powershell
# 用 PowerShell 异步并发注入
$jobs = 1..100 | ForEach-Object {
    $batch = @{ events = @(1..10 | ForEach-Object {
        @{ oper_id="op_stress_$_"; ts_ms=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds(); server_id="h_stress"; op_type="read"; res_key="app.log"; op_param="cat"; work_order_id=""; raw="{}" }
    })} | ConvertTo-Json -Depth 5
    
    Invoke-WebRequest -Uri "http://127.0.0.1:8443/collusion/ingest" `
        -Method POST -Headers $headers -Body $batch -ContentType "application/json" -AsJob
}
$jobs | Wait-Job | Receive-Job
$success = ($jobs | Where-Object { $_.State -eq "Completed" }).Count
Write-Host "成功: $success / 100 批"
```

**判定**：成功率 ≥ 99%（即 1000 条中至少 990 条成功）。

### 实验 L4-8：服务端重启恢复

**做什么**：注入 100 条事件后重启服务端，确认数据没丢。

**怎么做**：
1. 注入 100 条事件
2. 停掉服务端（Ctrl+C 或 Stop-Process）
3. 重新启动服务端
4. 查概览，确认事件还在

**判定**：events.jsonl 文件行数与注入数一致，重启后概览计数不丢。

---

## 第五章 常见问题排查手册

### 问题 1：服务端启动失败，端口被占用

**现象**：`bind: Address already in use` 或 `listen failed`

**排查**：
```powershell
# 看谁占了 8443
Get-NetTCPConnection -LocalPort 8443 -ErrorAction SilentlyContinue | Select-Object OwningProcess
# 杀掉
Get-Process auditforwarder* | Stop-Process -Force
```

### 问题 2：登录返回 401

**现象**：`{"message":"账号或密码不正确。"}`

**排查**：
1. 确认密码是 `admin123`（全小写，无空格）
2. 确认哈希算法是 SHA256
3. 检查 `config/server_windows.yaml` 的 `login_password_sha256` 是否为 `240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9`
4. 如果连续失败 3 次被锁定，重启服务端即可重置

### 问题 3：注入事件后等不到告警

**现象**：等了 15 分钟，概览计数还是 0。

**排查步骤**：
1. **检查事件是否落盘**：
   ```powershell
   # 看 events.jsonl 有没有内容
   Get-Content data/server/collusion/events.jsonl -Tail 5
   ```
   如果文件不存在或为空 → 注入失败，检查 API 返回的 status code

2. **检查时间戳**：`ts_ms` 是毫秒级 UTC 时间戳。如果你用了过去的时间（比如 2023 年的），事件可能因为太老被丢弃。用当前时间：
   ```powershell
   $now = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
   ```

3. **检查资产组匹配**：`res_key` 要匹配规则的资产组 pattern。比如 R-001 要匹配 `*backup*`，你的 res_key 必须含 "backup"。

4. **检查操作员数量**：合谋要求至少 2 名不同 oper_id。如果你所有事件都用同一个 oper_id，不满足 `min_operator_cnt`。

5. **检查操作序列**：规则匹配是子序列匹配（按时间顺序但不要求连续）。三步操作的 op_type 必须分别匹配 `any_of` 里的关键词。

### 问题 4：告警级别不对（预期 HIGH 实际 MID）

**排查**：
1. 检查 `base_score` 是否 ≥ `score_high`（80）
2. 检查是否走了长窗口（长窗口 HIGH 会降为 MID）
3. 检查是否有有效工单（工单扣 40 分可能拉低到 MID）
4. 检查是否开启了应急模式（等级自动降一级）

### 问题 5：PowerShell 命令报 JSON 转义错误

**现象**：`ConvertTo-Json` 生成的 JSON 注入失败。

**解决**：PowerShell 的 JSON 转义和 bash 不同。确保：
- 用 `ConvertTo-Json -Depth 5` 避免嵌套层级不够
- 字符串里的引号用反引号转义 `` `" ``
- 或者直接把 JSON 写到文件再 `-Body (Get-Content file.json -Raw)`

### 问题 6：实验数据污染（旧事件干扰新实验）

**现象**：每次实验的计数越来越乱，分不清哪条是哪次的。

**解决**：每次实验前清理数据并重启服务端：
```powershell
# 停服务端
Get-Process auditforwarder* -ErrorAction SilentlyContinue | Stop-Process -Force
# 清数据
Remove-Item data/server/collusion/events.jsonl -Force -ErrorAction SilentlyContinue
# 重启服务端
.\build\auditforwarder-server.exe --config config\server_windows.yaml
```

### 问题 7：时间戳格式不对

**现象**：事件注入成功但不参与检测。

**原因**：`ts_ms` 必须是**毫秒级**整数（13 位数字），不是秒级（10 位）。

**正确写法**：
```powershell
# 当前时间的毫秒时间戳
$ts = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
```

---

## 第六章 实验加速技巧

### 6.1 缩短时间窗口

**做什么**：把 15 分钟窗口缩短到 1 分钟，加速实验。

**怎么做**：编辑 `data/server/policies/collusion_config.json`，把 `short_window_minutes` 改为 1。

或者通过 API 热更新：
```powershell
$config = Get-Content data/server/policies/collusion_config.json -Raw | ConvertFrom-Json
$config.short_window_minutes = 1
$config.long_window_hours = 0.05  # 约 3 分钟
Invoke-WebRequest -Uri "http://127.0.0.1:8443/collusion/config" -Method PUT `
    -Headers $headers -Body ($config | ConvertTo-Json -Depth 10) -ContentType "application/json"
```

**注意**：实验结束后改回 15 分钟！生产环境不能这么短。

### 6.2 用脚本批量注入

**做什么**：把所有测试用例写成一个脚本，一键执行。

**怎么做**：创建 `scripts/run_collusion_tests.ps1`，把所有实验的注入命令写入，循环执行。

---

## 第七章 最终交付物清单

完成全部实验后，你需要产出以下交付物：

| 交付物 | 内容 | 验证节点 | 合格标准 |
|--------|------|----------|----------|
| L1 连通性报告 | 5 项检查结果 | L1 完成时 | 5/5 通过 |
| L2 基准报告 | 误报率数据 | L2 完成时 | FAR ≤ 5% |
| L3 攻击检测报告 | 5+10+3=18 项检测结果 | L3 完成时 | DR ≥ 95% |
| L4 容错报告 | 8 项容错测试结果 | L4 完成时 | 8/8 不崩溃 |
| 量化指标汇总 | DR/FAR/F1/延迟 | 全部完成后 | 见评估体系表 |
| 混淆矩阵 | TP/FP/FN/TN | 全部完成后 | — |
| 问题清单 | 发现的问题与修复建议 | 全程 | — |
| 实验结论 | 优秀/合格/不合格 | 最后 | 综合评定 |

### 最终合格标准

| 等级 | L1 | L2 | L3 | L4 | 结论 |
|------|----|----|----|----|------|
| 优秀 | 5/5 | FAR≤2% | DR≥95% | 8/8 | 可投产 |
| 合格 | 5/5 | FAR≤5% | DR≥85% | 7/8 | 可上线 |
| 不合格 | <5/5 | FAR>5% | DR<85% | <7/8 | 需优化 |

---

## 第八章 全流程操作时间线（一图看懂）

```
准备阶段（10 分钟）
  ├─ 0.1 检查环境就绪
  ├─ 0.2 构建项目（如需要）
  └─ 0.3 清理旧数据
       ↓
L1 连通性（10 分钟）
  ├─ 1. 启动服务端 → 确认 listening
  ├─ 2. 登录获取 Token → 确认 200+token
  ├─ 3. 查概览 → 确认计数为 0
  ├─ 4. 注入单事件 → 确认落盘
  └─ 5. 读规则 → 确认 5 条
       ↓
L2 正常基准（40 分钟，含等窗口）
  ├─ 1. 单人正常操作 → HIGH/MID=0
  ├─ 2. 双人白名单协同 → HIGH/MID=0
  └─ 等 15 分钟窗口到期
       ↓
L3 攻击注入（90 分钟）
  ├─ 3A: 5 条规则各测一次 → 各触发对应等级
  ├─ 3B: 10 项梯度强度 → DR≥95%
  └─ 3C: 3 项行为画像 → profile_factor>0
       ↓
L4 容错（30 分钟）
  ├─ 空事件 → 不崩溃
  ├─ 高并发 → 丢失<1%
  └─ 重启恢复 → 数据完整
       ↓
汇总（10 分钟）
  ├─ 填写报告模板
  ├─ 计算量化指标
  └─ 输出实验结论
```

---

## 第九章 应急处理方案

### 情况 1：服务端崩溃了

**症状**：服务端窗口消失或卡死。

**处理**：
1. 不要慌，events.jsonl 已落盘的数据不会丢
2. 看 `data/server/server.log` 找崩溃原因
3. 重启服务端，数据会自动恢复

### 情况 2：实验数据全乱了

**症状**：计数对不上，不知道哪条是哪次的。

**处理**：
1. 停服务端
2. 删 `data/server/collusion/` 整个目录
3. 重启服务端，从头开始

### 情况 3：所有攻击都没触发告警

**处理**：按这个顺序排查：
1. 事件有没有落盘？（看 events.jsonl）
2. 时间戳是不是毫秒级 13 位？
3. res_key 有没有匹配资产组 pattern？
4. oper_id 有没有至少 2 个不同的？
5. op_type 有没有匹配规则的 any_of 关键词？
6. 三步操作的时序对不对？（ts_ms 要递增）

### 情况 4：端口被占用无法启动

**处理**：
```powershell
# 查占用
netstat -ano | findstr :8443
# 杀进程
taskkill /PID <找到的PID> /F
```

---

> **最后一句话**：按这个指引一步一步来，每一步都确认"做对了"再往下走，遇到问题先看"常见问题排查"章节，你一定能独立完成全部验证实验。
