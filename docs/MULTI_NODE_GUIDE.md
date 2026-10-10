# AuditForwarder 多机实验验证 · 完整操作指南

> 适用场景：2-3 台物理电脑组网，验证客户端→服务端的审计数据采集、传输、合谋检测全链路
> 配套文档：[EXPERIMENT_GUIDE.md](file:///c:/Users/30952/Desktop/AuditForwarder_ovo1102/docs/EXPERIMENT_GUIDE.md)（单机操作指引）
> 预计耗时：前置准备 30 分钟 + 环境配置 20 分钟 + 连通性验证 15 分钟 + 实验执行 90 分钟 + 结果收集 15 分钟

---

## 一、角色分工与硬件清单

### 1.1 三台电脑角色分配

| 电脑编号 | 角色 | 运行程序 | 职责 |
|----------|------|----------|------|
| **电脑 A** | 服务端 | `auditforwarder-server.exe` | 接收客户端数据、合谋检测引擎、Web 管理控制台（8443 端口） |
| **电脑 B** | 客户端 1 | `auditforwarder-client.exe` 或 `auditforwarderd.exe` | 采集本机审计事件、上传到服务端、接收远程指令 |
| **电脑 C** | 客户端 2 | `auditforwarder-client.exe` 或 `auditforwarderd.exe` | 同上，第二台攻击者/协作者 |

**两台电脑的简化方案**：电脑 A 兼任服务端 + 客户端 1（本机回环），电脑 C 作为客户端 2。但推荐三台，隔离更真实。

### 1.2 每台电脑的软件依赖

| 软件 | 版本要求 | 电脑 A | 电脑 B | 电脑 C | 用途 |
|------|----------|--------|--------|--------|------|
| MSYS2 | 最新版（ucrt64 环境） | ✅ | ✅ | ✅ | 编译 C++ 代码 |
| g++ | 16.1.0+（ucrt64） | ✅ | ✅ | ✅ | 编译器 |
| CMake | 3.16+ | ✅ | ✅ | ✅ | 构建系统 |
| Ninja | 最新版 | ✅ | ✅ | ✅ | 构建后端 |
| Git | 任意版本 | ✅ | ✅ | ✅ | 拉取代码 |
| OpenSSL | 1.1+（开发库） | ✅ | ✅ | ✅ | 通信加密 |
| curl | 任意版本 | ✅ | ✅ | ✅ | API 调试 |
| 浏览器 | Chrome/Edge | ✅ | — | — | Web 控制台 |

### 1.3 网络要求

- 三台电脑在同一局域网（同一交换机或同网段）
- 电脑 A 的 8443 端口对 B、C 可达（无防火墙拦截）
- 三台电脑互相能 ping 通

---

## 二、前置准备阶段（30 分钟）

### 步骤 1：在每台电脑上拉取项目代码

**做什么**：确保三台电脑都有完整的项目代码。

**怎么做**（在每台电脑上执行）：

```powershell
# 在每台电脑的桌面打开 PowerShell
cd C:\Users\<你的用户名>\Desktop
git clone <你的仓库地址> AuditForwarder_ovo1102
cd AuditForwarder_ovo1102

# 确认代码完整
git log --oneline -5
# 应该看到最近的提交记录
```

**怎么判断做对了**：`git log` 输出至少 5 条提交记录，且三台电脑的 HEAD commit hash 相同。

**注意事项**：
- 如果三台电脑 HEAD 不一致，执行 `git pull` 同步
- 如果新电脑没配置过 GitHub 授权，参考 [windows-git-push-fix 技能](file:///c:/Users/30952/Desktop/AuditForwarder_ovo1102/.trae/skills/windows-git-push-fix/SKILL.md) 配置 HTTPS + GCM

### 步骤 2：在每台电脑上构建项目

**做什么**：编译生成可执行文件。

**怎么做**（在每台电脑上用 MSYS2 ucrt64 终端执行）：

```bash
cd /c/Users/<你的用户名>/Desktop/AuditForwarder_ovo1102
cmake -B build -G Ninja
cmake --build build
```

**怎么判断做对了**：终端显示 `[100%] Built target auditforwarder-server`（电脑 A）或 `[100%] Built target auditforwarder-client`，且 `build/` 目录下有对应 exe 文件。

**故障排查**：
- 报 `g++ not found` → 不在 ucrt64 环境，用 `C:\msys64\ucrt64\mingw32.exe` 启动终端
- 报 `ninja not found` → `pacman -S ninja`
- 报 SQLite 链接错误 → 确认 `third_party/sqlite3/sqlite3.c` 存在（约 9MB）
- 报 OpenSSL 找不到 → `pacman -S mingw-w64-ucrt-x86_64-openssl`

### 步骤 3：记录每台电脑的 IP 地址

**做什么**：获取三台电脑的局域网 IP，后续配置要用。

**怎么做**（在每台电脑上执行）：

```powershell
ipconfig | findstr IPv4
```

**怎么判断做对了**：输出类似 `IPv4 地址 . . . . . . . . . . . . : 192.168.1.100`。

**记录下来**（示例，替换为你的实际 IP）：

| 电脑 | 角色 | IP 地址 |
|------|------|---------|
| 电脑 A | 服务端 | 192.168.1.100 |
| 电脑 B | 客户端 1 | 192.168.1.101 |
| 电脑 C | 客户端 2 | 192.168.1.102 |

### 步骤 4：验证网络互通

**做什么**：确认 B 和 C 能 ping 通 A。

**怎么做**（在电脑 B 和 C 上执行）：

```powershell
# 替换为电脑 A 的实际 IP
ping 192.168.1.100 -n 4
```

**怎么判断做对了**：4 次回复全部成功，延迟 < 5ms（局域网）。

**故障排查**：
- 如果 ping 不通：检查电脑 A 的防火墙设置
  ```powershell
  # 在电脑 A 上临时放行 8443 端口（管理员 PowerShell）
  New-NetFirewallRule -DisplayName "AuditForwarder 8443" -Direction Inbound -LocalPort 8443 -Protocol TCP -Action Allow
  ```
- 如果还是不通：检查三台电脑是否在同一工作组/网段
- 如果走 VPN 或跨网段：确保路由可达

---

## 三、环境配置阶段（20 分钟）

### 步骤 5：配置电脑 A（服务端）

**做什么**：修改服务端配置，让监听地址对外可达。

**怎么做**：编辑 `config\server_windows.yaml`：

```yaml
manager:
  enabled: true
  listen: 0.0.0.0:8443           # 关键：0.0.0.0 表示监听所有网卡（不是 127.0.0.1）
  auth_token: ""
  login_username: "admin"
  login_password_sha256: "240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9"
  status_timeout_seconds: 30
  use_tls: false                  # 实验环境用 HTTP，生产环境必须 TLS
  require_client_cert: false
  enrollment_key: ""              # 空表示不验证注册密钥
```

**检查要点**：
- `listen` 必须是 `0.0.0.0:8443`（不能是 `127.0.0.1:8443`，后者只接受本机）
- `use_tls: false`（实验环境用 HTTP 即可）
- 密码哈希对应明文 `admin123`

### 步骤 6：配置电脑 B（客户端 1）

**做什么**：修改客户端配置，让它指向电脑 A 的 IP。

**怎么做**：编辑电脑 B 上的 `config\client_windows.yaml`：

```yaml
agent:
  id: "client-node-B"             # 唯一标识，每台客户端不同
  data_dir: data/client
  config_path: config/client_windows.yaml

transport:
  servers:
    - "http://192.168.1.100:8443/ingest?agent=client-node-B"   # 指向电脑 A
  mode: realtime
  interval_sec: 5
  compress: true
  encrypt_payload: false
  auth_token: ""
  verify_tls: false

remote:
  enabled: true
  servers:
    - "http://192.168.1.100:8443"   # 指向电脑 A
  host_id: "client-node-B"          # 与 agent.id 一致
  heartbeat_interval_sec: 5
  command_poll_interval_sec: 3
  audit_summary_interval_sec: 5
  production_mode: false
  require_tls: false
  enrollment_key: ""
  allowed_commands:
    - collect_status
    - echo
    - set_collector
    - set_collectors
    - load_rules

collectors:
  enabled: true

privilege_detect:
  enabled: true

test_injection:
  enabled: false                    # 实验时关闭，需要手动注入时再开
```

**检查要点**：
- `transport.servers` 的 IP 替换为电脑 A 实际 IP（192.168.1.100）
- `remote.servers` 同样替换
- `agent.id` 和 `remote.host_id` 必须一致，且每台客户端唯一
- `enrollment_key` 与服务端保持一致（都为空即可）

### 步骤 7：配置电脑 C（客户端 2）

**做什么**：同步骤 6，但用不同的 agent.id。

**怎么做**：编辑电脑 C 上的 `config\client_windows.yaml`，把以下字段改成不同的值：

```yaml
agent:
  id: "client-node-C"              # 与电脑 B 不同！

transport:
  servers:
    - "http://192.168.1.100:8443/ingest?agent=client-node-C"

remote:
  servers:
    - "http://192.168.1.100:8443"
  host_id: "client-node-C"          # 与 agent.id 一致
```

**检查要点**：电脑 B 的 id 是 `client-node-B`，电脑 C 的 id 是 `client-node-C`，**不能重复**。

---

## 四、网络连通性验证（15 分钟）

### 步骤 8：启动服务端（电脑 A）

**做什么**：在电脑 A 上启动服务端。

**怎么做**（电脑 A 的 PowerShell）：

```powershell
cd C:\Users\<你的用户名>\Desktop\AuditForwarder_ovo1102
.\build\auditforwarder-server.exe --config config\server_windows.yaml
```

**怎么判断做对了**：
- 终端输出 `manager listening on 0.0.0.0:8443`
- 没有 ERROR
- 窗口保持开着

### 步骤 9：从客户端电脑验证服务端可达

**做什么**：在电脑 B 和 C 上确认能访问电脑 A 的服务端。

**怎么做**（电脑 B 或 C 的 PowerShell）：

```powershell
# 浏览器打开电脑 A 的 Web 控制台
# 在浏览器地址栏输入：http://192.168.1.100:8443/
# 应该看到登录页面

# 或用 curl 测试
curl http://192.168.1.100:8443/auth/login -X POST `
  -H "Content-Type: application/json" `
  -d '{"username":"admin","password_sha256":"240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9"}'
```

**怎么判断做对了**：
- 浏览器能打开登录页面
- curl 返回 `{"token":"xxx"}（HTTP 200）`

**故障排查**：
- 浏览器打不开 → 检查电脑 A 防火墙（见步骤 4）
- curl 报连接超时 → 确认电脑 A 的 `listen` 是 `0.0.0.0:8443` 不是 `127.0.0.1:8443`
- curl 返回 401 → 密码哈希不对，检查 `login_password_sha256`

### 步骤 10：启动客户端（电脑 B 和 C）

**做什么**：启动两台客户端，确认它们能连上服务端。

**怎么做**（电脑 B 的 PowerShell）：

```powershell
cd C:\Users\<你的用户名>\Desktop\AuditForwarder_ovo1102
.\build\auditforwarder-client.exe --config config\client_windows.yaml
```

**怎么做**（电脑 C 的 PowerShell，同样的命令）：

```powershell
cd C:\Users\<你的用户名>\Desktop\AuditForwarder_ovo1102
.\build\auditforwarder-client.exe --config config\client_windows.yaml
```

**怎么判断做对了**：
- 客户端终端输出 `连接服务端成功` 或 `心跳已发送`
- 电脑 A 的服务端终端输出 `客户端 client-node-B 已注册` 和 `客户端 client-node-C 已注册`

**故障排查**：
- 客户端报 `连接失败` → 检查 `transport.servers` 的 IP 是否正确
- 客户端报 `认证失败` → 检查 `auth_token` 和 `enrollment_key` 配置
- 服务端看不到客户端注册 → 检查客户端 `remote.enabled` 是否为 `true`

### 步骤 11：在 Web 控制台确认两台客户端在线

**做什么**：通过服务端 Web 控制台确认两台客户端已接入。

**怎么做**：在电脑 A 的浏览器打开 `http://192.168.1.100:8443/`，登录后：
1. 点击左侧导航"主机管理"，应看到 `client-node-B` 和 `client-node-C`
2. 点击"连接请求"，应看到两台客户端的在线状态为"在线"

**怎么判断做对了**：两台客户端都显示在线，最近心跳时间在 5 秒内。

---

## 五、实验执行阶段（90 分钟）

### 实验 1：正常基线测试（L2 多机版）

**目的**：确认两台客户端正常采集上传，不触发误报。

**怎么做**：
1. 保持两台客户端正常运行 5 分钟
2. 在服务端 Web 控制台查看"运行概览"，确认 `eventsCollected` 数量在增长
3. 等待 15 分钟短窗口到期
4. 查看"合谋检测→概览"，确认 HIGH=0, MID=0

**判定标准**：正常采集运行 15 分钟，无误报。

### 实验 2：跨机合谋攻击注入（L3 多机版）

**目的**：模拟两台客户端的操作员协作执行合谋攻击，验证检测引擎能跨机识别。

**做什么**：通过服务端 API 直接注入构造好的合谋事件（事件中标注来自不同客户端）。

**怎么做**（在电脑 A 的 PowerShell）：

```powershell
# 登录获取 Token
$loginRsp = Invoke-WebRequest -Uri "http://127.0.0.1:8443/auth/login" -Method POST `
    -Body '{"username":"admin","password_sha256":"240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9"}' `
    -ContentType "application/json"
$token = ($loginRsp.Content | ConvertFrom-Json).token
$headers = @{ Authorization = "Bearer $token" }

# 构造 R-001 备份销毁合谋：2 名操作员（分别来自电脑 B 和 C）协作
$attack = @{ events = @(
    # 操作员 op_b（来自电脑 B）：删除备份
    @{ oper_id="op_b"; ts_ms=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds(); server_id="client-node-B"; op_type="delete"; res_key="backup_daily.bak"; op_param="rm -f /backup/daily.bak"; work_order_id=""; raw="{}" },
    # 操作员 op_c（来自电脑 C）：卸载磁盘
    @{ oper_id="op_c"; ts_ms=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()+5000; server_id="client-node-C"; op_type="unmount"; res_key="disk_lvm_01"; op_param="umount /dev/lvm_01"; work_order_id=""; raw="{}" },
    # 操作员 op_b（来自电脑 B）：删除快照
    @{ oper_id="op_b"; ts_ms=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()+10000; server_id="client-node-B"; op_type="snapshot"; res_key="vm_snap_destroy"; op_param="snapshot delete vm_snap"; work_order_id=""; raw="{}"
    }
)} | ConvertTo-Json -Depth 5

# 注入到服务端
Invoke-WebRequest -Uri "http://127.0.0.1:8443/collusion/ingest" -Method POST `
    -Headers $headers -Body $attack -ContentType "application/json"

Write-Host "跨机合谋攻击已注入，等待窗口到期..."
```

**怎么判断做对了**：等短窗口到期（默认 15 分钟）后：

```powershell
Start-Sleep -Seconds 910  # 等 15 分钟 + 10 秒宽限期

# 查看概览
$overview = Invoke-WebRequest -Uri "http://127.0.0.1:8443/collusion/overview" -Headers $headers
Write-Host $overview.Content
# 预期：HIGH >= 1

# 查看告警详情
$events = Invoke-WebRequest -Uri "http://127.0.0.1:8443/collusion/events?level=HIGH" -Headers $headers
Write-Host $events.Content
# 预期：含 rule_id="R-001" 的事件，risk_score 约为 85
```

**判定标准**：
- 概览 HIGH 计数 ≥ 1
- 事件详情含 `rule_id: "R-001"`、`risk_score: 85`（±5）
- 事件涉及的 server_id 含 `client-node-B` 和 `client-node-C`

### 实验 3：真实采集链路验证

**目的**：确认客户端真实采集的审计事件能上传到服务端并入库。

**做什么**：在客户端开启测试注入（合成事件），确认服务端能收到。

**怎么做**：
1. 在电脑 B 上编辑 `config\client_windows.yaml`，把 `test_injection.enabled` 改为 `true`
2. 重启电脑 B 的客户端
3. 等 1 分钟，在服务端 Web 控制台查看"运行概览"，确认 `eventsCollected` 在增长
4. 查看"数据库管理"，选择 `client-node-B`，确认有数据

**判定标准**：服务端能看到电脑 B 上传的事件，数据库中有记录。

### 实验 4：远程控制指令下发

**目的**：验证服务端能向客户端下发指令。

**做什么**：从服务端向电脑 B 发送 `echo` 测试指令。

**怎么做**（在电脑 A 的浏览器）：
1. 打开"主机管理"页面
2. 在"远程控制指令"区域，目标主机 ID 填 `client-node-B`
3. 指令类型选 `echo`
4. 指令参数填 `hello from server`
5. 点击"发送到目标主机"

**怎么判断做对了**：
- 电脑 B 的客户端终端输出 `收到远程指令: echo hello from server`
- 服务端 Web 控制台显示指令已送达

---

## 六、结果收集与对比（15 分钟）

### 步骤 12：导出实验数据

**做什么**：从服务端导出全部实验数据用于分析。

**怎么做**（电脑 A 的 PowerShell）：

```powershell
# 导出合谋检测事件
Invoke-WebRequest -Uri "http://127.0.0.1:8443/collusion/events/export" `
    -Headers $headers -OutFile "results/collusion_events_$(Get-Date -Format yyyyMMdd_HHmm).ndjson"

# 导出主机数据库（每个客户端独立数据库）
# 在 Web 控制台"数据库管理"页面，选择主机后点击"导出"

# 导出运行概览快照
$overview = Invoke-WebRequest -Uri "http://127.0.0.1:8443/manager/status" -Headers $headers
$overview.Content | Out-File "results/overview_$(Get-Date -Format yyyyMMdd_HHmm).json"
```

### 步骤 13：结果校验

**做什么**：对照预期检查实验结果。

**校验标准表**：

| 校验项 | 预期 | 实际 | 是否合格 |
|--------|------|------|----------|
| 两台客户端在线 | 都在线 | ________ | ________ |
| 正常基线无误报 | HIGH=0, MID=0 | ________ | ________ |
| R-001 跨机合谋检测 | HIGH≥1, rule_id=R-001 | ________ | ________ |
| 真实采集数据入库 | client-node-B 有数据 | ________ | ________ |
| 远程指令送达 | 客户端收到 echo | ________ | ________ |
| 数据完整性 | 重启后数据不丢 | ________ | ________ |

### 步骤 14：跨机数据一致性校验

**做什么**：确认每台客户端的数据在服务端独立数据库中正确隔离。

**怎么做**：
1. 在 Web 控制台"数据库管理"页面
2. 分别选择 `client-node-B` 和 `client-node-C`
3. 确认各自数据库中的事件 `server_id` 字段只含自己的 ID
4. 确认没有数据串台

**判定标准**：B 的数据库只有 B 的事件，C 的数据库只有 C 的事件。

---

## 七、常见故障排查

### 故障 1：网络不通

**现象**：客户端报 `连接服务端失败` 或 `curl` 超时。

**排查步骤**：
1. 在客户端 ping 服务端 IP：`ping 192.168.1.100`
2. 如果 ping 不通 → 检查物理网线/WiFi、同网段
3. 如果 ping 通但 8443 不通 → 检查服务端防火墙：
   ```powershell
   # 在电脑 A 上放行 8443
   New-NetFirewallRule -DisplayName "AF 8443" -Direction Inbound -LocalPort 8443 -Protocol TCP -Action Allow
   ```
4. 如果还是不通 → 检查服务端 `listen` 是否为 `0.0.0.0:8443`

### 故障 2：客户端 ID 重复

**现象**：服务端只看到一台客户端，另一台被覆盖。

**原因**：两台客户端的 `agent.id` 相同。

**解决**：确保电脑 B 的 `agent.id` 是 `client-node-B`，电脑 C 是 `client-node-C`，互不相同。

### 故障 3：版本不一致

**现象**：三台电脑的代码版本不同步，行为不一致。

**排查**：
```powershell
# 在每台电脑上执行，对比 commit hash
git rev-parse HEAD
```

**解决**：如果 hash 不一致，在落后的电脑上执行 `git pull origin master` 同步。

### 故障 4：权限不足

**现象**：客户端无法采集事件，或服务端无法绑定端口。

**排查**：
- 服务端绑定 8443 需要管理员权限：用管理员 PowerShell 启动
- 客户端采集 Windows 事件日志需要管理员权限：用管理员 PowerShell 启动客户端
- 如果服务端以 Windows 服务安装，确认 `auditforwarderd` 服务以 LocalSystem 账户运行

### 故障 5：时间不同步导致事件乱序

**现象**：合谋检测不触发，因为事件时间戳乱序。

**排查**：
```powershell
# 在每台电脑上检查系统时间
w32tm /query /status
# 如果偏差超过 1 秒，同步时间
w32tm /resync /force
```

**解决**：确保三台电脑系统时间同步（NTP）。或注入事件时统一用服务端时间戳。

### 故障 6：数据串台

**现象**：客户端 B 的数据出现在客户端 C 的数据库里。

**原因**：注入事件时 `server_id` 写错了。

**解决**：注入事件时，`server_id` 必须与客户端的 `agent.id` 一致。B 的事件 `server_id` 填 `client-node-B`，C 的填 `client-node-C`。

---

## 八、数据同步方式与成功判定

### 8.1 数据同步方式

| 数据类型 | 同步方向 | 方式 | 频率 |
|----------|----------|------|------|
| 审计事件 | 客户端→服务端 | HTTP POST /ingest | 5 秒/批（realtime 模式） |
| 心跳 | 客户端→服务端 | HTTP POST /remote/heartbeat | 5 秒 |
| 远程指令 | 服务端→客户端 | 客户端轮询 /remote/commands | 3 秒 |
| 合谋检测结果 | 服务端本地 | events.jsonl 落盘 | 窗口到期时 |

### 8.2 成功判定条件

| 判定维度 | 成功标准 |
|----------|----------|
| 网络连通 | 三台电脑互 ping 通，8443 端口可达 |
| 客户端接入 | 两台客户端都显示在线，心跳正常 |
| 数据采集 | 客户端事件上传到服务端并入库 |
| 数据隔离 | 每台客户端数据在独立数据库中 |
| 合谋检测 | 跨机合谋攻击被检测为 HIGH |
| 远程控制 | 服务端指令能下发到指定客户端 |
| 误报率 | 正常运行 15 分钟无 HIGH/MID 告警 |
| 数据完整性 | 服务端重启后数据不丢 |

---

## 九、可复现性保障

1. **代码版本一致**：三台电脑 `git rev-parse HEAD` 输出相同
2. **配置文件归档**：三台电脑的 `config/*.yaml` 实验后归档到 `results/config_snapshot/`
3. **事件模板复用**：所有注入事件保存为 JSON 文件，归档到 `tests/fixtures/multi_node/`
4. **步骤可独立执行**：每个实验编号明确，无需前置依赖（除连通性外）
5. **结果可追溯**：events.jsonl 含完整证据链，支持事后审计
6. **环境无特殊依赖**：标准 Windows + MSYS2 局域网环境，无云服务依赖

---

## 十、完整时间线总结

```
准备阶段（30 分钟）
  ├─ 步骤 1：三台电脑拉取代码
  ├─ 步骤 2：三台电脑构建项目
  ├─ 步骤 3：记录每台 IP
  └─ 步骤 4：验证网络互通
       ↓
配置阶段（20 分钟）
  ├─ 步骤 5：配置电脑 A（服务端，listen=0.0.0.0:8443）
  ├─ 步骤 6：配置电脑 B（客户端 1，指向 A 的 IP）
  └─ 步骤 7：配置电脑 C（客户端 2，指向 A 的 IP）
       ↓
连通性验证（15 分钟）
  ├─ 步骤 8：启动服务端
  ├─ 步骤 9：从客户端验证服务端可达
  ├─ 步骤 10：启动两台客户端
  └─ 步骤 11：Web 控制台确认在线
       ↓
实验执行（90 分钟）
  ├─ 实验 1：正常基线（15 分钟）
  ├─ 实验 2：跨机合谋攻击注入（20 分钟）
  ├─ 实验 3：真实采集链路（15 分钟）
  └─ 实验 4：远程控制指令（10 分钟）
       ↓
结果收集（15 分钟）
  ├─ 步骤 12：导出实验数据
  ├─ 步骤 13：结果校验
  └─ 步骤 14：数据一致性校验
```

---

> 本指南所有步骤可在标准 Windows 局域网环境下独立执行，不依赖云服务或特殊私有环境。三台电脑按角色分工，配置明确，故障排查节点完整覆盖。
