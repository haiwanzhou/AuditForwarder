# AuditForwarder VS Code 编译与运行指南

本文档用于指导接收方在 VS Code 中打开、编译、运行和调试已打包交付的 AuditForwarder 源码项目。交付方式为 ZIP 压缩包，不要求也不依赖 `git clone`。

## 1. 开发环境要求

| 类型 | 推荐版本 | 说明 |
| --- | --- | --- |
| 操作系统 | Windows 10/11 或 Linux | 本指南以 Windows + VS Code 为主 |
| VS Code | 最新稳定版 | 项目编辑、终端运行和调试 |
| Node.js | 18.x 或更高 | 用于执行 `npm run dev`、`npm run build` 等便捷脚本 |
| npm | 9.x 或更高 | 用于生成 `package-lock.json` 并运行脚本 |
| CMake | 3.16 或更高 | C++ 项目构建系统 |
| C++ 编译器 | MSYS2 MinGW-w64、Visual Studio 2022 或 GCC 9+ | 编译服务端、客户端和测试程序 |
| OpenSSL | 1.1.1 或更高 | 加密、签名、哈希功能 |
| zlib | 1.2 或更高 | 压缩功能 |
| PostgreSQL | 15 或更高，可选 | 仅在需要验证数据库脚本时安装 |

本项目主体是 C++/CMake。`package.json` 只封装常用命令，不包含业务 npm 依赖：

```json
"dependencies": {},
"devDependencies": {}
```

## 2. VS Code 推荐插件

建议安装：

| 插件 | 插件 ID | 用途 |
| --- | --- | --- |
| C/C++ | `ms-vscode.cpptools` | C++ 语法、跳转、调试 |
| CMake Tools | `ms-vscode.cmake-tools` | CMake 配置和构建 |
| CMake | `twxs.cmake` | CMakeLists.txt 语法高亮 |
| YAML | `redhat.vscode-yaml` | 配置文件编辑 |
| PowerShell | `ms-vscode.powershell` | Windows 终端脚本支持 |
| Markdown All in One | `yzhang.markdown-all-in-one` | 查看和编辑说明文档 |

可选 VS Code 设置：

```json
{
  "cmake.configureOnOpen": false,
  "files.encoding": "utf8bom",
  "terminal.integrated.defaultProfile.windows": "PowerShell"
}
```

说明：项目配置和中文文档建议使用 UTF-8 或 UTF-8 with BOM 保存，避免 Windows 控制台中文显示异常。

## 3. 解压并打开项目

1. 获取交付压缩包，例如 `AuditForwarder_source.zip`。
2. 解压到本地任意目录。
3. 打开 VS Code。
4. 选择“文件 -> 打开文件夹”。
5. 选择解压后的 `AuditForwarder` 项目根目录。
6. 打开“终端 -> 新建终端”。

检查当前目录是否正确：

```powershell
Get-ChildItem
```

应能看到：

```text
client
config
docs
include
scripts
server
shared
tests
CMakeLists.txt
package.json
README.md
```

## 4. 安装依赖

在 VS Code 终端执行：

```powershell
npm install
```

预期结果：

- 生成 `package-lock.json`。
- 因为没有外部 npm 依赖，通常不会生成大型 `node_modules` 目录。
- 如果生成空的 `node_modules`，交付打包前仍应删除。

Windows 使用 MSYS2 时，先在终端设置工具链路径：

```powershell
$env:MSYS2_ROOT = "<MSYS2安装目录>"
$env:PATH = "$env:MSYS2_ROOT\mingw64\bin;$env:MSYS2_ROOT\usr\bin;$env:PATH"
```

检查工具：

```powershell
node --version
npm --version
cmake --version
g++ --version
openssl version
```

## 5. 编译步骤

推荐使用 npm 脚本：

```powershell
npm run configure
npm run build
```

等价 CMake 命令：

```powershell
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build --config Release
```

构建成功后，`build` 目录中应生成：

```text
auditforwarder-server.exe
auditforwarder-client.exe
auditforwarderd.exe
auditforwarder_tests.exe
```

## 6. 运行服务端

方式一：构建并启动服务端。

```powershell
npm run dev
```

方式二：已构建后直接启动服务端。

```powershell
npm run start:server
```

等价命令：

```powershell
.\build\auditforwarder-server.exe -c .\config\server_windows.yaml
```

访问管理页面：

```text
http://127.0.0.1:8443/
```

本地登录账号：

交付包不内置默认密码，`login_password_sha256` 为占位值，首次使用前请按《本地测试环境配置说明.md》第 6 节生成并替换为自己的密码哈希。

API Token 示例：

```text
<请填写你在配置中自行设置的 auth_token；默认留空时接口无需认证>
```

生产环境必须修改默认账号、密码哈希、Token 和注册密钥。

## 7. 运行客户端

保持服务端运行，新开一个 VS Code 终端：

```powershell
npm run start:client
```

等价命令：

```powershell
.\build\auditforwarder-client.exe -c .\config\client_windows.yaml
```

客户端会连接：

```text
http://127.0.0.1:8443
```

如果服务端部署在其他机器，请修改：

```text
config/client_windows.yaml
```

## 8. 运行测试

```powershell
npm test
```

等价命令：

```powershell
ctest --test-dir build --output-on-failure
```

手动验证服务端状态（`auth_token` 为空时无需认证头；已配置时替换为你的 Token）：

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8443/status" -Headers @{ Authorization = "Bearer <你的auth_token>" }
```

预期返回中包含：

```text
running: true
```

## 9. 运行调试流程

如果需要在 VS Code 里使用“终端 -> 运行生成任务”或“运行和调试”面板，可以在项目根目录创建 `.vscode` 目录，并添加下面两个配置文件。

`.vscode/tasks.json`：

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "配置 CMake",
      "type": "shell",
      "command": "npm",
      "args": ["run", "configure"],
      "group": "build",
      "problemMatcher": []
    },
    {
      "label": "编译项目",
      "type": "shell",
      "command": "npm",
      "args": ["run", "build"],
      "group": {
        "kind": "build",
        "isDefault": true
      },
      "problemMatcher": ["$gcc"]
    },
    {
      "label": "运行测试",
      "type": "shell",
      "command": "npm",
      "args": ["test"],
      "dependsOn": "编译项目",
      "group": "test",
      "problemMatcher": []
    }
  ]
}
```

`.vscode/launch.json`：

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "调试服务端",
      "type": "cppdbg",
      "request": "launch",
      "program": "${workspaceFolder}/build/auditforwarder-server.exe",
      "args": ["-c", "config/server_windows.yaml"],
      "cwd": "${workspaceFolder}",
      "stopAtEntry": false,
      "externalConsole": false,
      "MIMode": "gdb",
      "miDebuggerPath": "gdb.exe",
      "preLaunchTask": "编译项目"
    },
    {
      "name": "调试客户端",
      "type": "cppdbg",
      "request": "launch",
      "program": "${workspaceFolder}/build/auditforwarder-client.exe",
      "args": ["-c", "config/client_windows.yaml"],
      "cwd": "${workspaceFolder}",
      "stopAtEntry": false,
      "externalConsole": false,
      "MIMode": "gdb",
      "miDebuggerPath": "gdb.exe",
      "preLaunchTask": "编译项目"
    }
  ]
}
```

如果使用 Visual Studio 生成器，生成文件可能位于 `build/Release/` 或 `build/Debug/` 目录，此时把 `program` 改成对应路径即可。

### 9.1 服务端调试

1. 在 VS Code 中打开 `server/src/server_main.cpp`。
2. 在入口逻辑或 `server/src/manager/manager_server.cpp` 中设置断点。
3. 使用 CMake Tools 选择构建目标 `auditforwarder-server`。
4. 调试参数设置为：

```text
-c config/server_windows.yaml
```

### 9.2 客户端调试

1. 打开 `client/src/client_main.cpp`。
2. 在启动逻辑或 `client/src/core/agent.cpp` 中设置断点。
3. 调试目标选择 `auditforwarder-client`。
4. 调试参数设置为：

```text
-c config/client_windows.yaml
```

## 10. 常见问题

### 10.1 `npm run build` 提示找不到 `cmake`

原因：CMake 未安装或未加入 PATH。

解决：安装 CMake 后重启 VS Code，再执行 `cmake --version` 检查。

### 10.2 `g++` 或 `make` 找不到

原因：MSYS2 或编译工具链未配置。

解决：设置 `MSYS2_ROOT` 和 `PATH`，或改用 Visual Studio 2022 工具链。

### 10.3 `/status` 返回 `unauthorized`

原因：接口需要 Bearer Token。

解决：请求头加入你自行配置的 `auth_token`：

```text
Authorization: Bearer <你的auth_token>
```

### 10.4 8443 端口被占用

解决：停止占用端口的程序，或修改 `config/server_windows.yaml` 中的：

```yaml
manager:
  listen: 127.0.0.1:8443
```

### 10.5 Windows 安全日志采集失败

原因：订阅 Windows 安全日志需要管理员权限。

解决：以管理员身份运行 VS Code 或终端；如果只测试 Web 管理页面，可以忽略该采集错误。

### 10.6 PostgreSQL 连接失败

检查：

- PostgreSQL 服务是否启动。
- `psql` 是否可用。
- 数据库名、用户名、密码是否与配置一致。
- 是否先执行 `001_schema.sql`，再执行 `002_seed.sql`。

## 11. 交付前清理要求

压缩前确认不包含：

```text
node_modules/
build/
build_*/
data/
.env
*.zip
```

这些目录和文件已在 `.gitignore` 中配置，交付压缩包也会排除它们。
