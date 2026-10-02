// AuditForwarder 客户端 GUI - Windows 原生窗口界面
// 提供服务器地址配置、连接状态显示、重试机制等用户友好的图形化操作。

#include "auditforwarder/agent.h"
#include "auditforwarder/config.h"
#include "auditforwarder/logger.h"
#include "auditforwarder/process.h"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <thread>

#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <shellapi.h>

// MinGW 下 popen 使用 _popen
#ifdef __MINGW32__
#define AF_POPEN _popen
#define AF_PCLOSE _pclose
#else
#define AF_POPEN popen
#define AF_PCLOSE pclose
#endif

#pragma comment(lib, "comctl32.lib")

// 控件 ID
#define IDC_SERVER_IP       101
#define IDC_SERVER_PORT     102
#define IDC_SAVE_CONFIG     103
#define IDC_CONNECT         104
#define IDC_STATUS_LABEL    105
#define IDC_LOG_EDIT        106
#define IDC_RETRY_COUNT     107
#define IDC_AUTO_CONNECT    108
#define IDC_AGENT_ID        109

// 定时器 ID
#define IDT_CONNECT_TIMER   1
#define IDT_STATUS_TIMER    2

static const wchar_t* WINDOW_CLASS = L"AuditForwarderClientGUI";
static const wchar_t* WINDOW_TITLE = L"AuditForwarder 客户端 - 连接管理";

struct GuiState {
    af::Agent agent;
    af::AgentConfig cfg;
    std::atomic<bool> running{false};
    std::atomic<bool> connecting{false};
    std::atomic<int> retry_count{0};
    std::atomic<int> max_retries{5};
    std::atomic<bool> auto_retry{true};
    HWND hwnd = nullptr;
    HWND ip_edit = nullptr;
    HWND port_edit = nullptr;
    HWND status_label = nullptr;
    HWND log_edit = nullptr;
    HWND connect_btn = nullptr;
    HWND retry_edit = nullptr;
    HWND agent_id_edit = nullptr;
    std::string config_path = "config/client_windows.yaml";
    std::thread worker_thread;
};

static GuiState g_state;

// 追加日志到编辑框（线程安全）
void AppendLog(const std::wstring& msg) {
    if (!g_state.log_edit) return;
    std::wstring wmsg = msg + L"\r\n";
    int len = GetWindowTextLengthW(g_state.log_edit);
    SendMessageW(g_state.log_edit, EM_SETSEL, len, len);
    SendMessageW(g_state.log_edit, EM_REPLACESEL, FALSE, (LPARAM)wmsg.c_str());
}

void SetStatus(const std::wstring& status, COLORREF color = RGB(0, 0, 0)) {
    if (!g_state.status_label) return;
    SetWindowTextW(g_state.status_label, status.c_str());
    // 通过自定义绘制改变颜色（简化：仅文本）
}

std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return {};
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring out(len - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, out.data(), len);
    return out;
}

std::string WideToUtf8(const std::wstring& s) {
    if (s.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string out(len - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, out.data(), len, nullptr, nullptr);
    return out;
}

std::wstring GetEditText(HWND hwnd) {
    int len = GetWindowTextLengthW(hwnd);
    std::wstring out(len, 0);
    GetWindowTextW(hwnd, out.data(), len + 1);
    return out;
}

// 保存配置到 YAML 文件
bool SaveConfig() {
    std::wstring ip = GetEditText(g_state.ip_edit);
    std::wstring port = GetEditText(g_state.port_edit);
    std::wstring agent_id = GetEditText(g_state.agent_id_edit);
    std::wstring retry_str = GetEditText(g_state.retry_edit);

    std::string ip_utf8 = WideToUtf8(ip);
    std::string port_utf8 = WideToUtf8(port);
    std::string agent_utf8 = WideToUtf8(agent_id);

    if (ip_utf8.empty() || port_utf8.empty()) {
        AppendLog(L"[错误] IP 地址和端口不能为空");
        return false;
    }

    // 验证端口范围
    try {
        int p = std::stoi(port_utf8);
        if (p < 1 || p > 65535) {
            AppendLog(L"[错误] 端口号必须在 1-65535 之间");
            return false;
        }
    } catch (...) {
        AppendLog(L"[错误] 端口号格式不正确");
        return false;
    }

    // 生成服务端 URL
    std::string server_url = "http://" + ip_utf8 + ":" + port_utf8;

    // 更新配置对象
    g_state.cfg.remote_server_urls.clear();
    g_state.cfg.remote_server_urls.push_back(server_url);
    g_state.cfg.server_urls.clear();
    g_state.cfg.server_urls.push_back(server_url + "/ingest?agent=" + agent_utf8);
    if (!agent_utf8.empty()) {
        g_state.cfg.agent_id = agent_utf8;
        g_state.cfg.remote_host_id = agent_utf8;
    }

    // 写入 YAML 文件
    std::string yaml = R"(# AuditForwarder 客户端配置（由 GUI 自动生成）
agent:
  id: ")" + agent_utf8 + R"("
  data_dir: data/client
  config_path: ")" + g_state.config_path + R"("

log:
  level: info
  file: data/client/client.log
  max_bytes: 52428800
  max_backups: 5

chain:
  batch_size: 10
  sign_batches: false
  auto_persist: true
  hmac_key: ""

transport:
  servers:
    - ")" + server_url + R"(/ingest?agent=)" + agent_utf8 + R"("
  mode: realtime
  interval_sec: 5
  compress: true
  encrypt_payload: false
  auth_token: ""
  verify_tls: false

remote:
  enabled: true
  servers:
    - ")" + server_url + R"("
  host_id: ")" + agent_utf8 + R"("
  heartbeat_interval_sec: 5
  command_poll_interval_sec: 3
  audit_summary_interval_sec: 5
  production_mode: false
  require_tls: false
  crl_check: false
  enrollment_key: ""
  allowed_commands:
    - collect_status
    - echo
    - set_collector
    - set_collectors
    - load_rules

detector:
  rules_path: config/rules.yaml
  enable_behavior_baseline: true

self_protect:
  enabled: false

manager:
  enabled: false
  auth_token: ""

collectors:
  enabled: true

privilege_detect:
  enabled: true

test_injection:
  enabled: false
  interval_ms: 1000

processors:
  - type: enricher
  - type: pii_masker
  - type: deduper
    window_ms: 50
)";

    std::ofstream out(g_state.config_path);
    if (!out) {
        AppendLog(L"[错误] 无法写入配置文件: " + Utf8ToWide(g_state.config_path));
        return false;
    }
    out << yaml;
    AppendLog(L"[信息] 配置已保存到 " + Utf8ToWide(g_state.config_path));
    return true;
}

// 尝试连接服务端（使用 curl 探测 /status，返回 true 表示连接成功）
bool TryConnect() {
    if (g_state.connecting.load()) return false;
    g_state.connecting.store(true);

    std::wstring ip = GetEditText(g_state.ip_edit);
    std::wstring port = GetEditText(g_state.port_edit);
    std::string server_url = "http://" + WideToUtf8(ip) + ":" + WideToUtf8(port);

    SetStatus(L"连接中...");
    AppendLog(L"[信息] 正在连接服务端: " + Utf8ToWide(server_url));

    // 使用 curl 探测服务端 /status 接口，通过输出捕获 HTTP 状态码
    std::string cmd = "curl -s -o nul -w \"%{http_code}\" --connect-timeout 5 \"" + server_url + "/status\" 2>nul";
    FILE* fp = AF_POPEN(cmd.c_str(), "r");
    bool connected = false;
    if (fp) {
        char buf[64] = {0};
        if (fgets(buf, sizeof(buf), fp)) {
            int code = std::atoi(buf);
            // 2xx/3xx 视为连接成功
            connected = (code >= 200 && code < 400);
            if (!connected) {
                AppendLog(L"[警告] 服务端返回 HTTP " + std::to_wstring(code));
            }
        } else {
            AppendLog(L"[警告] curl 无输出，服务端可能未响应");
        }
        AF_PCLOSE(fp);
    } else {
        AppendLog(L"[错误] 无法执行 curl，请确认 curl 在 PATH 中");
    }

    if (connected) {
        SetStatus(L"已连接");
        AppendLog(L"[成功] 已连接到服务端 " + Utf8ToWide(server_url));
        g_state.retry_count.store(0);
    } else {
        SetStatus(L"连接失败");
        AppendLog(L"[失败] 无法连接到服务端 " + Utf8ToWide(server_url));
    }

    g_state.connecting.store(false);
    return connected;
}

// 后台工作线程：先探测连接，成功后再运行 Agent
void AgentWorker() {
    g_state.running.store(true);
    g_state.cfg.agent_id = WideToUtf8(GetEditText(g_state.agent_id_edit));
    if (g_state.cfg.agent_id.empty()) {
        g_state.cfg.agent_id = af::proc::hostname() + "-gui";
    }
    g_state.cfg.data_dir = "data/client";
    g_state.cfg.config_path = g_state.config_path;
    g_state.cfg.manager_enabled = false;
    g_state.cfg.remote_enabled = true;
    g_state.cfg.collectors_enabled = true;

    // 解析最大重试次数
    int max_retries = 5;
    try {
        std::wstring retry_str = GetEditText(g_state.retry_edit);
        if (!retry_str.empty()) {
            max_retries = std::max(1, std::stoi(WideToUtf8(retry_str)));
        }
    } catch (...) {
        // 保持默认值
    }

    // 连接前探测，支持重试
    bool connected = false;
    for (int attempt = 1; attempt <= max_retries && g_state.running.load(); ++attempt) {
        AppendLog(L"[信息] 第 " + std::to_wstring(attempt) + L"/" + std::to_wstring(max_retries) + L" 次连接尝试...");
        if (TryConnect()) {
            connected = true;
            break;
        }
        if (attempt < max_retries) {
            int backoff = std::min(30, attempt * 5); // 退避：5s, 10s, 15s... 最大30s
            AppendLog(L"[信息] 等待 " + std::to_wstring(backoff) + L" 秒后重试...");
            for (int i = 0; i < backoff * 10 && g_state.running.load(); ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
    }

    if (!connected) {
        AppendLog(L"[错误] 达到最大重试次数，连接失败");
        SetStatus(L"连接失败");
        g_state.running.store(false);
        return;
    }

    auto r = g_state.agent.init(g_state.cfg);
    if (r.is_err()) {
        AppendLog(L"[错误] Agent 初始化失败: " + Utf8ToWide(r.error().message()));
        g_state.running.store(false);
        return;
    }
    r = g_state.agent.start();
    if (r.is_err()) {
        AppendLog(L"[错误] Agent 启动失败: " + Utf8ToWide(r.error().message()));
        g_state.running.store(false);
        return;
    }
    AppendLog(L"[信息] Agent 已启动，正在运行...");
    SetStatus(L"运行中");
    while (g_state.running.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    g_state.agent.stop();
    AppendLog(L"[信息] Agent 已停止");
    SetStatus(L"已停止");
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        // 初始化通用控件
        INITCOMMONCONTROLSEX icex{ sizeof(icex), ICC_STANDARD_CLASSES | ICC_WIN95_CLASSES };
        InitCommonControlsEx(&icex);

        int y = 20;
        int label_w = 100, edit_w = 200, h = 24, gap = 10;

        // 服务器 IP
        CreateWindowW(L"STATIC", L"服务端 IP:", WS_CHILD | WS_VISIBLE,
                      20, y, label_w, h, hwnd, nullptr, nullptr, nullptr);
        g_state.ip_edit = CreateWindowW(L"EDIT", L"127.0.0.1", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                                        20 + label_w + gap, y, edit_w, h, hwnd, (HMENU)IDC_SERVER_IP, nullptr, nullptr);
        y += h + gap;

        // 端口
        CreateWindowW(L"STATIC", L"端口:", WS_CHILD | WS_VISIBLE,
                      20, y, label_w, h, hwnd, nullptr, nullptr, nullptr);
        g_state.port_edit = CreateWindowW(L"EDIT", L"8443", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                                          20 + label_w + gap, y, edit_w, h, hwnd, (HMENU)IDC_SERVER_PORT, nullptr, nullptr);
        y += h + gap;

        // Agent ID
        CreateWindowW(L"STATIC", L"客户端标识:", WS_CHILD | WS_VISIBLE,
                      20, y, label_w, h, hwnd, nullptr, nullptr, nullptr);
        g_state.agent_id_edit = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                                              20 + label_w + gap, y, edit_w, h, hwnd, (HMENU)IDC_AGENT_ID, nullptr, nullptr);
        y += h + gap;

        // 重试次数
        CreateWindowW(L"STATIC", L"最大重试:", WS_CHILD | WS_VISIBLE,
                      20, y, label_w, h, hwnd, nullptr, nullptr, nullptr);
        g_state.retry_edit = CreateWindowW(L"EDIT", L"5", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                                           20 + label_w + gap, y, edit_w, h, hwnd, (HMENU)IDC_RETRY_COUNT, nullptr, nullptr);
        y += h + gap + 5;

        // 按钮行
        CreateWindowW(L"BUTTON", L"保存配置", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                      20, y, 100, 32, hwnd, (HMENU)IDC_SAVE_CONFIG, nullptr, nullptr);
        g_state.connect_btn = CreateWindowW(L"BUTTON", L"连接服务端", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                            130, y, 110, 32, hwnd, (HMENU)IDC_CONNECT, nullptr, nullptr);
        y += 40;

        // 状态标签
        CreateWindowW(L"STATIC", L"状态:", WS_CHILD | WS_VISIBLE,
                      20, y, 50, h, hwnd, nullptr, nullptr, nullptr);
        g_state.status_label = CreateWindowW(L"STATIC", L"未连接", WS_CHILD | WS_VISIBLE | SS_LEFT,
                                             70, y, 300, h, hwnd, (HMENU)IDC_STATUS_LABEL, nullptr, nullptr);
        y += h + gap + 5;

        // 日志编辑框
        g_state.log_edit = CreateWindowW(L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL,
                                         20, y, 560, 200, hwnd, (HMENU)IDC_LOG_EDIT, nullptr, nullptr);

        AppendLog(L"[信息] AuditForwarder 客户端 GUI 已启动");
        AppendLog(L"[提示] 请输入服务端 IP 和端口，点击【保存配置】后点击【连接服务端】");
        return 0;
    }
    case WM_COMMAND: {
        switch (LOWORD(wParam)) {
        case IDC_SAVE_CONFIG: {
            if (SaveConfig()) {
                SetStatus(L"配置已保存");
            }
            return 0;
        }
        case IDC_CONNECT: {
            if (g_state.running.load()) {
                // 停止
                g_state.running.store(false);
                if (g_state.worker_thread.joinable()) g_state.worker_thread.join();
                SetWindowTextW(g_state.connect_btn, L"连接服务端");
                SetStatus(L"已停止");
                AppendLog(L"[信息] 用户手动停止连接");
            } else {
                if (SaveConfig()) {
                    // 启动 Agent 线程
                    if (g_state.worker_thread.joinable()) g_state.worker_thread.join();
                    g_state.worker_thread = std::thread(AgentWorker);
                    SetWindowTextW(g_state.connect_btn, L"停止");
                    SetStatus(L"运行中");
                }
            }
            return 0;
        }
        }
        return 0;
    }
    case WM_DESTROY: {
        g_state.running.store(false);
        if (g_state.worker_thread.joinable()) g_state.worker_thread.join();
        PostQuitMessage(0);
        return 0;
    }
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
    // 注册窗口类
    WNDCLASSEXW wc{ sizeof(wc) };
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = WINDOW_CLASS;
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    wc.hIconSm = LoadIcon(nullptr, IDI_APPLICATION);
    if (!RegisterClassExW(&wc)) {
        MessageBoxW(nullptr, L"窗口注册失败", L"错误", MB_ICONERROR);
        return 1;
    }

    // 创建主窗口
    HWND hwnd = CreateWindowExW(
        0, WINDOW_CLASS, WINDOW_TITLE,
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 620, 480,
        nullptr, nullptr, hInstance, nullptr);
    if (!hwnd) {
        MessageBoxW(nullptr, L"窗口创建失败", L"错误", MB_ICONERROR);
        return 1;
    }
    g_state.hwnd = hwnd;

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    // 消息循环
    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return static_cast<int>(msg.wParam);
}

// 兼容入口
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrev, LPSTR lpCmdLine, int nCmdShow) {
    return wWinMain(hInstance, hPrev, GetCommandLineW(), nCmdShow);
}
