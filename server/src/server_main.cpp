// AuditForwarder 服务端入口：运行在监管端，负责管理 API、Web 前端和客户端注册监控。

#include "auditforwarder/agent.h"
#include "auditforwarder/build_config.h"
#include "auditforwarder/logger.h"

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>

namespace {

std::string get_arg(int argc, char** argv, int& i, const std::string& opt) {
    if (i + 1 >= argc) {
        std::cerr << "选项 " << opt << " 缺少参数\n";
        std::exit(2);
    }
    return argv[++i];
}

void print_help() {
    std::cout <<
R"(AuditForwarder Server - 监管服务端

用法:
  auditforwarder-server [选项]

选项:
  -c, --config <path>   服务端配置文件
  -d, --data <dir>      服务端数据目录
  -L, --level <level>   日志级别: debug|info|notice|warning|error|critical
      --listen <addr>   监听地址，例如 127.0.0.1:8443
  -h, --help            显示帮助
)";
}

}  // namespace

int main(int argc, char** argv) {
    using namespace af;

    AgentConfig cfg;
    cfg.agent_id = "auditforwarder-server";
    cfg.data_dir = AF_DEFAULT_DATA_DIR;
    cfg.config_path = AF_DEFAULT_CONFIG_PATH;
    cfg.manager_enabled = true;
    cfg.remote_enabled = false;
    cfg.collectors_enabled = false;
    cfg.self_protect_enabled = false;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "-h" || a == "--help") { print_help(); return 0; }
        if (a == "-c" || a == "--config") cfg.config_path = get_arg(argc, argv, i, a);
        else if (a == "-d" || a == "--data") cfg.data_dir = get_arg(argc, argv, i, a);
        else if (a == "-L" || a == "--level") cfg.log_level = severity_from_string(get_arg(argc, argv, i, a));
        else if (a == "--listen") cfg.manager_listen = get_arg(argc, argv, i, a);
        else {
            std::cerr << "未知选项: " << a << "\n";
            print_help();
            return 2;
        }
    }

    Agent server;
    auto r = server.init(cfg);
    if (r.is_err()) {
        std::cerr << "服务端初始化失败: " << r.error().message() << "\n";
        return 1;
    }
    r = server.start();
    if (r.is_err()) {
        std::cerr << "服务端启动失败: " << r.error().message() << "\n";
        return 1;
    }

    AF_LOG_INFO("auditforwarder-server " << AF_VERSION_STRING << " 正在运行。按 Ctrl+C 停止。");
    while (server.is_running()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    server.stop();
    return 0;
}
