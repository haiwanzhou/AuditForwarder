// AuditForwarder 客户端入口：运行在被监管主机上，负责采集、心跳和命令轮询。

#include "auditforwarder/agent.h"
#include "auditforwarder/build_config.h"
#include "auditforwarder/logger.h"
#include "auditforwarder/process.h"

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
R"(AuditForwarder Client - 用户端 Agent

用法:
  auditforwarder-client [选项]

选项:
  -c, --config <path>   客户端配置文件
  -d, --data <dir>      客户端数据目录
  -L, --level <level>   日志级别: debug|info|notice|warning|error|critical
      --agent-id <id>   设置客户端主机标识
      --server <url>    中心服务端地址
  -h, --help            显示帮助
)";
}

}  // namespace

int main(int argc, char** argv) {
    using namespace af;

    AgentConfig cfg;
    cfg.agent_id = proc::hostname() + "-" + std::to_string(proc::current_pid());
    cfg.data_dir = AF_DEFAULT_DATA_DIR;
    cfg.config_path = AF_DEFAULT_CONFIG_PATH;
    cfg.manager_enabled = false;
    cfg.remote_enabled = true;
    cfg.collectors_enabled = true;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "-h" || a == "--help") { print_help(); return 0; }
        if (a == "-c" || a == "--config") cfg.config_path = get_arg(argc, argv, i, a);
        else if (a == "-d" || a == "--data") cfg.data_dir = get_arg(argc, argv, i, a);
        else if (a == "-L" || a == "--level") cfg.log_level = severity_from_string(get_arg(argc, argv, i, a));
        else if (a == "--agent-id") cfg.agent_id = get_arg(argc, argv, i, a);
        else if (a == "--server") cfg.remote_server_urls.push_back(get_arg(argc, argv, i, a));
        else {
            std::cerr << "未知选项: " << a << "\n";
            print_help();
            return 2;
        }
    }

    Agent agent;
    auto r = agent.init(cfg);
    if (r.is_err()) {
        std::cerr << "客户端初始化失败: " << r.error().message() << "\n";
        return 1;
    }
    r = agent.start();
    if (r.is_err()) {
        std::cerr << "客户端启动失败: " << r.error().message() << "\n";
        return 1;
    }

    AF_LOG_INFO("auditforwarder-client " << AF_VERSION_STRING << " 正在运行。按 Ctrl+C 停止。");
    while (agent.is_running()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    agent.stop();
    return 0;
}
