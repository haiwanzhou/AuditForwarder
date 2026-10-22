// AuditForwarder - 多操作员行为模拟器命令行入口（M8）。
//
// 用法示例：
//   auditforwarder-sim --scenario cert_r42 --operators 4 --output data/sim_events.jsonl
//   auditforwarder-sim --list
//
// 输出 JSONL 可直接投递到服务端 POST /collusion/ingest（支持 {"events":[...]} 批量）。

#include "auditforwarder/simulator.h"

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>

namespace {

void print_help() {
    std::cout
        << "AuditForwarder 多操作员行为模拟器（M8）\n\n"
        << "参数：\n"
        << "  --scenario <名称>       场景名称（默认 cert_r42，见 --list）\n"
        << "  --operators <2-10>      正常行为操作员数量（默认 4）\n"
        << "  --normal-events <N>     每名操作员的正常操作条数（默认 8）\n"
        << "  --seed <N>              随机种子（默认 20261022，保证可复现）\n"
        << "  --base-epoch-ms <N>     基准时间毫秒（默认当前时间）\n"
        << "  --no-attacks            仅生成正常行为（对照组）\n"
        << "  --output <文件>         输出文件（默认标准输出）\n"
        << "  --list                  列出可用场景\n"
        << "  --help                  显示本帮助\n";
}

bool parse_u64(const std::string& text, std::uint64_t& out) {
    if (text.empty()) return false;
    std::uint64_t value = 0;
    for (char c : text) {
        if (c < '0' || c > '9') return false;
        value = value * 10 + static_cast<std::uint64_t>(c - '0');
    }
    out = value;
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    af::sim::SimConfig cfg;
    std::string output;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        auto next = [&](std::string& value) {
            if (i + 1 >= argc) return false;
            value = argv[++i];
            return true;
        };
        std::string value;
        if (arg == "--help" || arg == "-h") {
            print_help();
            return 0;
        }
        if (arg == "--list") {
            for (const auto& line : af::sim::scenario_catalog()) std::cout << line << "\n";
            return 0;
        }
        if (arg == "--no-attacks") {
            cfg.inject_attacks = false;
            continue;
        }
        if (arg == "--scenario") {
            if (!next(value)) { std::cerr << "--scenario 缺少参数\n"; return 2; }
            cfg.scenario = value;
            continue;
        }
        if (arg == "--output" || arg == "-o") {
            if (!next(output)) { std::cerr << "--output 缺少参数\n"; return 2; }
            continue;
        }
        if (arg == "--operators" || arg == "--normal-events" || arg == "--seed" ||
            arg == "--base-epoch-ms") {
            if (!next(value)) { std::cerr << arg << " 缺少参数\n"; return 2; }
            std::uint64_t num = 0;
            if (!parse_u64(value, num)) { std::cerr << arg << " 需要非负整数\n"; return 2; }
            if (arg == "--operators") cfg.operators = static_cast<int>(num);
            else if (arg == "--normal-events") cfg.normal_events_per_operator = num;
            else if (arg == "--seed") cfg.seed = num;
            else cfg.base_epoch_ms = num;
            continue;
        }
        std::cerr << "未知参数：" << arg << "（使用 --help 查看用法）\n";
        return 2;
    }

    const std::string jsonl = af::sim::simulate_jsonl(cfg);
    if (jsonl.empty()) {
        std::cerr << "场景不存在或未生成事件：" << cfg.scenario << "（使用 --list 查看可用场景）\n";
        return 1;
    }

    if (output.empty()) {
        // 直接输出 JSONL 时不打印摘要，避免污染管道数据
        std::cout << jsonl;
        return 0;
    }

    {
        std::ofstream out(output, std::ios::binary | std::ios::trunc);
        if (!out) {
            std::cerr << "无法写入输出文件：" << output << "\n";
            return 1;
        }
        out << jsonl;
        if (!out) {
            std::cerr << "写入输出文件失败：" << output << "\n";
            return 1;
        }
    }

    std::size_t lines = 0;
    for (char c : jsonl) if (c == '\n') ++lines;
    std::cout << "已生成 " << lines << " 条事件（场景=" << cfg.scenario
              << " 操作员=" << cfg.operators
              << " 攻击序列=" << (cfg.inject_attacks ? "开启" : "关闭") << "）\n";
    return 0;
}
