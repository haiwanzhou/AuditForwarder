#pragma once
// AuditForwarder - ONNX Runtime 推理封装（M3 措施3）。
//
// 设计依据 docs/REMEDIATION_PLAN.md 第四章：
//   - 条件编译 AF_HAVE_ONNXRUNTIME：有 ONNX Runtime 时真实推理，无时优雅降级；
//   - PIMPL 封装，隐藏 ONNX Runtime C++ API 细节，避免头文件污染；
//   - 优雅降级：模型未加载 / Runtime 缺失时 is_loaded()=false、infer() 返回空向量，
//     调用方（collusion 引擎）据此跳过 ML 因子，不崩溃、不阻断。
//   - 预训练模型：models/isolation_forest.onnx（输入[1,20]→输出[1]异常分数）
//                  models/lstm_seq.onnx（序列异常检测，可选）

#include <memory>
#include <string>
#include <vector>

namespace af::ml {

// ONNX 模型封装：加载与推理。PIMPL 隔离 ONNX Runtime 依赖。
class OnnxModel {
public:
    OnnxModel();
    ~OnnxModel();

    OnnxModel(const OnnxModel&) = delete;
    OnnxModel& operator=(const OnnxModel&) = delete;

    // 加载模型文件；成功返回 true。无 ONNX Runtime 或文件缺失时返回 false（不抛异常）。
    bool load(const std::string& model_path);

    // 模型是否已加载且可推理
    bool is_loaded() const;

    // 推理：输入展平的 float 特征向量，输出模型输出向量。
    // 未加载时返回空向量（优雅降级）。
    std::vector<float> infer(const std::vector<float>& features);

    // 模型输入/输出张量名（调试用）
    std::string input_name() const;
    std::string output_name() const;

    // 最近一次错误描述（调试/日志用）
    std::string last_error() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace af::ml
