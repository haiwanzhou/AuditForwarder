// AuditForwarder - ONNX Runtime 推理封装实现。
// 条件编译：AF_HAVE_ONNXRUNTIME 定义时使用真实 ONNX Runtime C++ API，
//           否则使用优雅降级桩（load 永远失败、infer 返回空向量）。
// 详见 docs/REMEDIATION_PLAN.md 第四章 4.3.1。

#include "auditforwarder/onnx_inference.h"
#include "auditforwarder/logger.h"

namespace af::ml {

// ================================================================
// 优雅降级桩：无 ONNX Runtime 时编译此分支
// ================================================================
#ifndef AF_HAVE_ONNXRUNTIME

struct OnnxModel::Impl {
    bool loaded { false };
    std::string last_err;
    std::string model_path;
};

OnnxModel::OnnxModel() : impl_(std::make_unique<Impl>()) {
    impl_->last_err = "ONNX Runtime 未集成（编译时未启用 AF_HAVE_ONNXRUNTIME）";
}

OnnxModel::~OnnxModel() = default;

bool OnnxModel::load(const std::string& model_path) {
    impl_->model_path = model_path;
    impl_->last_err = "ONNX Runtime 未集成，无法加载模型: " + model_path;
    AF_LOG_WARN("OnnxModel::load 失败（ONNX Runtime 未集成），模型路径: " << model_path
                << " —— ML 因子将优雅降级为 0");
    impl_->loaded = false;
    return false;
}

bool OnnxModel::is_loaded() const {
    return impl_ ? impl_->loaded : false;
}

std::vector<float> OnnxModel::infer(const std::vector<float>& /*features*/) {
    // 优雅降级：未加载时返回空向量，调用方据此跳过 ML 因子
    return {};
}

std::string OnnxModel::input_name() const { return {}; }
std::string OnnxModel::output_name() const { return {}; }
std::string OnnxModel::last_error() const { return impl_ ? impl_->last_err : "未初始化"; }

#else
// ================================================================
// 真实 ONNX Runtime 实现（AF_HAVE_ONNXRUNTIME 定义时编译）
// ================================================================
#include <onnxruntime_cxx_api.h>

struct OnnxModel::Impl {
    std::unique_ptr<Ort::Env> env;
    std::unique_ptr<Ort::Session> session;
    std::string input_name_str;
    std::string output_name_str;
    std::vector<std::string> input_names_str;
    std::vector<std::string> output_names_str;
    bool loaded { false };
    std::string last_err;
    std::string model_path;
};

OnnxModel::OnnxModel() : impl_(std::make_unique<Impl>()) {
    try {
        impl_->env = std::make_unique<Ort::Env>(ORT_LOGGING_LEVEL_WARNING, "AuditForwarder");
    } catch (const std::exception& e) {
        impl_->last_err = std::string("ONNX Runtime 环境初始化失败: ") + e.what();
        AF_LOG_ERROR(impl_->last_err);
    }
}

OnnxModel::~OnnxModel() = default;

bool OnnxModel::load(const std::string& model_path) {
    impl_->model_path = model_path;
    impl_->loaded = false;
    if (!impl_->env) {
        impl_->last_err = "ONNX Runtime 环境未初始化";
        return false;
    }
    try {
        Ort::SessionOptions opts;
        opts.SetIntraOpNumThreads(1);
        opts.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_ALL);
        impl_->session = std::make_unique<Ort::Session>(*impl_->env, model_path.c_str(), opts);

        // 读取输入/输出张量名
        Ort::AllocatorWithDefaultOptions allocator;
        auto input_count = impl_->session->GetInputCount();
        for (std::size_t i = 0; i < input_count; ++i) {
            auto name = impl_->session->GetInputNameAllocated(i, allocator);
            impl_->input_names_str.push_back(name.get());
        }
        auto output_count = impl_->session->GetOutputCount();
        for (std::size_t i = 0; i < output_count; ++i) {
            auto name = impl_->session->GetOutputNameAllocated(i, allocator);
            impl_->output_names_str.push_back(name.get());
        }
        if (!impl_->input_names_str.empty())
            impl_->input_name_str = impl_->input_names_str[0];
        if (!impl_->output_names_str.empty())
            impl_->output_name_str = impl_->output_names_str[0];

        impl_->loaded = true;
        impl_->last_err.clear();
        AF_LOG_INFO("ONNX 模型加载成功: " << model_path
                    << " input=" << impl_->input_name_str
                    << " output=" << impl_->output_name_str);
        return true;
    } catch (const Ort::Exception& e) {
        impl_->last_err = std::string("ONNX Runtime 加载异常: ") + e.what();
        AF_LOG_ERROR(impl_->last_err);
    } catch (const std::exception& e) {
        impl_->last_err = std::string("模型加载失败: ") + e.what();
        AF_LOG_ERROR(impl_->last_err);
    }
    return false;
}

bool OnnxModel::is_loaded() const {
    return impl_ && impl_->loaded;
}

std::vector<float> OnnxModel::infer(const std::vector<float>& features) {
    if (!is_loaded() || !impl_->session) return {};

    try {
        // 假设输入形状 [1, N]，N = features.size()
        std::vector<int64_t> input_shape{1, static_cast<int64_t>(features.size())};
        Ort::MemoryInfo mem_info = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);
        Ort::Value input_tensor = Ort::Value::CreateTensor<float>(
            mem_info, const_cast<float*>(features.data()), features.size(),
            input_shape.data(), input_shape.size());

        const char* input_name = impl_->input_name_str.c_str();
        auto output_tensors = impl_->session->Run(
            Ort::RunOptions{nullptr}, &input_name, &input_tensor, 1,
            &impl_->output_name_str.c_str(), 1);

        if (output_tensors.empty()) return {};

        // 读取输出（假设为 float 向量）
        auto& out_tensor = output_tensors.front();
        float* out_data = out_tensor.GetTensorMutableData<float>();
        auto out_count = out_tensor.GetTensorTypeAndShapeInfo().GetElementCount();
        return std::vector<float>(out_data, out_data + out_count);
    } catch (const Ort::Exception& e) {
        impl_->last_err = std::string("ONNX 推理异常: ") + e.what();
        AF_LOG_ERROR(impl_->last_err);
    } catch (const std::exception& e) {
        impl_->last_err = std::string("推理失败: ") + e.what();
        AF_LOG_ERROR(impl_->last_err);
    }
    return {};
}

std::string OnnxModel::input_name() const { return impl_ ? impl_->input_name_str : ""; }
std::string OnnxModel::output_name() const { return impl_ ? impl_->output_name_str : ""; }
std::string OnnxModel::last_error() const { return impl_ ? impl_->last_err : "未初始化"; }

#endif  // AF_HAVE_ONNXRUNTIME

}  // namespace af::ml
