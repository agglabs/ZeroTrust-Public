// runtime.hpp

#pragma once

#include "ztl/ast.hpp"

#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

namespace ztl {
    class Interpreter;

    struct Object;
    struct NativeFn;

    using Value = std::variant<
        std::monostate,                    // null
        bool,
        double,
        std::string,
        std::shared_ptr<Object>,
        std::shared_ptr<NativeFn>
    >;

    struct CallContext {
        Value self;
        std::vector<Value> positional;
        std::unordered_map<std::string, Value> named;
        const std::vector<StmtPtr>* block = nullptr;
        Interpreter* interp = nullptr;
        int line = 0;
        int col = 0;
    };

    using NativeCallback = std::function<Value(CallContext&)>;

    struct NativeFn {
        std::string name;
        NativeCallback fn;
    };

    struct Object {
        std::string type_name;
        std::unordered_map<std::string, Value> fields;
        std::unordered_map<std::string, std::shared_ptr<NativeFn>> methods;
        std::shared_ptr<void> native_state;
    };

    class RuntimeError : public std::runtime_error {
    public:
        RuntimeError(const std::string& msg, int line = 0, int col = 0)
            : std::runtime_error("runtime error at " + std::to_string(line) + ":" + std::to_string(col) + ": " + msg) {}
    };

    struct ReturnException {
        Value value;
    };

    class Environment {
    public:
        Environment() = default;
        explicit Environment(Environment* parent) : parent_(parent) {}

        void define(const std::string& name, Value v) { vars_[name] = std::move(v); }
        bool assign(const std::string& name, Value v) {
            if (vars_.count(name)) { vars_[name] = std::move(v); return true; }
            if (parent_) return parent_->assign(name, std::move(v));
            return false;
        }
        Value* lookup(const std::string& name) {
            auto it = vars_.find(name);
            if (it != vars_.end()) return &it->second;
            if (parent_) return parent_->lookup(name);
            return nullptr;
        }

    private:
        Environment* parent_ = nullptr;
        std::unordered_map<std::string, Value> vars_;
    };

    // Value helpers
    bool is_truthy(const Value& v);
    bool values_equal(const Value& a, const Value& b);
    std::string value_to_string(const Value& v);
    std::string type_name_of(const Value& v);

    inline std::shared_ptr<Object> as_object(const Value& v) {
        if (auto p = std::get_if<std::shared_ptr<Object>>(&v)) return *p;
        return nullptr;
    }
    inline const std::string* as_string(const Value& v) { return std::get_if<std::string>(&v); }
    inline const double* as_number(const Value& v) { return std::get_if<double>(&v); }
    inline const bool* as_bool(const Value& v) { return std::get_if<bool>(&v); }
}
