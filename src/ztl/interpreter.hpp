// interpreter.hpp

#pragma once

#include "ztl/ast.hpp"
#include "ztl/runtime.hpp"

#include <memory>
#include <string>
#include <vector>

namespace ztl {
    class Interpreter {
    public:
        Interpreter();

        void define_global(const std::string& name, Value v);
        Value* global(const std::string& name);

        void run_program(const Program& p);
        Value eval_expr(const Expr& e, Environment& env);
        void exec_stmt(const Stmt& s, Environment& env);
        void exec_block(const std::vector<StmtPtr>& body, Environment& env);

        Environment& global_env() { return globals_; }

    private:
        Environment globals_;

        Value eval_call(const Call& c, Environment& env, int line, int col);
        Value eval_member(const MemberAccess& m, Environment& env);
        Value invoke_method(const Value& receiver, const std::string& method,
                            std::vector<Value>& pos, std::unordered_map<std::string, Value>& named,
                            const std::vector<StmtPtr>* block, int line, int col);
        Value invoke_function(const Value& callee, Value self,
                              std::vector<Value>& pos, std::unordered_map<std::string, Value>& named,
                              const std::vector<StmtPtr>* block, int line, int col);
    };
}
