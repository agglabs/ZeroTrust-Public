// interpreter.cpp

#include "ztl/interpreter.hpp"

#include <cctype>
#include <cmath>
#include <sstream>

namespace ztl {
    // ---------- Value helpers ----------

    bool is_truthy(const Value& v) {
        if (std::holds_alternative<std::monostate>(v)) return false;
        if (auto b = std::get_if<bool>(&v)) return *b;
        if (auto n = std::get_if<double>(&v)) return *n != 0.0;
        if (auto s = std::get_if<std::string>(&v)) return !s->empty();
        return true;
    }

    bool values_equal(const Value& a, const Value& b) {
        if (a.index() != b.index()) return false;
        if (std::holds_alternative<std::monostate>(a)) return true;
        if (auto pa = std::get_if<bool>(&a))        return *pa == std::get<bool>(b);
        if (auto pa = std::get_if<double>(&a))      return *pa == std::get<double>(b);
        if (auto pa = std::get_if<std::string>(&a)) return *pa == std::get<std::string>(b);
        if (auto pa = std::get_if<std::shared_ptr<Object>>(&a))
            return *pa == std::get<std::shared_ptr<Object>>(b);
        if (auto pa = std::get_if<std::shared_ptr<NativeFn>>(&a))
            return *pa == std::get<std::shared_ptr<NativeFn>>(b);
        return false;
    }

    std::string value_to_string(const Value& v) {
        if (std::holds_alternative<std::monostate>(v)) return "null";
        if (auto b = std::get_if<bool>(&v))            return *b ? "true" : "false";
        if (auto n = std::get_if<double>(&v)) {
            std::ostringstream os;
            if (*n == std::floor(*n) && std::isfinite(*n) && std::abs(*n) < 1e15) os << static_cast<long long>(*n);
            else os << *n;
            return os.str();
        }
        if (auto s = std::get_if<std::string>(&v)) return *s;
        if (auto o = std::get_if<std::shared_ptr<Object>>(&v)) return "<" + (*o)->type_name + ">";
        if (auto f = std::get_if<std::shared_ptr<NativeFn>>(&v)) return "<fn " + (*f)->name + ">";
        return "?";
    }

    std::string type_name_of(const Value& v) {
        if (std::holds_alternative<std::monostate>(v)) return "null";
        if (std::holds_alternative<bool>(v))          return "bool";
        if (std::holds_alternative<double>(v))        return "number";
        if (std::holds_alternative<std::string>(v))   return "string";
        if (std::holds_alternative<std::shared_ptr<Object>>(v))   return "object";
        if (std::holds_alternative<std::shared_ptr<NativeFn>>(v)) return "function";
        return "unknown";
    }

    // ---------- Interpreter ----------

    Interpreter::Interpreter() {}

    void Interpreter::define_global(const std::string& name, Value v) { globals_.define(name, std::move(v)); }
    Value* Interpreter::global(const std::string& name) { return globals_.lookup(name); }

    void Interpreter::run_program(const Program& p) {
        for (const auto& s : p.statements) exec_stmt(*s, globals_);
    }

    void Interpreter::exec_stmt(const Stmt& s, Environment& env) {
        std::visit([&](auto& n) {
            using T = std::decay_t<decltype(n)>;
            if constexpr (std::is_same_v<T, IncludeStmt>) {
                // Includes are no-ops in MVP; stdlib is always available.
                (void)n;
            } else if constexpr (std::is_same_v<T, ExprStmt>) {
                (void)eval_expr(*n.expr, env);
            } else if constexpr (std::is_same_v<T, AssignStmt>) {
                Value v = eval_expr(*n.value, env);
                if (!env.assign(n.target_name, v)) env.define(n.target_name, std::move(v));
            } else if constexpr (std::is_same_v<T, IfStmt>) {
                Value cond = eval_expr(*n.condition, env);
                if (is_truthy(cond)) exec_block(n.then_branch, env);
                else if (!n.else_branch.empty()) exec_block(n.else_branch, env);
            } else if constexpr (std::is_same_v<T, ReturnStmt>) {
                Value v;
                if (n.value) v = eval_expr(*n.value, env);
                throw ReturnException{std::move(v)};
            }
        }, s.node);
    }

    void Interpreter::exec_block(const std::vector<StmtPtr>& body, Environment& env) {
        Environment scope(&env);
        for (const auto& s : body) exec_stmt(*s, scope);
    }

    Value Interpreter::eval_expr(const Expr& e, Environment& env) {
        return std::visit([&](auto& n) -> Value {
            using T = std::decay_t<decltype(n)>;
            if constexpr (std::is_same_v<T, LiteralNull>)   { return Value{std::monostate{}}; }
            else if constexpr (std::is_same_v<T, LiteralBool>)   { return Value{n.value}; }
            else if constexpr (std::is_same_v<T, LiteralNumber>) { return Value{n.value}; }
            else if constexpr (std::is_same_v<T, LiteralString>) { return Value{n.value}; }
            else if constexpr (std::is_same_v<T, Identifier>) {
                Value* v = env.lookup(n.name);
                if (!v) throw RuntimeError("undefined identifier '" + n.name + "'", e.line, e.col);
                return *v;
            }
            else if constexpr (std::is_same_v<T, ScopedAccess>) {
                std::string key = n.scope + "::" + n.name;
                Value* v = env.lookup(key);
                if (!v) throw RuntimeError("undefined scoped name '" + key + "'", e.line, e.col);
                return *v;
            }
            else if constexpr (std::is_same_v<T, MemberAccess>) {
                return eval_member(n, env);
            }
            else if constexpr (std::is_same_v<T, Call>) {
                return eval_call(n, env, e.line, e.col);
            }
            else if constexpr (std::is_same_v<T, UnaryOp>) {
                Value operand = eval_expr(*n.operand, env);
                if (n.op == "!") return Value{!is_truthy(operand)};
                if (n.op == "-") {
                    auto num = as_number(operand);
                    if (!num) throw RuntimeError("cannot negate non-number", e.line, e.col);
                    return Value{-*num};
                }
                throw RuntimeError("unknown unary op '" + n.op + "'", e.line, e.col);
            }
            else if constexpr (std::is_same_v<T, BinaryOp>) {
                if (n.op == "&&") { Value l = eval_expr(*n.lhs, env); if (!is_truthy(l)) return l; return eval_expr(*n.rhs, env); }
                if (n.op == "||") { Value l = eval_expr(*n.lhs, env); if (is_truthy(l)) return l;  return eval_expr(*n.rhs, env); }
                Value l = eval_expr(*n.lhs, env);
                Value r = eval_expr(*n.rhs, env);
                if (n.op == "==") return Value{values_equal(l, r)};
                if (n.op == "!=") return Value{!values_equal(l, r)};
                if (n.op == "+") {
                    if (as_number(l) && as_number(r)) return Value{*as_number(l) + *as_number(r)};
                    return Value{value_to_string(l) + value_to_string(r)};
                }
                if (n.op == "-") {
                    if (as_number(l) && as_number(r)) return Value{*as_number(l) - *as_number(r)};
                    throw RuntimeError("'-' requires numbers", e.line, e.col);
                }
                auto need_num = [&](const Value& v) -> double {
                    auto p = as_number(v);
                    if (!p) throw RuntimeError("comparison requires numbers", e.line, e.col);
                    return *p;
                };
                if (n.op == "<")  return Value{need_num(l) <  need_num(r)};
                if (n.op == ">")  return Value{need_num(l) >  need_num(r)};
                if (n.op == "<=") return Value{need_num(l) <= need_num(r)};
                if (n.op == ">=") return Value{need_num(l) >= need_num(r)};
                throw RuntimeError("unknown binary op '" + n.op + "'", e.line, e.col);
            }
            return Value{std::monostate{}};
        }, e.node);
    }

    Value Interpreter::eval_member(const MemberAccess& m, Environment& env) {
        Value receiver = eval_expr(*m.object, env);
        auto obj = as_object(receiver);
        if (!obj) throw RuntimeError("cannot access '." + m.member + "' on non-object (" + type_name_of(receiver) + ")",
                                     m.object->line, m.object->col);
        auto fit = obj->fields.find(m.member);
        if (fit != obj->fields.end()) return fit->second;
        // Methods are only reachable via Call — but expose as bound function for completeness.
        auto mit = obj->methods.find(m.member);
        if (mit != obj->methods.end()) return Value{mit->second};
        throw RuntimeError("object '" + obj->type_name + "' has no member '" + m.member + "'",
                           m.object->line, m.object->col);
    }

    Value Interpreter::eval_call(const Call& c, Environment& env, int line, int col) {
        std::vector<Value> pos;
        std::unordered_map<std::string, Value> named;
        for (const auto& a : c.args) {
            Value v = eval_expr(*a.value, env);
            if (a.name.empty()) pos.push_back(std::move(v));
            else                named[a.name] = std::move(v);
        }
        const std::vector<StmtPtr>* block = c.has_block ? &c.trailing_block : nullptr;

        // Method call?  callee is MemberAccess.
        if (auto mm = std::get_if<MemberAccess>(&c.callee->node)) {
            Value receiver = eval_expr(*mm->object, env);
            return invoke_method(receiver, mm->member, pos, named, block, line, col);
        }
        // Otherwise: evaluate callee as a value and call it.
        Value callee = eval_expr(*c.callee, env);
        return invoke_function(callee, Value{std::monostate{}}, pos, named, block, line, col);
    }

    static Value call_string_method(const std::string& s, const std::string& method,
                                    std::vector<Value>& pos, int line, int col) {
        auto need_str = [&](std::size_t i, const std::string& what) -> const std::string& {
            if (i >= pos.size()) throw RuntimeError(what + " missing", line, col);
            auto p = as_string(pos[i]);
            if (!p) throw RuntimeError(what + " must be a string", line, col);
            return *p;
        };
        auto need_num = [&](std::size_t i, const std::string& what) -> double {
            if (i >= pos.size()) throw RuntimeError(what + " missing", line, col);
            auto p = as_number(pos[i]);
            if (!p) throw RuntimeError(what + " must be a number", line, col);
            return *p;
        };
        if (method == "length" || method == "size") return Value{static_cast<double>(s.size())};
        if (method == "starts_with") {
            const std::string& p = need_str(0, "prefix");
            return Value{s.size() >= p.size() && s.compare(0, p.size(), p) == 0};
        }
        if (method == "ends_with") {
            const std::string& p = need_str(0, "suffix");
            return Value{s.size() >= p.size() && s.compare(s.size() - p.size(), p.size(), p) == 0};
        }
        if (method == "contains") {
            const std::string& p = need_str(0, "substring");
            return Value{s.find(p) != std::string::npos};
        }
        if (method == "slice") {
            std::size_t start = static_cast<std::size_t>(need_num(0, "start"));
            if (start > s.size()) start = s.size();
            std::size_t end = s.size();
            if (pos.size() > 1) {
                double e = need_num(1, "end");
                if (e < 0) end = 0;
                else if (static_cast<std::size_t>(e) < end) end = static_cast<std::size_t>(e);
            }
            if (end < start) end = start;
            return Value{s.substr(start, end - start)};
        }
        if (method == "to_lower") {
            std::string out = s;
            for (auto& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            return Value{out};
        }
        if (method == "to_upper") {
            std::string out = s;
            for (auto& c : out) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
            return Value{out};
        }
        if (method == "trim") {
            std::size_t a = 0, b = s.size();
            while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) a++;
            while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) b--;
            return Value{s.substr(a, b - a)};
        }
        if (method == "index_of") {
            const std::string& p = need_str(0, "substring");
            auto i = s.find(p);
            return Value{i == std::string::npos ? -1.0 : static_cast<double>(i)};
        }
        throw RuntimeError("string has no method '" + method + "'", line, col);
    }

    Value Interpreter::invoke_method(const Value& receiver, const std::string& method,
                                     std::vector<Value>& pos, std::unordered_map<std::string, Value>& named,
                                     const std::vector<StmtPtr>* block, int line, int col) {
        if (auto s = as_string(receiver)) {
            (void)named; (void)block;
            return call_string_method(*s, method, pos, line, col);
        }
        auto obj = as_object(receiver);
        if (!obj) throw RuntimeError("cannot call method '" + method + "' on " + type_name_of(receiver), line, col);
        auto it = obj->methods.find(method);
        if (it == obj->methods.end()) throw RuntimeError(
            "object '" + obj->type_name + "' has no method '" + method + "'", line, col);
        CallContext ctx;
        ctx.self = receiver;
        ctx.positional = std::move(pos);
        ctx.named = std::move(named);
        ctx.block = block;
        ctx.interp = this;
        ctx.line = line; ctx.col = col;
        return it->second->fn(ctx);
    }

    Value Interpreter::invoke_function(const Value& callee, Value self,
                                       std::vector<Value>& pos, std::unordered_map<std::string, Value>& named,
                                       const std::vector<StmtPtr>* block, int line, int col) {
        auto fn = std::get_if<std::shared_ptr<NativeFn>>(&callee);
        if (!fn) throw RuntimeError("value is not callable (" + type_name_of(callee) + ")", line, col);
        CallContext ctx;
        ctx.self = std::move(self);
        ctx.positional = std::move(pos);
        ctx.named = std::move(named);
        ctx.block = block;
        ctx.interp = this;
        ctx.line = line; ctx.col = col;
        return (*fn)->fn(ctx);
    }
}
