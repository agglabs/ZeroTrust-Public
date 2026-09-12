// ast.hpp

#pragma once

#include <memory>
#include <string>
#include <variant>
#include <vector>

namespace ztl {
    struct Expr;
    struct Stmt;
    using ExprPtr = std::shared_ptr<Expr>;
    using StmtPtr = std::shared_ptr<Stmt>;

    // ---------- Expressions ----------

    struct LiteralNull {};
    struct LiteralBool   { bool value; };
    struct LiteralNumber { double value; };
    struct LiteralString { std::string value; };
    struct Identifier    { std::string name; };

    struct MemberAccess {
        ExprPtr object;
        std::string member;
    };

    struct ScopedAccess {
        std::string scope;   // e.g. "net"
        std::string name;    // e.g. "http"
    };

    struct CallArg {
        std::string name;    // empty if positional
        ExprPtr value;
    };

    struct Call {
        ExprPtr callee;
        std::vector<CallArg> args;
        std::vector<StmtPtr> trailing_block;  // for plugin.run { ... }
        bool has_block = false;
    };

    struct UnaryOp {
        std::string op;    // "!" or "-"
        ExprPtr operand;
    };

    struct BinaryOp {
        std::string op;    // "==", "!=", "<", ">", "<=", ">=", "&&", "||", "+", "-"
        ExprPtr lhs;
        ExprPtr rhs;
    };

    struct Expr {
        std::variant<
            LiteralNull,
            LiteralBool,
            LiteralNumber,
            LiteralString,
            Identifier,
            MemberAccess,
            ScopedAccess,
            Call,
            UnaryOp,
            BinaryOp
        > node;

        int line = 0;
        int col = 0;
    };

    // ---------- Statements ----------

    struct ExprStmt {
        ExprPtr expr;
    };

    struct AssignStmt {
        std::string target_name;   // simple assignment to identifier
        ExprPtr value;
    };

    struct IfStmt {
        ExprPtr condition;
        std::vector<StmtPtr> then_branch;
        std::vector<StmtPtr> else_branch;
    };

    struct ReturnStmt {
        ExprPtr value;   // may be nullptr
    };

    struct IncludeStmt {
        std::string module_name;
    };

    struct Stmt {
        std::variant<
            ExprStmt,
            AssignStmt,
            IfStmt,
            ReturnStmt,
            IncludeStmt
        > node;

        int line = 0;
        int col = 0;
    };

    // ---------- Program ----------

    struct Program {
        std::vector<StmtPtr> statements;
    };
}
