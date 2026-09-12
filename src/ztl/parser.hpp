// parser.hpp

#pragma once

#include "ztl/ast.hpp"
#include "ztl/token.hpp"

#include <stdexcept>
#include <vector>

namespace ztl {
    class ParseError : public std::runtime_error {
    public:
        ParseError(const std::string& msg, int line, int col)
            : std::runtime_error("parse error at " + std::to_string(line) + ":" + std::to_string(col) + ": " + msg) {}
    };

    class Parser {
    public:
        explicit Parser(std::vector<Token> tokens);
        Program parse_program();

    private:
        std::vector<Token> tokens_;
        std::size_t pos_ = 0;

        const Token& peek(int offset = 0) const;
        const Token& advance();
        bool check(TokenType t) const;
        bool match(TokenType t);
        const Token& expect(TokenType t, const std::string& what);

        StmtPtr parse_statement();
        StmtPtr parse_if();
        StmtPtr parse_return();
        StmtPtr parse_include();
        std::vector<StmtPtr> parse_block();

        ExprPtr parse_expression();
        ExprPtr parse_or();
        ExprPtr parse_and();
        ExprPtr parse_equality();
        ExprPtr parse_comparison();
        ExprPtr parse_additive();
        ExprPtr parse_unary();
        ExprPtr parse_postfix();
        ExprPtr parse_primary();

        std::vector<CallArg> parse_call_args();
    };
}
