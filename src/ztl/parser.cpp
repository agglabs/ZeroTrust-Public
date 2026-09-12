// parser.cpp

#include "ztl/parser.hpp"

namespace {
    template <typename T>
    ztl::ExprPtr make_expr(T node, int line, int col) {
        auto e = std::make_shared<ztl::Expr>();
        e->node = std::move(node);
        e->line = line;
        e->col = col;
        return e;
    }

    template <typename T>
    ztl::StmtPtr make_stmt(T node, int line, int col) {
        auto s = std::make_shared<ztl::Stmt>();
        s->node = std::move(node);
        s->line = line;
        s->col = col;
        return s;
    }
}

namespace ztl {
    Parser::Parser(std::vector<Token> tokens) : tokens_(std::move(tokens)) {}

    const Token& Parser::peek(int offset) const {
        std::size_t i = pos_ + static_cast<std::size_t>(offset);
        if (i >= tokens_.size()) return tokens_.back();
        return tokens_[i];
    }

    const Token& Parser::advance() {
        const Token& t = tokens_[pos_];
        if (pos_ + 1 < tokens_.size()) pos_++;
        return t;
    }

    bool Parser::check(TokenType t) const { return peek().type == t; }

    bool Parser::match(TokenType t) {
        if (check(t)) { advance(); return true; }
        return false;
    }

    const Token& Parser::expect(TokenType t, const std::string& what) {
        if (!check(t)) {
            const Token& tk = peek();
            throw ParseError("expected " + what + ", got '" + tk.text + "'", tk.line, tk.col);
        }
        return advance();
    }

    Program Parser::parse_program() {
        Program p;
        while (!check(TokenType::END_OF_FILE)) {
            p.statements.push_back(parse_statement());
        }
        return p;
    }

    StmtPtr Parser::parse_statement() {
        if (check(TokenType::INCLUDE_KW)) return parse_include();
        if (check(TokenType::IF_KW))      return parse_if();
        if (check(TokenType::RETURN_KW))  return parse_return();

        // Assignment: IDENT '=' expr ';'
        if (check(TokenType::IDENT) && peek(1).type == TokenType::ASSIGN) {
            const Token& id = advance();
            advance();  // '='
            ExprPtr value = parse_expression();
            match(TokenType::SEMICOLON);
            AssignStmt a;
            a.target_name = id.text;
            a.value = value;
            return make_stmt(std::move(a), id.line, id.col);
        }

        // Otherwise: expression statement
        int line = peek().line, col = peek().col;
        ExprPtr e = parse_expression();
        match(TokenType::SEMICOLON);
        ExprStmt es;
        es.expr = e;
        return make_stmt(std::move(es), line, col);
    }

    StmtPtr Parser::parse_include() {
        const Token& kw = advance();  // 'include'
        expect(TokenType::LPAREN, "'(' after include");
        const Token& s = expect(TokenType::STRING, "module name string");
        expect(TokenType::RPAREN, "')' after include argument");
        match(TokenType::SEMICOLON);
        IncludeStmt inc;
        inc.module_name = s.text;
        return make_stmt(std::move(inc), kw.line, kw.col);
    }

    StmtPtr Parser::parse_if() {
        const Token& kw = advance();  // 'if'
        expect(TokenType::LPAREN, "'(' after if");
        ExprPtr cond = parse_expression();
        expect(TokenType::RPAREN, "')' after if condition");

        IfStmt ifs;
        ifs.condition = cond;
        ifs.then_branch = parse_block();

        if (match(TokenType::ELSE_KW)) {
            if (check(TokenType::IF_KW)) {
                ifs.else_branch.push_back(parse_if());
            } else {
                ifs.else_branch = parse_block();
            }
        }
        return make_stmt(std::move(ifs), kw.line, kw.col);
    }

    StmtPtr Parser::parse_return() {
        const Token& kw = advance();  // 'return'
        ReturnStmt r;
        if (!check(TokenType::SEMICOLON) && !check(TokenType::RBRACE) && !check(TokenType::END_OF_FILE)) {
            r.value = parse_expression();
        }
        match(TokenType::SEMICOLON);
        return make_stmt(std::move(r), kw.line, kw.col);
    }

    std::vector<StmtPtr> Parser::parse_block() {
        expect(TokenType::LBRACE, "'{'");
        std::vector<StmtPtr> stmts;
        while (!check(TokenType::RBRACE) && !check(TokenType::END_OF_FILE)) {
            stmts.push_back(parse_statement());
        }
        expect(TokenType::RBRACE, "'}'");
        return stmts;
    }

    // Expressions (precedence low → high):
    //   or       ->  and ('||' and)*
    //   and      ->  equality ('&&' equality)*
    //   equality ->  comparison (('=='|'!=') comparison)*
    //   compare  ->  additive (('<'|'>'|'<='|'>=') additive)*
    //   additive ->  unary (('+'|'-') unary)*
    //   unary    ->  ('!'|'-') unary | postfix
    //   postfix  ->  primary ( '.' IDENT | '(' args ')' | trailing-block )*
    //   primary  ->  NUMBER | STRING | true | false | null | IDENT [ '::' IDENT ] | '(' expr ')'

    ExprPtr Parser::parse_expression() { return parse_or(); }

    ExprPtr Parser::parse_or() {
        ExprPtr lhs = parse_and();
        while (check(TokenType::OR)) {
            const Token& op = advance();
            ExprPtr rhs = parse_and();
            BinaryOp b; b.op = op.text; b.lhs = lhs; b.rhs = rhs;
            lhs = make_expr(std::move(b), op.line, op.col);
        }
        return lhs;
    }

    ExprPtr Parser::parse_and() {
        ExprPtr lhs = parse_equality();
        while (check(TokenType::AND)) {
            const Token& op = advance();
            ExprPtr rhs = parse_equality();
            BinaryOp b; b.op = op.text; b.lhs = lhs; b.rhs = rhs;
            lhs = make_expr(std::move(b), op.line, op.col);
        }
        return lhs;
    }

    ExprPtr Parser::parse_equality() {
        ExprPtr lhs = parse_comparison();
        while (check(TokenType::EQ) || check(TokenType::NEQ)) {
            const Token& op = advance();
            ExprPtr rhs = parse_comparison();
            BinaryOp b; b.op = op.text; b.lhs = lhs; b.rhs = rhs;
            lhs = make_expr(std::move(b), op.line, op.col);
        }
        return lhs;
    }

    ExprPtr Parser::parse_comparison() {
        ExprPtr lhs = parse_additive();
        while (check(TokenType::LT) || check(TokenType::GT) || check(TokenType::LTE) || check(TokenType::GTE)) {
            const Token& op = advance();
            ExprPtr rhs = parse_additive();
            BinaryOp b; b.op = op.text; b.lhs = lhs; b.rhs = rhs;
            lhs = make_expr(std::move(b), op.line, op.col);
        }
        return lhs;
    }

    ExprPtr Parser::parse_additive() {
        ExprPtr lhs = parse_unary();
        while (check(TokenType::PLUS) || check(TokenType::MINUS)) {
            const Token& op = advance();
            ExprPtr rhs = parse_unary();
            BinaryOp b; b.op = op.text; b.lhs = lhs; b.rhs = rhs;
            lhs = make_expr(std::move(b), op.line, op.col);
        }
        return lhs;
    }

    ExprPtr Parser::parse_unary() {
        if (check(TokenType::BANG) || check(TokenType::MINUS)) {
            const Token& op = advance();
            ExprPtr operand = parse_unary();
            UnaryOp u; u.op = op.text; u.operand = operand;
            return make_expr(std::move(u), op.line, op.col);
        }
        return parse_postfix();
    }

    std::vector<CallArg> Parser::parse_call_args() {
        std::vector<CallArg> args;
        expect(TokenType::LPAREN, "'('");
        while (!check(TokenType::RPAREN) && !check(TokenType::END_OF_FILE)) {
            CallArg a;
            // Named argument?  IDENT ':' expr
            if (check(TokenType::IDENT) && peek(1).type == TokenType::COLON) {
                a.name = advance().text;
                advance();  // ':'
            }
            a.value = parse_expression();
            args.push_back(std::move(a));
            if (!match(TokenType::COMMA)) break;
        }
        expect(TokenType::RPAREN, "')'");
        return args;
    }

    ExprPtr Parser::parse_postfix() {
        ExprPtr node = parse_primary();
        while (true) {
            if (check(TokenType::DOT)) {
                const Token& dot = advance();
                const Token& name = expect(TokenType::IDENT, "member name after '.'");
                MemberAccess m;
                m.object = node;
                m.member = name.text;
                node = make_expr(std::move(m), dot.line, dot.col);
            } else if (check(TokenType::LPAREN)) {
                int line = peek().line, col = peek().col;
                Call c;
                c.callee = node;
                c.args = parse_call_args();
                // trailing block:  ident.member { ... }
                if (check(TokenType::LBRACE)) {
                    c.has_block = true;
                    c.trailing_block = parse_block();
                }
                node = make_expr(std::move(c), line, col);
            } else if (check(TokenType::LBRACE)) {
                // implicit-call trailing block:  plugin.run { ... }
                int line = peek().line, col = peek().col;
                Call c;
                c.callee = node;
                c.has_block = true;
                c.trailing_block = parse_block();
                node = make_expr(std::move(c), line, col);
            } else {
                break;
            }
        }
        return node;
    }

    ExprPtr Parser::parse_primary() {
        const Token& t = peek();

        if (check(TokenType::NUMBER)) {
            advance();
            LiteralNumber n; n.value = std::stod(t.text);
            return make_expr(std::move(n), t.line, t.col);
        }
        if (check(TokenType::STRING)) {
            advance();
            LiteralString s; s.value = t.text;
            return make_expr(std::move(s), t.line, t.col);
        }
        if (check(TokenType::TRUE_KW))  { advance(); LiteralBool b{true};  return make_expr(std::move(b), t.line, t.col); }
        if (check(TokenType::FALSE_KW)) { advance(); LiteralBool b{false}; return make_expr(std::move(b), t.line, t.col); }
        if (check(TokenType::NULL_KW))  { advance(); return make_expr(LiteralNull{}, t.line, t.col); }

        if (check(TokenType::IDENT)) {
            const Token& id = advance();
            if (check(TokenType::SCOPE)) {
                advance();
                const Token& name = expect(TokenType::IDENT, "name after '::'");
                ScopedAccess s;
                s.scope = id.text;
                s.name = name.text;
                return make_expr(std::move(s), id.line, id.col);
            }
            Identifier i; i.name = id.text;
            return make_expr(std::move(i), id.line, id.col);
        }

        if (check(TokenType::LPAREN)) {
            advance();
            ExprPtr e = parse_expression();
            expect(TokenType::RPAREN, "')'");
            return e;
        }

        throw ParseError("unexpected token '" + t.text + "'", t.line, t.col);
    }
}
