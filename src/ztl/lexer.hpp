// lexer.hpp

#pragma once

#include "ztl/token.hpp"

#include <stdexcept>
#include <string>
#include <vector>

namespace ztl {
    class LexError : public std::runtime_error {
    public:
        LexError(const std::string& msg, int line, int col)
            : std::runtime_error("lex error at " + std::to_string(line) + ":" + std::to_string(col) + ": " + msg) {}
    };

    class Lexer {
    public:
        explicit Lexer(std::string src);
        std::vector<Token> tokenize();

    private:
        std::string src_;
        std::size_t pos_ = 0;
        int line_ = 1;
        int col_ = 1;

        char peek(int offset = 0) const;
        char advance();
        bool match(char c);
        void skip_ws_and_comments();
        Token read_string();
        Token read_number();
        Token read_ident_or_keyword();
        Token make(TokenType t, const std::string& text, int line, int col);
    };
}
