// token.hpp

#pragma once

#include <string>

namespace ztl {
    enum class TokenType {
        // Literals
        NUMBER,
        STRING,
        IDENT,
        TRUE_KW,
        FALSE_KW,
        NULL_KW,

        // Keywords
        INCLUDE_KW,
        IF_KW,
        ELSE_KW,
        RETURN_KW,

        // Punctuation
        LPAREN,     // (
        RPAREN,     // )
        LBRACE,     // {
        RBRACE,     // }
        LBRACKET,   // [
        RBRACKET,   // ]
        COMMA,      // ,
        COLON,      // :
        SCOPE,      // ::
        DOT,        // .
        SEMICOLON,  // ;
        ASSIGN,     // =

        // Operators
        EQ,     // ==
        NEQ,    // !=
        LT,     // <
        GT,     // >
        LTE,    // <=
        GTE,    // >=
        BANG,   // !
        AND,    // &&
        OR,     // ||
        PLUS,   // +
        MINUS,  // -

        END_OF_FILE
    };

    struct Token {
        TokenType type;
        std::string text;
        int line = 0;
        int col = 0;
    };
}
