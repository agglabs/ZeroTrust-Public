// lexer.cpp

#include "ztl/lexer.hpp"

#include <cctype>
#include <unordered_map>

namespace ztl {
    Lexer::Lexer(std::string src) : src_(std::move(src)) {}

    char Lexer::peek(int offset) const {
        std::size_t i = pos_ + static_cast<std::size_t>(offset);
        if (i >= src_.size()) return '\0';
        return src_[i];
    }

    char Lexer::advance() {
        char c = src_[pos_++];
        if (c == '\n') { line_++; col_ = 1; } else { col_++; }
        return c;
    }

    bool Lexer::match(char c) {
        if (peek() == c) { advance(); return true; }
        return false;
    }

    void Lexer::skip_ws_and_comments() {
        while (pos_ < src_.size()) {
            char c = peek();
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
                advance();
            } else if (c == '/' && peek(1) == '/') {
                while (pos_ < src_.size() && peek() != '\n') advance();
            } else if (c == '/' && peek(1) == '*') {
                advance(); advance();
                while (pos_ < src_.size() && !(peek() == '*' && peek(1) == '/')) advance();
                if (pos_ < src_.size()) { advance(); advance(); }
            } else if (c == '#') {
                while (pos_ < src_.size() && peek() != '\n') advance();
            } else {
                break;
            }
        }
    }

    Token Lexer::make(TokenType t, const std::string& text, int line, int col) {
        return Token{t, text, line, col};
    }

    Token Lexer::read_string() {
        int start_line = line_, start_col = col_;
        advance();  // consume opening quote
        std::string out;
        while (pos_ < src_.size() && peek() != '"') {
            char c = advance();
            if (c == '\\' && pos_ < src_.size()) {
                char esc = advance();
                switch (esc) {
                    case 'n':  out += '\n'; break;
                    case 't':  out += '\t'; break;
                    case 'r':  out += '\r'; break;
                    case '\\': out += '\\'; break;
                    case '"':  out += '"';  break;
                    case '0':  out += '\0'; break;
                    default:   out += esc;  break;
                }
            } else {
                out += c;
            }
        }
        if (pos_ >= src_.size()) throw LexError("unterminated string", start_line, start_col);
        advance();  // closing quote
        return make(TokenType::STRING, out, start_line, start_col);
    }

    Token Lexer::read_number() {
        int start_line = line_, start_col = col_;
        std::string out;
        while (std::isdigit(static_cast<unsigned char>(peek()))) out += advance();
        if (peek() == '.' && std::isdigit(static_cast<unsigned char>(peek(1)))) {
            out += advance();
            while (std::isdigit(static_cast<unsigned char>(peek()))) out += advance();
        }
        return make(TokenType::NUMBER, out, start_line, start_col);
    }

    Token Lexer::read_ident_or_keyword() {
        int start_line = line_, start_col = col_;
        std::string out;
        while (std::isalnum(static_cast<unsigned char>(peek())) || peek() == '_') out += advance();

        static const std::unordered_map<std::string, TokenType> keywords = {
            {"include", TokenType::INCLUDE_KW},
            {"if",      TokenType::IF_KW},
            {"else",    TokenType::ELSE_KW},
            {"return",  TokenType::RETURN_KW},
            {"true",    TokenType::TRUE_KW},
            {"false",   TokenType::FALSE_KW},
            {"null",    TokenType::NULL_KW},
        };
        auto it = keywords.find(out);
        if (it != keywords.end()) return make(it->second, out, start_line, start_col);
        return make(TokenType::IDENT, out, start_line, start_col);
    }

    std::vector<Token> Lexer::tokenize() {
        std::vector<Token> tokens;
        while (true) {
            skip_ws_and_comments();
            if (pos_ >= src_.size()) break;
            int l = line_, c = col_;
            char ch = peek();

            if (ch == '"') { tokens.push_back(read_string()); continue; }
            if (std::isdigit(static_cast<unsigned char>(ch))) { tokens.push_back(read_number()); continue; }
            if (std::isalpha(static_cast<unsigned char>(ch)) || ch == '_') { tokens.push_back(read_ident_or_keyword()); continue; }

            advance();
            switch (ch) {
                case '(': tokens.push_back(make(TokenType::LPAREN,    "(", l, c)); break;
                case ')': tokens.push_back(make(TokenType::RPAREN,    ")", l, c)); break;
                case '{': tokens.push_back(make(TokenType::LBRACE,    "{", l, c)); break;
                case '}': tokens.push_back(make(TokenType::RBRACE,    "}", l, c)); break;
                case '[': tokens.push_back(make(TokenType::LBRACKET,  "[", l, c)); break;
                case ']': tokens.push_back(make(TokenType::RBRACKET,  "]", l, c)); break;
                case ',': tokens.push_back(make(TokenType::COMMA,     ",", l, c)); break;
                case ';': tokens.push_back(make(TokenType::SEMICOLON, ";", l, c)); break;
                case '.': tokens.push_back(make(TokenType::DOT,       ".", l, c)); break;
                case '+': tokens.push_back(make(TokenType::PLUS,      "+", l, c)); break;
                case '-': tokens.push_back(make(TokenType::MINUS,     "-", l, c)); break;
                case ':':
                    if (match(':')) tokens.push_back(make(TokenType::SCOPE, "::", l, c));
                    else            tokens.push_back(make(TokenType::COLON, ":",  l, c));
                    break;
                case '=':
                    if (match('=')) tokens.push_back(make(TokenType::EQ,     "==", l, c));
                    else            tokens.push_back(make(TokenType::ASSIGN, "=",  l, c));
                    break;
                case '!':
                    if (match('=')) tokens.push_back(make(TokenType::NEQ,  "!=", l, c));
                    else            tokens.push_back(make(TokenType::BANG, "!",  l, c));
                    break;
                case '<':
                    if (match('=')) tokens.push_back(make(TokenType::LTE, "<=", l, c));
                    else            tokens.push_back(make(TokenType::LT,  "<",  l, c));
                    break;
                case '>':
                    if (match('=')) tokens.push_back(make(TokenType::GTE, ">=", l, c));
                    else            tokens.push_back(make(TokenType::GT,  ">",  l, c));
                    break;
                case '&':
                    if (match('&')) tokens.push_back(make(TokenType::AND, "&&", l, c));
                    else            throw LexError("expected &&", l, c);
                    break;
                case '|':
                    if (match('|')) tokens.push_back(make(TokenType::OR, "||", l, c));
                    else            throw LexError("expected ||", l, c);
                    break;
                default:
                    throw LexError(std::string("unexpected character: '") + ch + "'", l, c);
            }
        }
        tokens.push_back(make(TokenType::END_OF_FILE, "", line_, col_));
        return tokens;
    }
}
