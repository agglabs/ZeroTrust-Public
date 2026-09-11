// json.cpp

#include "util/json.hpp"

#include <cctype>
#include <fstream>
#include <sstream>

namespace {
    struct Parser {
        std::string text;
        std::size_t pos = 0;

        Parser(std::string t) : text(std::move(t)) {}

        bool eof() const { return pos >= text.size(); }
        char peek() const { return eof() ? '\0' : text[pos]; }
        char advance() { return text[pos++]; }

        void skip_ws() {
            while (!eof()) {
                char c = peek();
                if (c == ' ' || c == '\t' || c == '\r' || c == '\n') advance();
                else break;
            }
        }

        bool consume(char c) {
            skip_ws();
            if (peek() != c) return false;
            advance();
            return true;
        }

        std::shared_ptr<util::JsonValue> parse_value() {
            skip_ws();
            if (eof()) return nullptr;

            char c = peek();

            if (c == '"')                                            return parse_string();
            if (c == '{')                                            return parse_object();
            if (c == '[')                                            return parse_array();
            if (c == 't' || c == 'f')                                return parse_bool();
            if (c == 'n')                                            return parse_null();
            if (c == '-' || std::isdigit(static_cast<unsigned char>(c))) return parse_number();

            return nullptr;
        }

        std::shared_ptr<util::JsonValue> parse_string() {
            if (!consume('"')) return nullptr;

            std::string out;

            while (!eof() && peek() != '"') {
                char c = advance();

                if (c == '\\' && !eof()) {
                    char next = advance();
                    switch (next) {
                        case 'n':  out += '\n'; break;
                        case 'r':  out += '\r'; break;
                        case 't':  out += '\t'; break;
                        case 'b':  out += '\b'; break;
                        case 'f':  out += '\f'; break;
                        case '"':  out += '"';  break;
                        case '\\': out += '\\'; break;
                        case '/':  out += '/';  break;
                        case 'u':
                            if (pos + 3 < text.size()) {
                                int code = 0;
                                for (int i = 0; i < 4; i++) {
                                    char h = advance();
                                    code <<= 4;
                                    if      (h >= '0' && h <= '9') code |= h - '0';
                                    else if (h >= 'a' && h <= 'f') code |= 10 + (h - 'a');
                                    else if (h >= 'A' && h <= 'F') code |= 10 + (h - 'A');
                                }
                                if (code < 0x80) {
                                    out += static_cast<char>(code);
                                } else if (code < 0x800) {
                                    out += static_cast<char>(0xC0 | ((code >> 6) & 0x1F));
                                    out += static_cast<char>(0x80 | (code & 0x3F));
                                } else {
                                    out += static_cast<char>(0xE0 | ((code >> 12) & 0x0F));
                                    out += static_cast<char>(0x80 | ((code >> 6)  & 0x3F));
                                    out += static_cast<char>(0x80 | (code & 0x3F));
                                }
                            }
                            break;
                        default: out += next; break;
                    }
                } else {
                    out += c;
                }
            }

            if (!consume('"')) return nullptr;

            auto v = std::make_shared<util::JsonValue>();
            v->v = out;
            return v;
        }

        std::shared_ptr<util::JsonValue> parse_number() {
            std::string buf;
            while (!eof()) {
                char c = peek();
                if (std::isdigit(static_cast<unsigned char>(c)) ||
                    c == '-' || c == '.' || c == 'e' || c == 'E' || c == '+')
                {
                    buf += advance();
                } else break;
            }
            auto v = std::make_shared<util::JsonValue>();
            v->v = std::stod(buf);
            return v;
        }

        std::shared_ptr<util::JsonValue> parse_bool() {
            auto v = std::make_shared<util::JsonValue>();
            if (text.compare(pos, 4, "true") == 0) {
                pos += 4;
                v->v = true;
                return v;
            }
            if (text.compare(pos, 5, "false") == 0) {
                pos += 5;
                v->v = false;
                return v;
            }
            return nullptr;
        }

        std::shared_ptr<util::JsonValue> parse_null() {
            if (text.compare(pos, 4, "null") == 0) {
                pos += 4;
                return std::make_shared<util::JsonValue>();
            }
            return nullptr;
        }

        std::shared_ptr<util::JsonValue> parse_array() {
            if (!consume('[')) return nullptr;
            util::JsonArray arr;
            skip_ws();
            if (peek() == ']') {
                advance();
                auto v = std::make_shared<util::JsonValue>();
                v->v = arr;
                return v;
            }
            while (true) {
                auto item = parse_value();
                if (!item) return nullptr;
                arr.push_back(item);
                skip_ws();
                if (peek() == ',') { advance(); continue; }
                if (peek() == ']') { advance(); break; }
                return nullptr;
            }
            auto v = std::make_shared<util::JsonValue>();
            v->v = arr;
            return v;
        }

        std::shared_ptr<util::JsonValue> parse_object() {
            if (!consume('{')) return nullptr;
            util::JsonObject obj;
            skip_ws();
            if (peek() == '}') {
                advance();
                auto v = std::make_shared<util::JsonValue>();
                v->v = obj;
                return v;
            }
            while (true) {
                skip_ws();
                auto key = parse_string();
                if (!key || !key->is_string()) return nullptr;
                skip_ws();
                if (!consume(':')) return nullptr;
                auto value = parse_value();
                if (!value) return nullptr;
                obj[key->as_string()] = value;
                skip_ws();
                if (peek() == ',') { advance(); continue; }
                if (peek() == '}') { advance(); break; }
                return nullptr;
            }
            auto v = std::make_shared<util::JsonValue>();
            v->v = obj;
            return v;
        }
    };
}

namespace util {
    std::shared_ptr<JsonValue> parse_json(const std::string& text) {
        Parser p(text);
        return p.parse_value();
    }

    std::optional<std::shared_ptr<JsonValue>> parse_json_file(const std::string& path) {
        std::ifstream f(path);
        if (!f.is_open()) return std::nullopt;

        std::ostringstream buf;
        buf << f.rdbuf();

        auto value = parse_json(buf.str());
        if (!value) return std::nullopt;
        return value;
    }

    std::string obj_get_string(const JsonObject& o, const std::string& key) {
        auto it = o.find(key);
        if (it == o.end() || !it->second->is_string()) return "";
        return it->second->as_string();
    }

    int obj_get_int(const JsonObject& o, const std::string& key) {
        auto it = o.find(key);
        if (it == o.end() || !it->second->is_number()) return 0;
        return static_cast<int>(it->second->as_number());
    }

    bool obj_get_bool(const JsonObject& o, const std::string& key) {
        auto it = o.find(key);
        if (it == o.end() || !it->second->is_bool()) return false;
        return it->second->as_bool();
    }
}
