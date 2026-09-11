// parser.cpp

#include "ztl/parser.hpp"
#include "logging/logging.hpp"

#include <cctype>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace {
    struct Cursor {
        const std::string& text;
        std::size_t pos = 0;
        int line = 1;

        Cursor(const std::string& t) : text(t) {}

        bool eof() const {
            return pos >= text.size();
        }

        char peek() const {
            return eof() ? '\0' : text[pos];
        }

        char advance() {
            char c = text[pos++];
            if (c == '\n') line++;
            return c;
        }

        void skip_whitespace_and_comments() {
            while (!eof()) {
                char c = peek();

                if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
                    advance();
                    continue;
                }

                if (c == '#') {
                    while (!eof() && peek() != '\n') advance();
                    continue;
                }

                break;
            }
        }

        std::string read_identifier() {
            std::string out;

            while (!eof()) {
                char c = peek();
                if (std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-') {
                    out += c;
                    advance();
                } else {
                    break;
                }
            }

            return out;
        }

        std::string read_operator() {
            std::string out;

            while (!eof()) {
                char c = peek();
                if (c == '=' || c == '!' || c == '<' || c == '>') {
                    out += c;
                    advance();
                } else {
                    break;
                }
            }

            return out;
        }

        std::optional<std::string> read_string() {
            if (peek() != '"') return std::nullopt;
            advance();

            std::string out;

            while (!eof() && peek() != '"') {
                char c = advance();

                if (c == '\\' && !eof()) {
                    char next = advance();

                    if (next == 'x' && pos + 1 < text.size()) {
                        auto hex_value = [](char h) -> int {
                            if (h >= '0' && h <= '9') return h - '0';
                            if (h >= 'a' && h <= 'f') return 10 + (h - 'a');
                            if (h >= 'A' && h <= 'F') return 10 + (h - 'A');
                            return -1;
                        };

                        int hi = hex_value(text[pos]);
                        int lo = hex_value(text[pos + 1]);

                        if (hi >= 0 && lo >= 0) {
                            advance();
                            advance();
                            out += static_cast<char>((hi << 4) | lo);
                            continue;
                        }
                    }

                    switch (next) {
                        case 'n':  out += '\n'; break;
                        case 'r':  out += '\r'; break;
                        case 't':  out += '\t'; break;
                        case '"':  out += '"';  break;
                        case '\\': out += '\\'; break;
                        case '0':  out += '\0'; break;
                        default:   out += next; break;
                    }
                } else {
                    out += c;
                }
            }

            if (eof()) return std::nullopt;
            advance();

            return out;
        }
    };

    std::optional<core::Severity> parse_severity(const std::string& s) {
        if (s == "INFO")     return core::Severity::INFO;
        if (s == "LOW")      return core::Severity::LOW;
        if (s == "MEDIUM")   return core::Severity::MEDIUM;
        if (s == "HIGH")     return core::Severity::HIGH;
        if (s == "CRITICAL") return core::Severity::CRITICAL;
        return std::nullopt;
    }

    std::optional<ztl::Require> parse_require(Cursor& c, const std::string& source_name) {
        c.skip_whitespace_and_comments();

        std::string field = c.read_identifier();
        if (field.empty()) {
            logging::error(source_name + ":" + std::to_string(c.line) + " expected field name after 'require'");
            return std::nullopt;
        }

        c.skip_whitespace_and_comments();

        std::string op;
        char first = c.peek();

        if (first == '=' || first == '!' || first == '<' || first == '>') {
            op = c.read_operator();
        } else {
            op = c.read_identifier();
        }

        if (op.empty()) {
            logging::error(source_name + ":" + std::to_string(c.line) + " expected operator after '" + field + "'");
            return std::nullopt;
        }

        c.skip_whitespace_and_comments();

        auto value = c.read_string();
        if (!value) {
            logging::error(source_name + ":" + std::to_string(c.line) + " expected quoted value after '" + op + "'");
            return std::nullopt;
        }

        return ztl::Require{ field, op, *value };
    }

    std::optional<ztl::Probe> parse_probe(Cursor& c, const std::string& source_name) {
        c.skip_whitespace_and_comments();

        if (c.peek() != '{') {
            logging::error(source_name + ":" + std::to_string(c.line) + " expected '{' after 'probe'");
            return std::nullopt;
        }
        c.advance();

        ztl::Probe probe;

        while (true) {
            c.skip_whitespace_and_comments();
            if (c.eof()) {
                logging::error(source_name + ": unexpected end of file inside probe block");
                return std::nullopt;
            }
            if (c.peek() == '}') {
                c.advance();
                return probe;
            }

            std::string key = c.read_identifier();
            c.skip_whitespace_and_comments();

            if (key == "capture") {
                auto pattern = c.read_string();
                if (!pattern) {
                    logging::error(source_name + ":" + std::to_string(c.line) + " expected quoted regex after 'capture'");
                    return std::nullopt;
                }

                c.skip_whitespace_and_comments();
                std::string as_kw = c.read_identifier();

                if (as_kw != "as") {
                    logging::error(source_name + ":" + std::to_string(c.line) + " expected 'as' after capture pattern");
                    return std::nullopt;
                }

                c.skip_whitespace_and_comments();
                std::string varname = c.read_identifier();

                if (varname.empty()) {
                    logging::error(source_name + ":" + std::to_string(c.line) + " expected variable name after 'as'");
                    return std::nullopt;
                }

                probe.captures.push_back({ *pattern, varname });
                continue;
            }

            if (key == "require") {
                auto req = parse_require(c, source_name);
                if (!req) return std::nullopt;
                probe.post_requires.push_back(*req);
                continue;
            }

            auto value = c.read_string();
            if (!value) {
                logging::error(source_name + ":" + std::to_string(c.line) + " expected quoted string after '" + key + "'");
                return std::nullopt;
            }

            if (key == "send")             probe.send = *value;
            else if (key == "expect")      probe.expect.push_back(*value);
            else if (key == "expect_not")  probe.expect_not.push_back(*value);
            else if (key == "when")        probe.when = *value;
            else {
                logging::warn(source_name + ":" + std::to_string(c.line) + " unknown probe key '" + key + "'");
            }
        }
    }
}

namespace ztl {
    std::optional<Plugin> parse_plugin(const std::string& source, const std::string& source_name) {
        Cursor c(source);

        c.skip_whitespace_and_comments();
        std::string kw = c.read_identifier();

        if (kw != "plugin") {
            logging::error(source_name + ":" + std::to_string(c.line) + " expected 'plugin' keyword, got '" + kw + "'");
            return std::nullopt;
        }

        c.skip_whitespace_and_comments();
        std::string name = c.read_identifier();

        if (name.empty()) {
            logging::error(source_name + ":" + std::to_string(c.line) + " expected plugin name");
            return std::nullopt;
        }

        c.skip_whitespace_and_comments();
        if (c.peek() != '{') {
            logging::error(source_name + ":" + std::to_string(c.line) + " expected '{' after plugin name");
            return std::nullopt;
        }
        c.advance();

        Plugin plugin;
        plugin.name = name;

        while (true) {
            c.skip_whitespace_and_comments();
            if (c.eof()) {
                logging::error(source_name + ": unexpected end of file inside plugin block");
                return std::nullopt;
            }
            if (c.peek() == '}') {
                c.advance();
                break;
            }

            std::string key = c.read_identifier();

            if (key == "probe") {
                auto probe = parse_probe(c, source_name);
                if (!probe) return std::nullopt;
                plugin.probes.push_back(*probe);
                continue;
            }

            if (key == "require") {
                auto req = parse_require(c, source_name);
                if (!req) return std::nullopt;
                plugin.pre_requires.push_back(*req);
                continue;
            }

            c.skip_whitespace_and_comments();

            if (key == "severity") {
                std::string sev_str = c.read_identifier();
                auto sev = parse_severity(sev_str);

                if (!sev) {
                    logging::error(source_name + ":" + std::to_string(c.line) + " invalid severity '" + sev_str + "'");
                    return std::nullopt;
                }

                plugin.severity = *sev;
                continue;
            }

            if (key == "protocol") {
                std::string proto_str = c.read_identifier();

                if (proto_str == "tcp") {
                    plugin.protocol = core::Protocol::TCP;
                } else if (proto_str == "udp") {
                    plugin.protocol = core::Protocol::UDP;
                } else {
                    logging::error(source_name + ":" + std::to_string(c.line) + " invalid protocol '" + proto_str + "' (expected tcp or udp)");
                    return std::nullopt;
                }

                continue;
            }

            if (key == "match_mode") {
                std::string mode_str = c.read_identifier();

                if (mode_str == "all") {
                    plugin.match_mode = ztl::MatchMode::ALL;
                } else if (mode_str == "any") {
                    plugin.match_mode = ztl::MatchMode::ANY;
                } else {
                    logging::error(source_name + ":" + std::to_string(c.line) + " invalid match_mode '" + mode_str + "' (expected all or any)");
                    return std::nullopt;
                }

                continue;
            }

            auto value = c.read_string();

            if (!value) {
                logging::error(source_name + ":" + std::to_string(c.line) + " expected quoted string or identifier after '" + key + "'");
                return std::nullopt;
            }

            if (key == "service")          plugin.service     = *value;
            else if (key == "title")       plugin.title       = *value;
            else if (key == "description") plugin.description = *value;
            else {
                logging::warn(source_name + ":" + std::to_string(c.line) + " unknown plugin key '" + key + "'");
            }
        }

        return plugin;
    }

    std::vector<Plugin> load_plugins_from_dir(const std::string& dir_path) {
        std::vector<Plugin> out;

        std::error_code ec;
        if (!std::filesystem::exists(dir_path, ec) || !std::filesystem::is_directory(dir_path, ec)) {
            logging::error("Plugin directory not found: " + dir_path);
            return out;
        }

        for (const auto& entry : std::filesystem::directory_iterator(dir_path, ec)) {
            if (!entry.is_regular_file()) continue;
            if (entry.path().extension() != ".ztl") continue;

            std::ifstream file(entry.path());
            if (!file.is_open()) {
                logging::error("Cannot open plugin file: " + entry.path().string());
                continue;
            }

            std::ostringstream buffer;
            buffer << file.rdbuf();

            auto plugin = parse_plugin(buffer.str(), entry.path().filename().string());

            if (plugin) {
                out.push_back(*plugin);
            }
        }

        logging::info("Loaded " + std::to_string(out.size()) + " ZTL plugins from " + dir_path);
        return out;
    }
}
