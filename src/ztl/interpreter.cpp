// interpreter.cpp

#include "ztl/interpreter.hpp"
#include "transport/udp.hpp"
#include "logging/logging.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <functional>
#include <map>
#include <regex>
#include <string>
#include <vector>

namespace {
    std::string expand_variables(
        const std::string& source,
        const std::map<std::string, std::string>& variables
    ) {
        std::string out;
        std::size_t i = 0;

        while (i < source.size()) {
            if (i + 1 < source.size() && source[i] == '$' && source[i + 1] == '{') {
                std::size_t end = source.find('}', i + 2);

                if (end != std::string::npos) {
                    std::string name = source.substr(i + 2, end - i - 2);
                    auto it = variables.find(name);

                    if (it != variables.end()) {
                        out += it->second;
                    }

                    i = end + 1;
                    continue;
                }
            }

            out += source[i];
            i++;
        }

        return out;
    }

    bool safe_regex_search(const std::string& subject, const std::string& pattern, const std::string& plugin_name) {
        try {
            std::regex re(pattern);
            return std::regex_search(subject, re);
        } catch (const std::regex_error& e) {
            logging::error(
                std::string("Invalid regex in plugin '") + plugin_name +
                "': " + pattern + " (" + e.what() + ")"
            );
            return false;
        }
    }

    std::vector<int> version_numeric_parts(const std::string& v) {
        std::vector<int> parts;
        std::string current;

        for (char c : v) {
            if (std::isdigit(static_cast<unsigned char>(c))) {
                current += c;
            } else {
                if (!current.empty()) {
                    parts.push_back(std::stoi(current));
                    current.clear();
                }
            }
        }

        if (!current.empty()) parts.push_back(std::stoi(current));
        return parts;
    }

    int compare_versions(const std::string& a, const std::string& b) {
        std::vector<int> ap = version_numeric_parts(a);
        std::vector<int> bp = version_numeric_parts(b);

        std::size_t n = std::max(ap.size(), bp.size());
        for (std::size_t i = 0; i < n; i++) {
            int av = (i < ap.size()) ? ap[i] : 0;
            int bv = (i < bp.size()) ? bp[i] : 0;
            if (av != bv) return (av < bv) ? -1 : 1;
        }

        return 0;
    }

    bool evaluate_require(
        const ztl::Require& req,
        const std::map<std::string, std::string>& variables,
        const std::string& plugin_name
    ) {
        auto it = variables.find(req.field);
        std::string actual = (it != variables.end()) ? it->second : "";

        const std::string& op = req.op;
        const std::string& expected = req.value;

        if (op == "==")       return actual == expected;
        if (op == "!=")       return actual != expected;
        if (op == "contains") return actual.find(expected) != std::string::npos;

        if (op == "matches") {
            return safe_regex_search(actual, expected, plugin_name);
        }

        if (op == "<" || op == "<=" || op == ">" || op == ">=") {
            int cmp = compare_versions(actual, expected);
            if (op == "<")  return cmp <  0;
            if (op == "<=") return cmp <= 0;
            if (op == ">")  return cmp >  0;
            if (op == ">=") return cmp >= 0;
        }

        logging::warn("Unknown require operator in plugin '" + plugin_name + "': " + op);
        return false;
    }

    int run_probes(
        const ztl::Plugin& plugin,
        std::function<bool(const std::string&)> do_send,
        std::function<std::string()> do_receive,
        std::string& last_response,
        std::map<std::string, std::string>& variables
    ) {
        int matched = 0;

        for (const ztl::Probe& step : plugin.probes) {
            if (!step.when.empty()) {
                if (!safe_regex_search(last_response, step.when, plugin.name)) {
                    continue;
                }
            }

            std::string response;

            if (step.send.empty()) {
                response = last_response;
            } else {
                std::string send_data = expand_variables(step.send, variables);

                if (!do_send(send_data)) {
                    if (plugin.match_mode == ztl::MatchMode::ALL) return -1;
                    continue;
                }

                response = do_receive();
                last_response = response;

                if (response.empty()) {
                    if (plugin.match_mode == ztl::MatchMode::ALL) return -1;
                    continue;
                }
            }

            bool this_matched = true;

            for (const std::string& pat : step.expect) {
                if (!safe_regex_search(response, pat, plugin.name)) {
                    this_matched = false;
                    break;
                }
            }

            if (this_matched) {
                for (const std::string& pat : step.expect_not) {
                    if (safe_regex_search(response, pat, plugin.name)) {
                        this_matched = false;
                        break;
                    }
                }
            }

            if (!this_matched) {
                if (plugin.match_mode == ztl::MatchMode::ALL) return -1;
                continue;
            }

            for (const ztl::Capture& cap : step.captures) {
                try {
                    std::regex cap_re(cap.pattern);
                    std::smatch m;
                    if (std::regex_search(response, m, cap_re) && m.size() > 1) {
                        variables[cap.name] = m[1].str();
                    }
                } catch (const std::regex_error& e) {
                    logging::error(
                        std::string("Invalid capture regex in plugin '") + plugin.name +
                        "': " + cap.pattern + " (" + e.what() + ")"
                    );
                }
            }

            bool post_ok = true;
            for (const ztl::Require& req : step.post_requires) {
                if (!evaluate_require(req, variables, plugin.name)) {
                    post_ok = false;
                    break;
                }
            }

            if (!post_ok) {
                if (plugin.match_mode == ztl::MatchMode::ALL) return -1;
                continue;
            }

            matched++;
        }

        return matched;
    }
}

namespace ztl {
    std::optional<core::Finding> execute(
        const Plugin& plugin,
        const core::Port& port,
        const std::string& target_ip,
        core::KnowledgeBase& kb,
        int timeout_ms
    ) {
        if (!plugin.service.empty() && plugin.service != port.service) {
            return std::nullopt;
        }

        std::map<std::string, std::string> variables;
        variables["service"] = port.service;
        variables["product"] = port.product;
        variables["version"] = port.version;
        variables["distro"]  = port.distro;
        variables["port"]    = std::to_string(port.number);

        for (const auto& [key, value] : kb.snapshot()) {
            variables[key] = value;
        }

        for (const Require& req : plugin.pre_requires) {
            if (!evaluate_require(req, variables, plugin.name)) {
                return std::nullopt;
            }
        }

        std::string last_response;
        int matched = 0;

        if (plugin.protocol == core::Protocol::TCP) {
            transport::Tcp tcp;
            core::Port probe_state = tcp.connect(target_ip, port.number, timeout_ms);

            if (probe_state.state != core::PortState::OPEN) {
                return std::nullopt;
            }

            last_response = tcp.receive(500);

            matched = run_probes(
                plugin,
                [&](const std::string& s) { return tcp.send(s); },
                [&]() { return tcp.receive(timeout_ms); },
                last_response,
                variables
            );
        } else if (plugin.protocol == core::Protocol::UDP) {
            transport::Udp udp;

            matched = run_probes(
                plugin,
                [&](const std::string& s) {
                    std::vector<std::uint8_t> payload(s.begin(), s.end());
                    return udp.send(target_ip, port.number, payload);
                },
                [&]() { return udp.receive(timeout_ms); },
                last_response,
                variables
            );
        } else {
            return std::nullopt;
        }

        if (matched <= 0) {
            return std::nullopt;
        }

        core::Finding finding;
        finding.plugin_name = plugin.name;
        finding.title = expand_variables(plugin.title, variables);
        finding.description = expand_variables(plugin.description, variables);
        finding.severity = plugin.severity;
        finding.confidence = core::Confidence::VERIFIED;
        finding.port_number = port.number;
        finding.service = port.service;
        finding.product = port.product;
        finding.version = port.version;

        return finding;
    }
}
