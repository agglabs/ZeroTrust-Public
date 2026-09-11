// json_writer.cpp

#include "report/json_writer.hpp"
#include "logging/logging.hpp"

#include <chrono>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <sstream>

namespace {
    std::string escape(const std::string& s) {
        std::string out;
        out.reserve(s.size() + 8);

        for (char c : s) {
            switch (c) {
                case '"':  out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n";  break;
                case '\r': out += "\\r";  break;
                case '\t': out += "\\t";  break;
                case '\b': out += "\\b";  break;
                case '\f': out += "\\f";  break;
                default:
                    if (static_cast<unsigned char>(c) < 0x20) {
                        char buf[8];
                        std::snprintf(buf, sizeof(buf), "\\u%04x",
                                      static_cast<unsigned char>(c));
                        out += buf;
                    } else {
                        out += c;
                    }
            }
        }

        return out;
    }

    std::string quoted(const std::string& s) {
        return "\"" + escape(s) + "\"";
    }

    std::string indent(int level) {
        return std::string(level * 2, ' ');
    }

    std::string iso_utc_now() {
        auto now = std::chrono::system_clock::now();
        std::time_t t = std::chrono::system_clock::to_time_t(now);

        std::tm tm{};
        gmtime_r(&t, &tm);

        char buf[32];
        std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
        return buf;
    }

    std::string write_port(const core::Port& port, int level) {
        std::ostringstream ss;
        ss << indent(level) << "{\n";
        ss << indent(level + 1) << "\"number\": "   << port.number << ",\n";
        ss << indent(level + 1) << "\"protocol\": " << quoted(core::to_string(port.protocol)) << ",\n";
        ss << indent(level + 1) << "\"state\": "    << quoted(core::to_string(port.state))    << ",\n";
        ss << indent(level + 1) << "\"service\": "  << quoted(port.service) << ",\n";
        ss << indent(level + 1) << "\"product\": "  << quoted(port.product) << ",\n";
        ss << indent(level + 1) << "\"version\": "  << quoted(port.version) << ",\n";
        ss << indent(level + 1) << "\"distro\": "   << quoted(port.distro)  << ",\n";
        ss << indent(level + 1) << "\"tls\": "      << (port.tls ? "true" : "false") << "\n";
        ss << indent(level) << "}";
        return ss.str();
    }

    std::string write_finding(const core::Finding& f, int level) {
        std::ostringstream ss;
        ss << indent(level) << "{\n";
        ss << indent(level + 1) << "\"plugin_name\": " << quoted(f.plugin_name) << ",\n";
        ss << indent(level + 1) << "\"title\": "       << quoted(f.title)       << ",\n";
        ss << indent(level + 1) << "\"severity\": "    << quoted(core::to_string(f.severity))   << ",\n";
        ss << indent(level + 1) << "\"confidence\": "  << quoted(core::to_string(f.confidence)) << ",\n";
        ss << indent(level + 1) << "\"port_number\": " << f.port_number << ",\n";
        ss << indent(level + 1) << "\"service\": "     << quoted(f.service)     << ",\n";
        ss << indent(level + 1) << "\"product\": "     << quoted(f.product)     << ",\n";
        ss << indent(level + 1) << "\"version\": "     << quoted(f.version)     << ",\n";
        ss << indent(level + 1) << "\"cve_id\": "      << quoted(f.cve_id)      << ",\n";
        ss << indent(level + 1) << "\"description\": " << quoted(f.description) << "\n";
        ss << indent(level) << "}";
        return ss.str();
    }

    std::string write_host(const core::Host& host, int level) {
        std::ostringstream ss;
        ss << indent(level) << "{\n";
        ss << indent(level + 1) << "\"ip\": "        << quoted(host.ip)       << ",\n";
        ss << indent(level + 1) << "\"hostname\": "  << quoted(host.hostname) << ",\n";
        ss << indent(level + 1) << "\"state\": "     << quoted(core::to_string(host.state)) << ",\n";
        ss << indent(level + 1) << "\"ttl\": "       << host.ttl << ",\n";
        ss << indent(level + 1) << "\"os_guess\": "  << quoted(host.os_guess) << ",\n";

        ss << indent(level + 1) << "\"ports\": [";
        if (host.ports.empty()) {
            ss << "],\n";
        } else {
            ss << "\n";
            for (std::size_t i = 0; i < host.ports.size(); i++) {
                ss << write_port(host.ports[i], level + 2);
                if (i + 1 < host.ports.size()) ss << ",";
                ss << "\n";
            }
            ss << indent(level + 1) << "],\n";
        }

        ss << indent(level + 1) << "\"findings\": [";
        if (host.findings.empty()) {
            ss << "],\n";
        } else {
            ss << "\n";
            for (std::size_t i = 0; i < host.findings.size(); i++) {
                ss << write_finding(host.findings[i], level + 2);
                if (i + 1 < host.findings.size()) ss << ",";
                ss << "\n";
            }
            ss << indent(level + 1) << "],\n";
        }

        ss << indent(level + 1) << "\"kb\": {";
        if (host.kb.empty()) {
            ss << "}\n";
        } else {
            ss << "\n";
            std::size_t i = 0;
            for (const auto& [key, value] : host.kb) {
                ss << indent(level + 2) << quoted(key) << ": " << quoted(value);
                if (i + 1 < host.kb.size()) ss << ",";
                ss << "\n";
                i++;
            }
            ss << indent(level + 1) << "}\n";
        }

        ss << indent(level) << "}";
        return ss.str();
    }
}

namespace report {
    bool write_json_report(
        const std::string& path,
        const std::string& target,
        const std::vector<core::Host>& hosts
    ) {
        std::ostringstream ss;

        ss << "{\n";
        ss << "  \"target\": "     << quoted(target) << ",\n";
        ss << "  \"scanned_at\": " << quoted(iso_utc_now()) << ",\n";
        ss << "  \"host_count\": " << hosts.size() << ",\n";

        ss << "  \"hosts\": [";
        if (hosts.empty()) {
            ss << "]\n";
        } else {
            ss << "\n";
            for (std::size_t i = 0; i < hosts.size(); i++) {
                ss << write_host(hosts[i], 2);
                if (i + 1 < hosts.size()) ss << ",";
                ss << "\n";
            }
            ss << "  ]\n";
        }

        ss << "}\n";

        std::ofstream file(path);
        if (!file.is_open()) {
            logging::error("Cannot write JSON report to " + path);
            return false;
        }

        file << ss.str();
        file.close();

        logging::info("JSON report written to " + path);
        return true;
    }
}
