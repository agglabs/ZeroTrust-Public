// reader.cpp

#include "report/reader.hpp"
#include "util/json.hpp"
#include "logging/logging.hpp"

namespace {
    core::PortState parse_port_state(const std::string& s) {
        if (s == "OPEN")          return core::PortState::OPEN;
        if (s == "CLOSED")        return core::PortState::CLOSED;
        if (s == "FILTERED")      return core::PortState::FILTERED;
        if (s == "OPEN_FILTERED") return core::PortState::OPEN_FILTERED;
        return core::PortState::UNKNOWN;
    }

    core::Protocol parse_protocol(const std::string& s) {
        if (s == "TCP")  return core::Protocol::TCP;
        if (s == "UDP")  return core::Protocol::UDP;
        if (s == "ICMP") return core::Protocol::ICMP;
        return core::Protocol::UNKNOWN;
    }

    core::HostState parse_host_state(const std::string& s) {
        if (s == "ALIVE")       return core::HostState::ALIVE;
        if (s == "UNREACHABLE") return core::HostState::UNREACHABLE;
        return core::HostState::UNKNOWN;
    }

    core::Severity parse_severity(const std::string& s) {
        if (s == "INFO")     return core::Severity::INFO;
        if (s == "LOW")      return core::Severity::LOW;
        if (s == "MEDIUM")   return core::Severity::MEDIUM;
        if (s == "HIGH")     return core::Severity::HIGH;
        if (s == "CRITICAL") return core::Severity::CRITICAL;
        return core::Severity::INFO;
    }

    core::Confidence parse_confidence(const std::string& s) {
        if (s == "VERSION_MATCH") return core::Confidence::VERSION_MATCH;
        if (s == "VERIFIED")      return core::Confidence::VERIFIED;
        return core::Confidence::UNKNOWN;
    }

    core::Port to_port(const util::JsonObject& o) {
        core::Port p;
        p.number   = static_cast<std::uint16_t>(util::obj_get_int(o, "number"));
        p.protocol = parse_protocol(util::obj_get_string(o, "protocol"));
        p.state    = parse_port_state(util::obj_get_string(o, "state"));
        p.service  = util::obj_get_string(o, "service");
        p.product  = util::obj_get_string(o, "product");
        p.version  = util::obj_get_string(o, "version");
        p.distro   = util::obj_get_string(o, "distro");
        p.tls      = util::obj_get_bool(o, "tls");
        return p;
    }

    core::Finding to_finding(const util::JsonObject& o) {
        core::Finding f;
        f.plugin_name = util::obj_get_string(o, "plugin_name");
        f.title       = util::obj_get_string(o, "title");
        f.severity    = parse_severity(util::obj_get_string(o, "severity"));
        f.confidence  = parse_confidence(util::obj_get_string(o, "confidence"));
        f.port_number = static_cast<std::uint16_t>(util::obj_get_int(o, "port_number"));
        f.service     = util::obj_get_string(o, "service");
        f.product     = util::obj_get_string(o, "product");
        f.version     = util::obj_get_string(o, "version");
        f.cve_id      = util::obj_get_string(o, "cve_id");
        f.description = util::obj_get_string(o, "description");
        return f;
    }

    core::Host to_host(const util::JsonObject& o) {
        core::Host h;
        h.ip       = util::obj_get_string(o, "ip");
        h.hostname = util::obj_get_string(o, "hostname");
        h.state    = parse_host_state(util::obj_get_string(o, "state"));
        h.ttl      = util::obj_get_int(o, "ttl");
        h.os_guess = util::obj_get_string(o, "os_guess");

        auto ports_it = o.find("ports");
        if (ports_it != o.end() && ports_it->second->is_array()) {
            for (const auto& item : ports_it->second->as_array()) {
                if (item->is_object()) h.ports.push_back(to_port(item->as_object()));
            }
        }

        auto findings_it = o.find("findings");
        if (findings_it != o.end() && findings_it->second->is_array()) {
            for (const auto& item : findings_it->second->as_array()) {
                if (item->is_object()) h.findings.push_back(to_finding(item->as_object()));
            }
        }

        auto kb_it = o.find("kb");
        if (kb_it != o.end() && kb_it->second->is_object()) {
            for (const auto& [key, value] : kb_it->second->as_object()) {
                if (value->is_string()) h.kb[key] = value->as_string();
            }
        }

        return h;
    }
}

namespace report {
    std::optional<ScanReport> read_scan_report(const std::string& path) {
        auto root_opt = util::parse_json_file(path);
        if (!root_opt) {
            logging::error("Cannot open or parse JSON report at " + path);
            return std::nullopt;
        }

        auto root = *root_opt;
        if (!root->is_object()) {
            logging::error("Malformed JSON report: " + path);
            return std::nullopt;
        }

        const util::JsonObject& obj = root->as_object();

        ScanReport report;
        report.target     = util::obj_get_string(obj, "target");
        report.scanned_at = util::obj_get_string(obj, "scanned_at");

        auto hosts_it = obj.find("hosts");
        if (hosts_it != obj.end() && hosts_it->second->is_array()) {
            for (const auto& item : hosts_it->second->as_array()) {
                if (item->is_object()) report.hosts.push_back(to_host(item->as_object()));
            }
        }

        return report;
    }
}
