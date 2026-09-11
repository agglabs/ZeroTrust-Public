// vuln.cpp

#include "vuln/vuln.hpp"
#include "vuln/terrapin.hpp"
#include "vuln/tls_checks.hpp"
#include "logging/logging.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <functional>
#include <sstream>

namespace {
    struct CveEntry {
        std::string cve_id;
        std::string product;
        std::string version_min;
        std::string version_max;
        core::Severity severity = core::Severity::MEDIUM;
        std::string description;
    };

    std::vector<CveEntry> cve_database;

    std::string to_lower(const std::string& s) {
        std::string out = s;
        std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return out;
    }

    std::vector<std::string> split_by_tab(const std::string& line) {
        std::vector<std::string> fields;
        std::istringstream stream(line);
        std::string field;

        while (std::getline(stream, field, '\t')) {
            fields.push_back(field);
        }

        return fields;
    }

    core::Severity parse_severity(const std::string& s) {
        if (s == "INFO")     return core::Severity::INFO;
        if (s == "LOW")      return core::Severity::LOW;
        if (s == "MEDIUM")   return core::Severity::MEDIUM;
        if (s == "HIGH")     return core::Severity::HIGH;
        if (s == "CRITICAL") return core::Severity::CRITICAL;
        return core::Severity::MEDIUM;
    }

    std::vector<int> extract_numeric_parts(const std::string& version) {
        std::vector<int> parts;
        std::string current;

        for (char c : version) {
            if (std::isdigit(static_cast<unsigned char>(c))) {
                current += c;
            } else {
                if (!current.empty()) {
                    parts.push_back(std::stoi(current));
                    current.clear();
                }
            }
        }

        if (!current.empty()) {
            parts.push_back(std::stoi(current));
        }

        return parts;
    }

    int compare_versions(const std::string& a, const std::string& b) {
        std::vector<int> ap = extract_numeric_parts(a);
        std::vector<int> bp = extract_numeric_parts(b);

        std::size_t n = std::max(ap.size(), bp.size());

        for (std::size_t i = 0; i < n; i++) {
            int av = (i < ap.size()) ? ap[i] : 0;
            int bv = (i < bp.size()) ? bp[i] : 0;

            if (av != bv) return (av < bv) ? -1 : 1;
        }

        return 0;
    }

    bool version_in_range(const std::string& version, const std::string& lo, const std::string& hi) {
        if (lo != "*" && compare_versions(version, lo) < 0) return false;
        if (hi != "*" && compare_versions(version, hi) > 0) return false;
        return true;
    }

    bool product_matches(const std::string& db_product, const std::string& port_product) {
        return to_lower(db_product) == to_lower(port_product);
    }
}

namespace vuln {
    void load_database(const std::string& path) {

        std::ifstream file(path);

        if (!file.is_open()) {
            logging::error("Unable to open CVE database at " + path);
            return;
        }

        std::string line;
        int loaded = 0;

        while (std::getline(file, line)) {
            if (line.empty() || line[0] == '#') continue;

            std::vector<std::string> fields = split_by_tab(line);

            if (fields.size() < 6) {
                logging::warn("Invalid CVE line: " + line);
                continue;
            }

            CveEntry entry;
            entry.cve_id      = fields[0];
            entry.product     = fields[1];
            entry.version_min = fields[2];
            entry.version_max = fields[3];
            entry.severity    = parse_severity(fields[4]);
            entry.description = fields[5];

            cve_database.push_back(std::move(entry));
            loaded++;
        }

        logging::info("Loaded " + std::to_string(loaded) + " CVE entries from " + path);
    }

    std::vector<core::Finding> check_port(const core::Port& port) {
        std::vector<core::Finding> findings;

        if (port.product.empty() || port.version.empty()) {
            return findings;
        }

        for (const CveEntry& entry : cve_database) {
            if (!product_matches(entry.product, port.product)) continue;
            if (!version_in_range(port.version, entry.version_min, entry.version_max)) continue;

            core::Finding f;
            f.plugin_name = "cve-database";
            f.cve_id      = entry.cve_id;
            f.title       = entry.cve_id + ": " + entry.description;
            f.severity    = entry.severity;
            f.confidence  = core::Confidence::VERSION_MATCH;
            f.port_number = port.number;
            f.service     = port.service;
            f.product     = port.product;
            f.version     = port.version;

            std::string caveat =
                "This finding is based on version comparison only and has not been verified "
                "against actual server behavior.";

            if (!port.distro.empty()) {
                caveat +=
                    " Distribution tag detected (" + port.distro +
                    ") which commonly backports security fixes without changing the upstream "
                    "version string. Confirm against the distribution security tracker before "
                    "treating this as exploitable.";
            }

            f.description = entry.description + " " + caveat;

            findings.push_back(std::move(f));
        }

        return findings;
    }

    std::vector<core::Finding> run_native_checks(
        const core::Port& port,
        const std::string& target_ip,
        core::KnowledgeBase& kb
    ) {
        using NativeCheck = std::function<std::optional<core::Finding>(const core::Port&, const std::string&, core::KnowledgeBase&)>;

        struct RegisteredCheck {
            std::string service;
            NativeCheck fn;
        };

        static const std::vector<RegisteredCheck> registry = {
            { "ssh", check_terrapin }
        };

        std::vector<core::Finding> findings;

        for (const RegisteredCheck& entry : registry) {
            if (!entry.service.empty() && entry.service != port.service) continue;

            auto f = entry.fn(port, target_ip, kb);
            if (f) findings.push_back(*f);
        }

        std::vector<core::Finding> tls_findings = run_tls_checks(port, target_ip, kb);
        for (core::Finding& f : tls_findings) {
            findings.push_back(std::move(f));
        }

        return findings;
    }
}
