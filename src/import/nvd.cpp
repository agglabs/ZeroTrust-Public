// nvd.cpp

#include "import/nvd.hpp"
#include "util/json.hpp"
#include "logging/logging.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>

namespace {
    struct CpeMatch {
        std::string vendor;
        std::string product;
        std::string version;
        std::string version_start;
        std::string version_end;
    };

    struct Entry {
        std::string cve_id;
        std::string severity;
        std::string description;
        std::vector<CpeMatch> cpe_matches;
    };

    std::vector<std::string> split(const std::string& s, char sep) {
        std::vector<std::string> out;
        std::string current;
        for (char c : s) {
            if (c == sep) { out.push_back(current); current.clear(); }
            else current += c;
        }
        out.push_back(current);
        return out;
    }

    std::optional<CpeMatch> parse_cpe_criteria(const std::string& cpe23) {
        auto parts = split(cpe23, ':');
        if (parts.size() < 6) return std::nullopt;
        if (parts[0] != "cpe") return std::nullopt;

        CpeMatch out;
        out.vendor  = parts[3];
        out.product = parts[4];
        out.version = parts[5];
        return out;
    }

    std::string english_description(const util::JsonArray& descriptions) {
        for (const auto& item : descriptions) {
            if (!item->is_object()) continue;
            const auto& obj = item->as_object();
            if (util::obj_get_string(obj, "lang") == "en") {
                return util::obj_get_string(obj, "value");
            }
        }
        return "";
    }

    std::string highest_severity(const util::JsonObject& metrics) {
        for (const std::string& key : { "cvssMetricV31", "cvssMetricV30", "cvssMetricV2" }) {
            auto it = metrics.find(key);
            if (it == metrics.end() || !it->second->is_array()) continue;
            const auto& arr = it->second->as_array();
            for (const auto& item : arr) {
                if (!item->is_object()) continue;
                const auto& obj = item->as_object();
                auto cvss_it = obj.find("cvssData");
                if (cvss_it == obj.end() || !cvss_it->second->is_object()) continue;
                std::string sev = util::obj_get_string(cvss_it->second->as_object(), "baseSeverity");
                if (!sev.empty()) return sev;
            }
        }
        return "MEDIUM";
    }

    void extract_cpe_matches(const util::JsonArray& configurations, std::vector<CpeMatch>& out) {
        for (const auto& conf : configurations) {
            if (!conf->is_object()) continue;
            auto nodes_it = conf->as_object().find("nodes");
            if (nodes_it == conf->as_object().end() || !nodes_it->second->is_array()) continue;

            for (const auto& node : nodes_it->second->as_array()) {
                if (!node->is_object()) continue;
                auto matches_it = node->as_object().find("cpeMatch");
                if (matches_it == node->as_object().end() || !matches_it->second->is_array()) continue;

                for (const auto& match : matches_it->second->as_array()) {
                    if (!match->is_object()) continue;
                    const auto& m = match->as_object();

                    if (!util::obj_get_bool(m, "vulnerable")) continue;

                    std::string criteria = util::obj_get_string(m, "criteria");
                    auto cpe = parse_cpe_criteria(criteria);
                    if (!cpe) continue;

                    cpe->version_start = util::obj_get_string(m, "versionStartIncluding");
                    if (cpe->version_start.empty()) {
                        cpe->version_start = util::obj_get_string(m, "versionStartExcluding");
                    }
                    cpe->version_end = util::obj_get_string(m, "versionEndIncluding");
                    if (cpe->version_end.empty()) {
                        cpe->version_end = util::obj_get_string(m, "versionEndExcluding");
                    }

                    out.push_back(*cpe);
                }
            }
        }
    }

    Entry extract_entry(const util::JsonObject& cve_wrapper) {
        Entry e;

        auto cve_it = cve_wrapper.find("cve");
        if (cve_it == cve_wrapper.end() || !cve_it->second->is_object()) return e;
        const auto& cve = cve_it->second->as_object();

        e.cve_id = util::obj_get_string(cve, "id");

        auto desc_it = cve.find("descriptions");
        if (desc_it != cve.end() && desc_it->second->is_array()) {
            e.description = english_description(desc_it->second->as_array());
        }

        auto metrics_it = cve.find("metrics");
        if (metrics_it != cve.end() && metrics_it->second->is_object()) {
            e.severity = highest_severity(metrics_it->second->as_object());
        } else {
            e.severity = "MEDIUM";
        }

        auto conf_it = cve.find("configurations");
        if (conf_it != cve.end() && conf_it->second->is_array()) {
            extract_cpe_matches(conf_it->second->as_array(), e.cpe_matches);
        }

        return e;
    }

    std::string sanitize_field(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (char c : s) {
            if      (c == '\t') out += ' ';
            else if (c == '\n') out += ' ';
            else if (c == '\r') continue;
            else                out += c;
        }
        return out;
    }

    std::string truncate(const std::string& s, std::size_t max_len) {
        if (s.size() <= max_len) return s;
        return s.substr(0, max_len - 3) + "...";
    }

    std::string capitalize_product(const std::string& s) {
        if (s.empty()) return s;
        std::string out = s;
        out[0] = static_cast<char>(std::toupper(static_cast<unsigned char>(out[0])));
        return out;
    }
}

namespace import_data {
    int import_nvd(const std::string& json_path, const std::string& output_path) {
        auto root_opt = util::parse_json_file(json_path);
        if (!root_opt) {
            logging::error("Cannot open or parse NVD JSON at " + json_path);
            return 0;
        }

        auto root = *root_opt;
        if (!root->is_object()) {
            logging::error("NVD JSON root is not an object");
            return 0;
        }

        auto vulns_it = root->as_object().find("vulnerabilities");
        if (vulns_it == root->as_object().end() || !vulns_it->second->is_array()) {
            logging::error("NVD JSON has no 'vulnerabilities' array");
            return 0;
        }

        std::ofstream out(output_path);
        if (!out.is_open()) {
            logging::error("Cannot write output file at " + output_path);
            return 0;
        }

        out << "# zt-cve-database-nvd.txt\n";
        out << "# Auto-generated from NVD JSON feed.\n";
        out << "# Source: NVD (public domain, U.S. Government work)\n";
        out << "# format: cve_id<TAB>product<TAB>version_min<TAB>version_max<TAB>severity<TAB>description\n\n";

        int total_seen = 0;
        int total_kept = 0;

        for (const auto& v_item : vulns_it->second->as_array()) {
            if (!v_item->is_object()) continue;

            total_seen++;

            Entry e = extract_entry(v_item->as_object());
            if (e.cve_id.empty()) continue;
            if (e.cpe_matches.empty()) continue;

            std::string short_desc = truncate(sanitize_field(e.description), 300);

            for (const CpeMatch& cpe : e.cpe_matches) {
                std::string product = capitalize_product(cpe.product);

                std::string vmin = cpe.version_start;
                std::string vmax = cpe.version_end;

                if (vmin.empty()) vmin = "*";
                if (vmax.empty()) {
                    if (cpe.version.empty() || cpe.version == "*" || cpe.version == "-") {
                        vmax = "*";
                    } else {
                        vmin = cpe.version;
                        vmax = cpe.version;
                    }
                }

                out << e.cve_id << "\t"
                    << product   << "\t"
                    << vmin      << "\t"
                    << vmax      << "\t"
                    << e.severity << "\t"
                    << short_desc << "\n";

                total_kept++;
            }
        }

        logging::info(
            "NVD import: " + std::to_string(total_kept) + " entries from " +
            std::to_string(total_seen) + " CVEs in " + json_path
        );

        return total_kept;
    }
}
