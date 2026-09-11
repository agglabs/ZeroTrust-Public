// store.cpp

#include "feed/store.hpp"
#include "logging/logging.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>

namespace {
    std::vector<std::string> split_by_tab(const std::string& line) {
        std::vector<std::string> fields;
        std::istringstream stream(line);
        std::string field;
        while (std::getline(stream, field, '\t')) {
            fields.push_back(field);
        }
        return fields;
    }

    std::string to_lower(const std::string& s) {
        std::string out = s;
        std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return out;
    }

    std::vector<int> version_numeric_parts(const std::string& v) {
        std::vector<int> parts;
        std::string current;
        for (char c : v) {
            if (std::isdigit(static_cast<unsigned char>(c))) {
                current += c;
            } else if (!current.empty()) {
                parts.push_back(std::stoi(current));
                current.clear();
            }
        }
        if (!current.empty()) parts.push_back(std::stoi(current));
        return parts;
    }

    int compare_versions(const std::string& a, const std::string& b) {
        auto ap = version_numeric_parts(a);
        auto bp = version_numeric_parts(b);
        std::size_t n = std::max(ap.size(), bp.size());
        for (std::size_t i = 0; i < n; i++) {
            int av = i < ap.size() ? ap[i] : 0;
            int bv = i < bp.size() ? bp[i] : 0;
            if (av != bv) return av < bv ? -1 : 1;
        }
        return 0;
    }

    bool version_in_range(const std::string& v, const std::string& lo, const std::string& hi) {
        if (lo != "*" && compare_versions(v, lo) < 0) return false;
        if (hi != "*" && compare_versions(v, hi) > 0) return false;
        return true;
    }
}

namespace feed {
    void Store::load_cve_file(const std::string& path) {
        std::ifstream file(path);
        if (!file.is_open()) {
            logging::warn("CVE file not found (skipping): " + path);
            return;
        }

        int loaded = 0;
        std::string line;
        while (std::getline(file, line)) {
            if (line.empty() || line[0] == '#') continue;

            auto fields = split_by_tab(line);
            if (fields.size() < 6) continue;

            cves_.push_back({
                fields[0], fields[1], fields[2], fields[3], fields[4], fields[5]
            });
            loaded++;
        }

        logging::info("Loaded " + std::to_string(loaded) + " CVE entries from " + path);
    }

    void Store::load_probe_file(const std::string& path, const std::string& source_tag) {
        std::ifstream file(path);
        if (!file.is_open()) {
            logging::warn("Probe file not found (skipping): " + path);
            return;
        }

        int loaded = 0;
        std::string line;
        while (std::getline(file, line)) {
            if (line.empty() || line[0] == '#') continue;

            auto fields = split_by_tab(line);
            if (fields.size() < 3) continue;
            if (fields[0] != "match") continue;

            ProbeEntry e;
            e.service = fields[1];
            e.pattern = fields[2];
            e.flags   = fields.size() > 3 ? fields[3] : "";
            e.source  = source_tag;
            probes_.push_back(std::move(e));
            loaded++;
        }

        logging::info("Loaded " + std::to_string(loaded) + " probes from " + path + " (source=" + source_tag + ")");
    }

    std::optional<CveEntry> Store::find_cve(const std::string& cve_id) const {
        for (const auto& entry : cves_) {
            if (entry.cve_id == cve_id) return entry;
        }
        return std::nullopt;
    }

    std::vector<CveEntry> Store::search_cves(const std::string& product, const std::string& version) const {
        std::vector<CveEntry> out;
        std::string q_product = to_lower(product);

        for (const auto& entry : cves_) {
            if (to_lower(entry.product) != q_product) continue;

            if (!version.empty()) {
                if (!version_in_range(version, entry.version_min, entry.version_max)) continue;
            }

            out.push_back(entry);
        }

        return out;
    }
}
