// nmap_probes.cpp

#include "import/nmap_probes.hpp"
#include "logging/logging.hpp"

#include <fstream>
#include <regex>
#include <string>

namespace {
    struct Extracted {
        std::string service;
        std::string pattern;
        std::string flags;
        bool ok = false;
    };

    Extracted extract_match_line(const std::string& line) {
        Extracted out;

        if (line.size() < 8) return out;
        if (line.compare(0, 6, "match ") != 0) return out;

        std::size_t i = 6;
        while (i < line.size() && line[i] == ' ') i++;

        std::size_t service_end = line.find(' ', i);
        if (service_end == std::string::npos) return out;

        out.service = line.substr(i, service_end - i);
        i = service_end + 1;

        while (i < line.size() && line[i] == ' ') i++;

        if (i + 2 >= line.size() || line[i] != 'm') return out;
        char delim = line[i + 1];
        i += 2;

        std::size_t pattern_start = i;
        while (i < line.size() && line[i] != delim) {
            if (line[i] == '\\' && i + 1 < line.size()) i += 2;
            else                                        i++;
        }

        if (i >= line.size()) return out;

        out.pattern = line.substr(pattern_start, i - pattern_start);
        i++;

        std::size_t flags_start = i;
        while (i < line.size() && (line[i] == 's' || line[i] == 'i')) i++;
        out.flags = line.substr(flags_start, i - flags_start);

        out.ok = true;
        return out;
    }

    bool try_compile_regex(const std::string& pattern, bool icase) {
        try {
            auto flags = std::regex_constants::ECMAScript;
            if (icase) flags |= std::regex_constants::icase;

            std::regex re(pattern, flags);
            (void)re;
            return true;
        } catch (const std::regex_error&) {
            return false;
        }
    }

    bool has_incompatible_features(const std::string& pattern) {
        if (pattern.find("(?>") != std::string::npos) return true;
        if (pattern.find("(?<") != std::string::npos) return true;
        if (pattern.find("(?P") != std::string::npos) return true;
        if (pattern.find("(?#") != std::string::npos) return true;
        return false;
    }

    std::string escape_tab_and_newline_in_pattern(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (char c : s) {
            if      (c == '\t') out += "\\t";
            else if (c == '\n') out += "\\n";
            else                out += c;
        }
        return out;
    }
}

namespace import_data {
    int import_nmap_probes(const std::string& source_path, const std::string& output_path) {
        std::ifstream in(source_path);
        if (!in.is_open()) {
            logging::error("Cannot open nmap-service-probes at " + source_path);
            return 0;
        }

        std::ofstream out(output_path);
        if (!out.is_open()) {
            logging::error("Cannot write output file at " + output_path);
            return 0;
        }

        out << "# zt-service-probes-nmap.txt\n";
        out << "# Auto-generated from nmap-service-probes.\n";
        out << "# Only patterns compatible with std::regex ECMAScript are exported.\n";
        out << "# Nmap's data is licensed under Nmap Public Source License.\n\n";

        int total_seen   = 0;
        int total_kept   = 0;
        int skipped_feat = 0;
        int skipped_comp = 0;

        std::string line;
        while (std::getline(in, line)) {
            if (line.empty() || line[0] == '#') continue;
            if (line.compare(0, 6, "match ") != 0) continue;

            total_seen++;

            Extracted m = extract_match_line(line);
            if (!m.ok || m.pattern.empty()) {
                skipped_feat++;
                continue;
            }

            if (has_incompatible_features(m.pattern)) {
                skipped_feat++;
                continue;
            }

            bool icase = m.flags.find('i') != std::string::npos;
            if (!try_compile_regex(m.pattern, icase)) {
                skipped_comp++;
                continue;
            }

            std::string clean_pattern = escape_tab_and_newline_in_pattern(m.pattern);

            out << "match\t" << m.service << "\t" << clean_pattern;
            if (icase) out << "\ticase";
            out << "\n";

            total_kept++;
        }

        logging::info(
            "nmap probes import: " + std::to_string(total_kept) + "/" +
            std::to_string(total_seen) + " kept " +
            "(" + std::to_string(skipped_feat) + " unsupported features, " +
            std::to_string(skipped_comp) + " regex compile errors)"
        );

        return total_kept;
    }
}
