// processor.cpp

#include "processor.hpp"
#include "logging/logging.hpp"
#include "port.h"
#include <regex>
#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>

namespace {
    struct ServicePattern {
        std::regex pattern;
        std::string service;
    };

    std::vector<ServicePattern> service_patterns;

    std::vector<std::string> split_by_tab(const std::string& line) {
        std::vector<std::string> fields;
        std::istringstream stream(line);
        std::string field;

        while (std::getline(stream, field, '\t')) {
            fields.push_back(field);
        }

        return fields;
    }

    struct DistroPattern {
        std::regex pattern;
        std::string tag;
    };

    const std::vector<DistroPattern>& distro_patterns() {
        static const std::vector<DistroPattern> patterns = {
            { std::regex(R"((Ubuntu-[0-9a-zA-Z.~+_-]+))"),    "Ubuntu" },
            { std::regex(R"((Debian-[0-9a-zA-Z.~+_-]+))"),    "Debian" },
            { std::regex(R"(\bel([0-9]+)_([0-9]+))"),          "RHEL" },
            { std::regex(R"(\.fc([0-9]+))"),                   "Fedora" },
            { std::regex(R"(\.amzn([0-9]+))"),                 "AmazonLinux" },
            { std::regex(R"(\+alpine)"),                       "Alpine" },
            { std::regex(R"(\+suse)"),                         "SUSE" }
        };

        return patterns;
    }

    // Service detection lives in ZTL plugins (`data/plugins/*-detect.ztl`).
    // The regex path below still runs for the ~11k nmap patterns, but every
    // binary-protocol handshake (MySQL, PostgreSQL, ...) is handled by a plugin
    // and can override anything the regex path guessed.

}

namespace processor {
    void load_patterns(const std::string& path) {
        std::ifstream file(path);

        if (!file.is_open()) {
            logging::error("Unable to open pattern file at " + path);
            return;
        }

        std::string line;
        int loaded = 0;

        while (std::getline(file, line)) {
            if (line.empty() || line[0] == '#') {
                continue;
            }

            std::vector<std::string> fields = split_by_tab(line);

            if (fields.empty() || fields[0] != "match") {
                continue;
            }

            if (fields.size() < 3) {
                logging::warn("Invalid line at " + line);
                continue;
            }

            std::string service = fields[1];
            std::string regex_str = fields[2];

            auto regex_flags = std::regex_constants::ECMAScript;
            if (fields.size() > 3 && fields[3] == "icase") {
                regex_flags |= std::regex_constants::icase;
            }

            service_patterns.push_back({ std::regex(regex_str, regex_flags), service });
            loaded++;
        }

        logging::info("Initialized " + std::to_string(loaded) + " probes from " + path);
    }

    void detect_service(core::Port& port, const std::string& banner) {
        for (const ServicePattern& sp : service_patterns) {
            std::smatch matches;

            if (std::regex_search(banner, matches, sp.pattern)) {
                port.service = sp.service;

                if (matches.size() > 1) {
                    port.product = matches[1];
                }

                if (matches.size() > 2) {
                    port.version = matches[2];
                }

                return;
            }
        }

        port.service = "";
    }

    void detect_distro(core::Port& port, const std::string& banner) {
        for (const DistroPattern& dp : distro_patterns()) {
            std::smatch matches;

            if (std::regex_search(banner, matches, dp.pattern)) {
                port.distro = dp.tag;

                if (matches.size() > 1 && !matches[1].str().empty()) {
                    port.distro += " (" + matches[1].str() + ")";
                }

                return;
            }
        }
    }
}