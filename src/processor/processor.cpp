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

    // --- Probes PASYWNE: banner juz mamy, tylko go parsujemy ---
    // Zeby dodac kolejna baze danych wysylajaca dane same z siebie,
    // dopisz nowa funkcje bool(core::Port&, const std::string&) i dodaj ja do binary_probes.

    bool try_mysql(core::Port& port, const std::string& banner) {
        if (banner.size() < 6) {
            return false;
        }

        std::uint8_t protocol_version = static_cast<std::uint8_t>(banner[4]);

        if (protocol_version != 0x0a) {
            return false;
        }

        std::size_t version_start = 5;
        std::size_t version_end = banner.find('\0', version_start);

        if (version_end == std::string::npos) {
            return false;
        }

        port.service = "mysql";
        port.product = "MySQL";
        port.version = banner.substr(version_start, version_end - version_start);

        return true;
    }

    using BinaryProbe = bool (*)(core::Port&, const std::string&);

    std::vector<BinaryProbe> binary_probes = {
        try_mysql,
    };

    // --- Probes AKTYWNE: trzeba cos wyslac, zanim cokolwiek przyjdzie ---
    // Zeby dodac kolejna baze danych wymagajaca zapytania,
    // dopisz nowa funkcje bool(transport::Tcp&, core::Port&) i dodaj ja do active_probes.

    bool try_postgresql(transport::Tcp& tcp, core::Port& port) {
        std::vector<std::uint8_t> ssl_request = {
            0x00, 0x00, 0x00, 0x08,
            0x04, 0xD2, 0x16, 0x2F
        };

        std::string probe(
            reinterpret_cast<const char*>(ssl_request.data()),
            ssl_request.size()
        );

        if (!tcp.send(probe)) {
            return false;
        }

        std::string response = tcp.receive(800);

        if (response.size() != 1) {
            return false;
        }

        if (response[0] == 'S' || response[0] == 'N') {
            port.service = "postgresql";
            port.product = "PostgreSQL";
            return true;
        }

        return false;
    }

    using ActiveProbe = bool (*)(transport::Tcp&, core::Port&);

    std::vector<ActiveProbe> active_probes = {
        try_postgresql,
    };
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

        for (const BinaryProbe& probe : binary_probes) {
            if (probe(port, banner)) {
                return;
            }
        }

        port.service = "";
    }

    bool try_active_probe(transport::Tcp& tcp, core::Port& port) {
        for (const ActiveProbe& probe : active_probes) {
            if (probe(tcp, port)) {
                return true;
            }
        }

        return false;
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