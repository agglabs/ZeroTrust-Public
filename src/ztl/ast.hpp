// ast.hpp

#pragma once

#include "severity.h"
#include "protocol.h"

#include <string>
#include <vector>

namespace ztl {
    struct Capture {
        std::string pattern;
        std::string name;
    };

    struct Require {
        std::string field;
        std::string op;
        std::string value;
    };

    struct Probe {
        std::string send;
        std::vector<std::string> expect;
        std::vector<std::string> expect_not;
        std::string when;

        std::vector<Capture> captures;
        std::vector<Require> post_requires;
    };

    enum class MatchMode {
        ALL,
        ANY
    };

    struct Plugin {
        std::string name;
        std::string service;
        std::string title;
        std::string description;

        core::Severity severity = core::Severity::INFO;
        core::Protocol protocol = core::Protocol::TCP;
        MatchMode match_mode = MatchMode::ALL;

        std::vector<Require> pre_requires;
        std::vector<Probe> probes;
    };
}
