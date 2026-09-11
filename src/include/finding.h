// finding.h

#pragma once

#include "severity.h"
#include "confidence.h"

#include <cstdint>
#include <string>

namespace core {
    struct Finding {
        std::string plugin_name;
        std::string title;

        Severity severity = Severity::INFO;
        Confidence confidence = Confidence::UNKNOWN;

        std::uint16_t port_number = 0;

        std::string service;
        std::string product;
        std::string version;

        std::string description;
        std::string cve_id;
    };
}
