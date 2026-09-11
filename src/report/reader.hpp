// reader.hpp

#pragma once

#include "host.h"

#include <optional>
#include <string>
#include <vector>

namespace report {
    struct ScanReport {
        std::string target;
        std::string scanned_at;
        std::vector<core::Host> hosts;
    };

    std::optional<ScanReport> read_scan_report(const std::string& path);
}
