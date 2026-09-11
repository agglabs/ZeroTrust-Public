// json_writer.hpp

#pragma once

#include "host.h"

#include <string>
#include <vector>

namespace report {
    bool write_json_report(
        const std::string& path,
        const std::string& target,
        const std::vector<core::Host>& hosts
    );
}
