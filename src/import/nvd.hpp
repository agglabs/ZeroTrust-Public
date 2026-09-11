// nvd.hpp

#pragma once

#include <string>

namespace import_data {
    int import_nvd(const std::string& json_path, const std::string& output_path);
}
