// parser.hpp

#pragma once

#include "ztl/ast.hpp"

#include <optional>
#include <string>
#include <vector>

namespace ztl {
    std::optional<Plugin> parse_plugin(const std::string& source, const std::string& source_name);

    std::vector<Plugin> load_plugins_from_dir(const std::string& dir_path);
}
