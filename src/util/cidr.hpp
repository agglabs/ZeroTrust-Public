// cidr.hpp

#pragma once

#include <string>
#include <vector>

namespace util {
    std::vector<std::string> expand_cidr(const std::string& input);
}
