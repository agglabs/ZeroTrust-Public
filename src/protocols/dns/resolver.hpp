// resolver.hpp

#pragma once

#include <string>
#include <optional>

namespace dns {
    std::optional<std::string> resolve(const std::string& hostname, int timeout_ms);
}