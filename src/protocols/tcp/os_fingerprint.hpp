// os_fingerprint.hpp

#pragma once

#include <string>

namespace util {
    inline std::string guess_os_by_ttl(int ttl) {
        if (ttl <= 0)   return "";
        if (ttl <= 64)  return "Linux/Unix/macOS";
        if (ttl <= 128) return "Windows";
        if (ttl <= 255) return "Network device (Cisco/Solaris)";
        return "";
    }
}
