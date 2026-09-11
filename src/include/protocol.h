// protocol.h

#pragma once

#include <string>

namespace core {
    enum class Protocol {
        UNKNOWN,

        TCP,
        UDP,
        ICMP
    };

    inline std::string to_string(Protocol p) {
        switch (p) {
            case Protocol::UNKNOWN: return "UNKNOWN";
            case Protocol::TCP:     return "TCP";
            case Protocol::UDP:     return "UDP";
            case Protocol::ICMP:    return "ICMP";
        }
        return "UNKNOWN";  
    }
}