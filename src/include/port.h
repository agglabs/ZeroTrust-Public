// port.h

#pragma once

#include <cstdint>
#include <string>

#include "protocol.h"

namespace core {
    enum class PortState {
        UNKNOWN,

        OPEN,
        CLOSED,
        FILTERED,
        OPEN_FILTERED
    };

    struct Port {
        std::uint16_t number = 0;

        Protocol protocol = Protocol::UNKNOWN;
        PortState state = PortState::UNKNOWN;

        std::string service;
        std::string product;
        std::string version;
        std::string distro;

        bool tls = false;
    };

    inline std::string to_string(PortState p) {
        switch (p) {
            case PortState::UNKNOWN:       return "UNKNOWN";
            case PortState::OPEN:          return "OPEN";
            case PortState::CLOSED:        return "CLOSED";
            case PortState::FILTERED:      return "FILTERED";
            case PortState::OPEN_FILTERED: return "OPEN_FILTERED";
        }
        return "UNKNOWN";
    }
}