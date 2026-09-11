// host.h

#pragma once

#include "port.h"
#include "finding.h"

#include <map>
#include <string>
#include <vector>

namespace core {
    enum class HostState {
        UNKNOWN,

        ALIVE,
        UNREACHABLE
    };

    struct Host {
        std::string ip;
        std::string hostname;

        HostState state = HostState::UNKNOWN;

        int ttl = 0;
        std::string os_guess;

        std::vector<Port> ports;
        std::vector<Finding> findings;

        std::map<std::string, std::string> kb;
    };

    inline std::string to_string(HostState h) {
        switch (h) {
            case HostState::UNKNOWN: return "UNKNOWN";
            case HostState::ALIVE:   return "ALIVE";
            case HostState::UNREACHABLE: return "UNREACHABLE";
        }
        return "UNKNOWN";
    }
}