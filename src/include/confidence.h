// confidence.h

#pragma once

#include <string>

namespace core {
    enum class Confidence {
        UNKNOWN,

        VERSION_MATCH,
        VERIFIED
    };

    inline std::string to_string(Confidence c) {
        switch (c) {
            case Confidence::UNKNOWN:       return "UNKNOWN";
            case Confidence::VERSION_MATCH: return "VERSION_MATCH";
            case Confidence::VERIFIED:      return "VERIFIED";
        }
        return "UNKNOWN";
    }
}
