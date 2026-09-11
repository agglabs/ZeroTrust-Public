// severity.h

#pragma once

#include <string>

namespace core {
    enum class Severity {
        INFO,

        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    };

    inline std::string to_string(Severity s) {
        switch (s) {
            case Severity::INFO:     return "INFO";
            case Severity::LOW:      return "LOW";
            case Severity::MEDIUM:   return "MEDIUM";
            case Severity::HIGH:     return "HIGH";
            case Severity::CRITICAL: return "CRITICAL";
        }
        return "INFO";
    }
}
