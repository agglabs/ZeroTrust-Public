// logging.cpp

#include "logging.hpp"
#include <string>
#include <iostream>

namespace logging {
    void info(const std::string& message) {
        std::cout << "[INFO] " << message << "\n";
    }

    void warn(const std::string& message) {
        std::cerr << "[WARN] " << message << "\n";
    }

    void error(const std::string& message) {
        std::cerr << "[ERROR] " << message << "\n";
    }
}