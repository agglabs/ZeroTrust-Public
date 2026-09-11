// server.hpp

#pragma once

#include "feed/store.hpp"

#include <string>

namespace feed {
    void run_server(const std::string& host, int port, const Store& store);
}
