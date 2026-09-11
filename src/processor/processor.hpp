// processor.hpp

#pragma once

#include "port.h"
#include "transport/tcp.hpp"
#include <string>

namespace processor {
    void load_patterns(const std::string& path);
    void detect_service(core::Port& port, const std::string& banner);
    void detect_distro(core::Port& port, const std::string& banner);

    bool try_active_probe(transport::Tcp& tcp, core::Port& port);
}