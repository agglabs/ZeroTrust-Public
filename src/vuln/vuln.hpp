// vuln.hpp

#pragma once

#include "port.h"
#include "finding.h"
#include "core/knowledge_base.hpp"

#include <string>
#include <vector>

namespace vuln {
    void load_database(const std::string& path);

    std::vector<core::Finding> check_port(const core::Port& port);

    std::vector<core::Finding> run_native_checks(
        const core::Port& port,
        const std::string& target_ip,
        core::KnowledgeBase& kb
    );
}
