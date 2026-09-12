// tls_checks.hpp

#pragma once

#include "port.h"
#include "finding.h"
#include "core/knowledge_base.hpp"

#include <optional>
#include <string>
#include <vector>

namespace vuln {
    std::vector<core::Finding> run_tls_checks(
        const core::Port& port,
        const std::string& target_ip,
        core::KnowledgeBase& kb
    );
}
