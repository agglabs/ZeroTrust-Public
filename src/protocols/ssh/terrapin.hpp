// terrapin.hpp

#pragma once

#include "port.h"
#include "finding.h"
#include "core/knowledge_base.hpp"

#include <optional>
#include <string>

namespace vuln {
    std::optional<core::Finding> check_terrapin(
        const core::Port& port,
        const std::string& target_ip,
        core::KnowledgeBase& kb
    );
}
