// interpreter.hpp

#pragma once

#include "ztl/ast.hpp"
#include "port.h"
#include "finding.h"
#include "transport/tcp.hpp"
#include "core/knowledge_base.hpp"

#include <optional>
#include <string>

namespace ztl {
    std::optional<core::Finding> execute(
        const Plugin& plugin,
        const core::Port& port,
        const std::string& target_ip,
        core::KnowledgeBase& kb,
        int timeout_ms = 1500
    );
}
