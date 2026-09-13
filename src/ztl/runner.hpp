// runner.hpp

#pragma once

#include "ztl/ast.hpp"
#include "finding.h"

#include <cstdint>
#include <string>
#include <vector>

namespace ztl {
    struct FindingOut {
        std::string plugin_name;
        std::string severity;
        std::string title;
        std::string description;
        std::string evidence;
        core::Evidence evidence_data;
        std::vector<std::string> references;
        std::string remediation;
        std::string cvss_vector;
        double cvss = -1.0;
        std::string cve_id;
        std::string verification = "UNKNOWN";
        double confidence_score = 0.0;
        std::string host;
        core::Protocol protocol = core::Protocol::UNKNOWN;
        std::string scope = "PORT";
        std::string product;
        std::string version;
        std::int64_t timestamp = 0;
        std::string service;
        double confidence = 0.0;
        std::uint16_t port_number = 0;
    };

    struct PluginMeta {
        std::string name;
        std::string description;
        std::string category;
        std::string filter_service;   // empty => any
        bool filter_any = false;
    };

    struct LoadedPlugin {
        Program program;
        std::string source_path;
        PluginMeta preview_meta;      // filled in by preload_meta()
    };

    struct RunOutcome {
        PluginMeta meta;
        std::vector<FindingOut> findings;
        std::string detected_service;
        std::string detected_product;
        std::string detected_version;
        int detected_port = 0;
    };

    // Per-(host,port) shared key/value store used by plugins on the same port.
    struct KbShared;
    using KbSharedPtr = std::shared_ptr<KbShared>;
    KbSharedPtr make_kb();

    // Load & parse a single .ztl file.
    LoadedPlugin load_plugin(const std::string& path);

    // Load every *.ztl in a directory (non-recursive).
    std::vector<LoadedPlugin> load_plugins_dir(const std::string& dir);

    // Run one plugin against one (host, port). `known_service` may be empty.
    // `kb` (may be null) is a shared knowledge base for all plugins on this port.
    RunOutcome run_plugin(const LoadedPlugin& p,
                          const std::string& target_host,
                          int target_port,
                          const std::string& known_service,
                          KbSharedPtr kb = nullptr);

    // Run every applicable plugin against a list of open ports on a host.
    // Two-pass: first plugins with filter_any (service-detect), then plugins with
    // filter_service matching detected services.
    std::vector<FindingOut> run_all(const std::vector<LoadedPlugin>& plugins,
                                    const std::string& host,
                                    const std::vector<int>& open_ports);

    // Enriched service info discovered by plugins on a single port.
    struct DetectedInfo {
        std::string service;
        std::string product;
        std::string version;
    };

    // Two-pass run on a single (host, port). Returns detected service info.
    std::vector<FindingOut> run_for_port(const std::vector<LoadedPlugin>& plugins,
                                         const std::string& host, int port,
                                         const std::string& initial_service,
                                         DetectedInfo& out_info);
}
