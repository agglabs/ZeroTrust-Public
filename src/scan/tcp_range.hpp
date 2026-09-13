// tcp_range.hpp

#pragma once

#include "port.h"
#include "finding.h"
#include "ztl/runner.hpp"

#include <atomic>
#include <functional>
#include <string>
#include <vector>

namespace scan {
    struct TcpRangeResult {
        std::vector<core::Port>    ports;
        std::vector<core::Finding> findings;
    };

    // Live-stream hooks for the web UI. All callbacks run on scan worker
    // threads; they must be short and thread-safe.
    struct LiveSink {
        // Incremented by the scanner after every port probe (open or not).
        std::atomic<int>* progress = nullptr;

        // Called once per open port with the enriched Port and its findings
        // (native + ZTL + CVE). Called before the port is added to the return
        // value, from a worker thread.
        std::function<void(const core::Port&, const std::vector<core::Finding>&)> on_port_open;
    };

    // Multi-threaded TCP scan of a port range on one host. Runs banner grabbing,
    // service detection, distro detection, native vuln checks, ZTL plugins and
    // CVE lookups per open port. Returns everything sorted by port number.
    TcpRangeResult tcp_range_scan(
        const std::string& ip,
        int start_port,
        int end_port,
        const std::vector<ztl::LoadedPlugin>& plugins,
        const LiveSink& sink = {},
        int threads = 50,
        int connect_timeout_ms = 1000);
}
