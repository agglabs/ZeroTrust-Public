// tcp_range.cpp

#include "scan/tcp_range.hpp"

#include "transport/tcp.hpp"
#include "processor/processor.hpp"
#include "processor/thread_pool.hpp"
#include "scan/cve.hpp"
#include "core/knowledge_base.hpp"

#include <algorithm>
#include <cctype>
#include <mutex>
#include <unordered_set>

namespace scan {
    TcpRangeResult tcp_range_scan(
        const std::string& ip,
        int start_port,
        int end_port,
        const std::vector<ztl::LoadedPlugin>& plugins,
        const LiveSink& sink,
        int threads,
        int connect_timeout_ms)
    {
        TcpRangeResult out;
        std::mutex mu;
        core::KnowledgeBase kb;

        {
            concurrency::ThreadPool pool(threads);

            for (int p = start_port; p <= end_port; p++) {
                pool.enqueue([&, p]() {
                    transport::Tcp tcp;
                    core::Port result = tcp.connect(ip, p, connect_timeout_ms);
                    if (result.state != core::PortState::OPEN) {
                        if (sink.progress) sink.progress->fetch_add(1);
                        return;
                    }

                    std::string banner = tcp.receive(800);
                    if (banner.empty()) {
                        std::string http_request =
                            "GET / HTTP/1.0\r\n"
                            "Host: " + ip + "\r\n"
                            "Connection: close\r\n\r\n";
                        if (tcp.send(http_request)) banner = tcp.receive(800);
                    }

                    if (!banner.empty()) {
                        processor::detect_service(result, banner);
                        processor::detect_distro(result, banner);
                    }

                    std::vector<core::Finding> local;

                    auto native = vuln::run_native_checks(result, ip, kb);
                    for (auto& f : native) local.push_back(std::move(f));

                    {
                        ztl::DetectedInfo detected;
                        auto plugin_findings = ztl::run_for_port(plugins, ip, result.number, result.service, detected);
                        // Plugins are more specific than the generic regex path — when
                        // a plugin claims a value, let it win over anything guessed earlier.
                        if (!detected.service.empty()) result.service = detected.service;
                        if (!detected.product.empty()) result.product = detected.product;
                        if (!detected.version.empty()) result.version = detected.version;
                        for (const auto& f : plugin_findings) {
                            core::Finding cf;
                            cf.plugin_name = f.plugin_name;
                            cf.title       = f.title;
                            cf.description = f.description + (f.evidence.empty() ? "" : " | evidence: " + f.evidence);
                            cf.cve_id      = f.cve_id;
                            cf.verification = f.verification;
                            cf.confidence_score = f.confidence_score;
                            cf.port_number = f.port_number;
                            cf.host        = f.host;
                            cf.protocol    = f.protocol;
                            cf.scope       = f.scope;
                            cf.service     = f.service;
                            cf.product     = f.product;
                            cf.version     = f.version;
                            cf.evidence    = f.evidence;
                            cf.evidence_data = f.evidence_data;
                            cf.references = f.references;
                            cf.remediation = f.remediation;
                            cf.cvss_vector = f.cvss_vector;
                            cf.cvss        = f.cvss;
                            cf.timestamp   = f.timestamp;
                            std::string sev = f.severity;
                            for (auto& c : sev) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
                            if      (sev == "CRITICAL") cf.severity = core::Severity::CRITICAL;
                            else if (sev == "HIGH")     cf.severity = core::Severity::HIGH;
                            else if (sev == "MEDIUM")   cf.severity = core::Severity::MEDIUM;
                            else if (sev == "LOW")      cf.severity = core::Severity::LOW;
                            else                        cf.severity = core::Severity::INFO;
                            if      (f.verification == "ACTIVE_CHECK")  cf.confidence = core::Confidence::VERIFIED;
                            else if (f.verification == "VERSION_MATCH") cf.confidence = core::Confidence::VERSION_MATCH;
                            else                                         cf.confidence = core::Confidence::UNKNOWN;
                            local.push_back(std::move(cf));
                        }
                    }

                    std::unordered_set<std::string> plugin_cves;
                    for (const core::Finding& f : local) {
                        if (!f.cve_id.empty()) plugin_cves.insert(f.cve_id);
                    }
                    auto cves = vuln::check_port(result);
                    for (auto& f : cves) {
                        if (!plugin_cves.count(f.cve_id)) local.push_back(std::move(f));
                    }

                    for (core::Finding& f : local) {
                        if (f.host.empty()) f.host = ip;
                        if (f.protocol == core::Protocol::UNKNOWN) f.protocol = result.protocol;
                        if (f.service.empty()) f.service = result.service;
                        if (f.product.empty()) f.product = result.product;
                        if (f.version.empty()) f.version = result.version;
                    }
                    core::deduplicate_findings(local);

                    if (sink.on_port_open) sink.on_port_open(result, local);

                    {
                        std::lock_guard<std::mutex> g(mu);
                        out.ports.push_back(result);
                        for (auto& f : local) out.findings.push_back(std::move(f));
                    }
                    if (sink.progress) sink.progress->fetch_add(1);
                });
            }
        }

        std::sort(out.ports.begin(), out.ports.end(),
            [](const core::Port& a, const core::Port& b) { return a.number < b.number; });
        std::sort(out.findings.begin(), out.findings.end(),
            [](const core::Finding& a, const core::Finding& b) { return a.port_number < b.port_number; });
        core::deduplicate_findings(out.findings);
        return out;
    }
}
