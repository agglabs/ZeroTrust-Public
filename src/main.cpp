#include "transport/tcp.hpp"
#include "transport/udp.hpp"
#include "transport/icmp.hpp"
#include "processor/processor.hpp"
#include "protocols/dns/resolver.hpp"
#include "processor/thread_pool.hpp"
#include "ztl/runner.hpp"
#include "scan/cve.hpp"
#include "scan/tcp_range.hpp"
#include "core/knowledge_base.hpp"
#include "scan/reporter.hpp"
#include "scan/cidr.hpp"
#include "protocols/tcp/os_fingerprint.hpp"
#include "webui/webui.hpp"
#include "port.h"
#include "host.h"
#include "finding.h"

#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <mutex>
#include <algorithm>
#include <cctype>
#include <unordered_set>
#include <arpa/inet.h>

using namespace std;

static std::string pad_right(const std::string& s, std::size_t width) {
    if (s.size() >= width) return s;
    return s + std::string(width - s.size(), ' ');
}

static void print_host_report(const std::string& ip,
                              const std::string& hostname,
                              const std::string& os_guess,
                              int ttl,
                              std::vector<core::Port> ports,
                              std::vector<core::Finding> findings)
{
    std::sort(ports.begin(), ports.end(),
        [](const core::Port& a, const core::Port& b) { return a.number < b.number; });
    std::sort(findings.begin(), findings.end(),
        [](const core::Finding& a, const core::Finding& b) { return a.port_number < b.port_number; });

    cout << "\nScan report for ";
    if (!hostname.empty()) cout << hostname << " (" << ip << ")";
    else                   cout << ip;
    cout << "\n";

    cout << "Host is up";
    if (!os_guess.empty() || ttl > 0) {
        cout << " (";
        bool first = true;
        if (ttl > 0)              { cout << "ttl=" << ttl; first = false; }
        if (!os_guess.empty())    { if (!first) cout << ", "; cout << "os=" << os_guess; }
        cout << ")";
    }
    cout << "\n\n";

    if (ports.empty()) {
        cout << "No open ports.\n";
    } else {
        cout << pad_right("PORT", 10)
             << pad_right("STATE", 7)
             << pad_right("SERVICE", 12)
             << "PRODUCT\n";

        for (const core::Port& p : ports) {
            std::string port_col = std::to_string(p.number) + "/tcp";
            std::string prod = p.product;
            if (!p.version.empty()) prod += (prod.empty() ? "" : " ") + p.version;
            if (!p.distro.empty()) prod += (prod.empty() ? "" : " ") + std::string("[") + p.distro + "]";

            cout << pad_right(port_col, 10)
                 << pad_right("open", 7)
                 << pad_right(p.service.empty() ? "-" : p.service, 12)
                 << (prod.empty() ? "-" : prod)
                 << "\n";
        }
    }

    if (!findings.empty()) {
        cout << "\nFindings (" << findings.size() << "):\n";
        for (const core::Finding& f : findings) {
            std::string sev = "[" + core::to_string(f.severity) + "]";
            std::string conf = "[" + core::to_string(f.confidence) + "]";
            std::string verification = "[" + core::verification_label(f.verification) + "]";
            std::string where = std::to_string(f.port_number) + "/tcp";
              cout << "  " << pad_right(sev, 12) << pad_right(conf, 17) << pad_right(verification, 20)
                 << pad_right(where, 10) << f.title << "\n";
            if (!f.description.empty()) {
                cout << "      " << f.description << "\n";
            }
        }
    }
}

int main()
{
    processor::load_patterns("data/zt-service-probes.txt");
    vuln::load_database("data/zt-cve-database.txt");
    vuln::load_distro_fixes("data/zt-distro-fixes.txt");

    const std::vector<ztl::LoadedPlugin> plugins = ztl::load_plugins_dir("data/plugins");

    int protocol;

    cout << "Choose protocol:\n";
    cout << "1. TCP\n";
    cout << "2. UDP\n";
    cout << "3. ICMP (ping)\n";
    cout << "4. TCP port range scan\n";
    cout << "5. Full scan (CIDR + OS fingerprint)\n";
    cout << "6. Start web UI (SSO via AGG One)\n";
    cout << "Protocol: ";
    cin >> protocol;

    if (protocol == 6)
    {
        webui::Config wc;
        return webui::run(wc, plugins);
    }

    string ip;
    int port = 0;

    cout << "IP or CIDR (e.g. 192.168.1.0/24): ";
    cin >> ip;

    bool looks_like_cidr = ip.find('/') != std::string::npos;

    if (!looks_like_cidr)
    {
        sockaddr_in ip_check{};
        bool is_raw_ip = inet_pton(AF_INET, ip.c_str(), &ip_check.sin_addr) == 1;

        if (!is_raw_ip)
        {
            cout << "Resolving " << ip << "...\n";

            auto resolved = dns::resolve(ip, 2000);

            if (!resolved)
            {
                cerr << "Could not resolve hostname: " << ip << "\n";
                return 1;
            }

            cout << "Resolved " << ip << " -> " << *resolved << "\n";
            ip = *resolved;
        }
    }

    if (protocol == 1 || protocol == 2)
    {
        cout << "Port: ";
        cin >> port;
    }

    if (protocol == 1)
    {
        transport::Tcp tcp;

        core::Port result = tcp.connect(ip, port);

        cout << "Port: " + to_string(result.number) + ", Protocol: " + core::to_string(result.protocol) + ", State: " + core::to_string(result.state) << endl;

        if (result.state != core::PortState::OPEN)
        {
            cerr << "TCP connection failed\n";
            return 1;
        }

        cout << "TCP connected!\n";

        if (!tcp.send("Hello from ZeroTrust!"))
        {
            cerr << "TCP send failed\n";
            return 1;
        }

        string response = tcp.receive();

        cout << "Received: " << response << '\n';

        processor::detect_service(result, response);

        cout << "Service: " + result.service + ", Product: " + result.product + ", Version: " + result.version << endl;
    }
    else if (protocol == 2)
    {
        transport::Udp udp;

        if (!udp.send(
            ip,
            port,
            {'H', 'e', 'l', 'l', 'o', ' ', 'f', 'r', 'o', 'm', ' ', 'Z', 'e', 'r', 'o', 'T', 'r', 'u', 's', 't', '!'}
        ))
        {
            cerr << "UDP send failed\n";
            return 1;
        }

        cout << "UDP packet sent!\n";
    }
    else if (protocol == 3)
    {
        transport::Icmp icmp;

        core::Host result = icmp.ping(ip, 2000);

        cout << "Host: " + result.ip + ", State: " + core::to_string(result.state) << endl;

        if (result.state != core::HostState::ALIVE)
        {
            cerr << "Host did not respond to ping\n";
            return 1;
        }

        cout << "Host is alive!\n";
    }
    else if (protocol == 4)
    {
        int start_port = 0;
        int end_port = 0;

        cout << "Start port: ";
        cin >> start_port;

        cout << "End port: ";
        cin >> end_port;

        auto result = scan::tcp_range_scan(ip, start_port, end_port, plugins);
        print_host_report(ip, "", "", 0, result.ports, result.findings);
    }
    else if (protocol == 5)
    {
        int start_port = 0;
        int end_port = 0;

        cout << "Start port: ";
        cin >> start_port;

        cout << "End port: ";
        cin >> end_port;

        std::vector<std::string> targets = util::expand_cidr(ip);

        if (targets.empty())
        {
            cerr << "No hosts to scan\n";
            return 1;
        }

        cout << "Scanning " << targets.size() << " host(s) on ports "
             << start_port << "-" << end_port << "\n\n";

        int ports_per_host = end_port - start_port + 1;
        int total_scans = static_cast<int>(targets.size()) * ports_per_host;

        progress::CliReporter reporter;
        reporter.begin("Full scan", total_scans);

        std::vector<core::Host> hosts;

        for (const std::string& target_ip : targets)
        {
            core::Host host;
            host.ip = target_ip;

            transport::Icmp icmp;
            core::Host ping_result = icmp.ping(target_ip, 1000);

            host.state    = ping_result.state;
            host.ttl      = ping_result.ttl;
            host.os_guess = util::guess_os_by_ttl(host.ttl);

            std::mutex host_mutex;
            core::KnowledgeBase kb;

            {
                concurrency::ThreadPool pool(50);

                for (int p = start_port; p <= end_port; p++)
                {
                    pool.enqueue([target_ip, p, &host, &host_mutex, &plugins, &kb, &reporter]()
                    {
                        struct TickOnExit {
                            progress::Reporter& r;
                            ~TickOnExit() { r.tick(); }
                        } tick_guard{reporter};

                        transport::Tcp tcp;
                        core::Port result = tcp.connect(target_ip, p, 1000);

                        if (result.state != core::PortState::OPEN) return;

                        std::string banner = tcp.receive(800);

                        if (banner.empty())
                        {
                            std::string http_request =
                                "GET / HTTP/1.0\r\n"
                                "Host: " + target_ip + "\r\n"
                                "Connection: close\r\n\r\n";

                            if (tcp.send(http_request))
                            {
                                banner = tcp.receive(800);
                            }
                        }

                        if (!banner.empty())
                        {
                            processor::detect_service(result, banner);
                            processor::detect_distro(result, banner);
                        }

                        std::vector<core::Finding> local_findings;

                        std::vector<core::Finding> native_findings = vuln::run_native_checks(result, target_ip, kb);
                        for (core::Finding& f : native_findings) local_findings.push_back(std::move(f));

                        {
                            ztl::DetectedInfo detected;
                            auto plugin_findings = ztl::run_for_port(plugins, target_ip, result.number, result.service, detected);
                            if (!detected.service.empty()) result.service = detected.service;
                            if (!detected.product.empty()) result.product = detected.product;
                            if (!detected.version.empty()) result.version = detected.version;
                            for (const auto& f : plugin_findings) {
                                core::Finding cf;
                                cf.plugin_name = f.plugin_name;
                                cf.title = f.title;
                                cf.description = f.description + (f.evidence.empty() ? "" : " | evidence: " + f.evidence);
                                cf.cve_id = f.cve_id;
                                cf.verification = f.verification;
                                cf.confidence_score = f.confidence_score;
                                cf.port_number = f.port_number;
                                cf.host = f.host;
                                cf.protocol = f.protocol;
                                cf.scope = f.scope;
                                cf.service = f.service;
                                cf.product = f.product;
                                cf.version = f.version;
                                cf.evidence = f.evidence;
                                cf.evidence_data = f.evidence_data;
                                cf.references = f.references;
                                cf.remediation = f.remediation;
                                cf.cvss_vector = f.cvss_vector;
                                cf.cvss = f.cvss;
                                cf.timestamp = f.timestamp;
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
                                local_findings.push_back(std::move(cf));
                            }
                        }

                        std::unordered_set<std::string> plugin_cves;
                        for (const core::Finding& f : local_findings) {
                            if (!f.cve_id.empty()) plugin_cves.insert(f.cve_id);
                        }
                        std::vector<core::Finding> cve_findings = vuln::check_port(result);
                        for (core::Finding& f : cve_findings) {
                            if (!plugin_cves.count(f.cve_id)) local_findings.push_back(std::move(f));
                        }

                        for (core::Finding& f : local_findings) {
                            if (f.host.empty()) f.host = target_ip;
                            if (f.protocol == core::Protocol::UNKNOWN) f.protocol = result.protocol;
                            if (f.service.empty()) f.service = result.service;
                            if (f.product.empty()) f.product = result.product;
                            if (f.version.empty()) f.version = result.version;
                        }
                        core::deduplicate_findings(local_findings);

                        std::lock_guard<std::mutex> lock(host_mutex);
                        host.ports.push_back(result);
                        for (const core::Finding& f : local_findings) host.findings.push_back(f);
                    });
                }
            }

            host.kb = kb.snapshot();

            std::sort(host.ports.begin(), host.ports.end(),
                [](const core::Port& a, const core::Port& b) { return a.number < b.number; });

            std::sort(host.findings.begin(), host.findings.end(),
                [](const core::Finding& a, const core::Finding& b) { return a.port_number < b.port_number; });
            core::deduplicate_findings(host.findings);

            print_host_report(target_ip, host.hostname, host.os_guess, host.ttl,
                              host.ports, host.findings);
            hosts.push_back(std::move(host));
        }

        reporter.end();

        cout << "\nDone.\n";
    }
    else
    {
        cerr << "Invalid protocol\n";
        return 1;
    }

    return 0;
}