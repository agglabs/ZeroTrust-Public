#include "transport/tcp.hpp"
#include "transport/udp.hpp"
#include "transport/icmp.hpp"
#include "processor/processor.hpp"
#include "protocols/dns/resolver.hpp"
#include "processor/thread_pool.hpp"
#include "ztl/runner.hpp"
#include "scan/cve.hpp"
#include "core/knowledge_base.hpp"
#include "scan/reporter.hpp"
#include "scan/cidr.hpp"
#include "protocols/tcp/os_fingerprint.hpp"
#include "port.h"
#include "host.h"
#include "finding.h"

#include <iostream>
#include <string>
#include <vector>
#include <mutex>
#include <algorithm>
#include <cctype>
#include <arpa/inet.h>

using namespace std;

int main()
{
    processor::load_patterns("data/zt-service-probes.txt");
    processor::load_patterns("data/zt-service-probes-nmap.txt");

    vuln::load_database("data/zt-cve-database.txt");
    vuln::load_database("data/zt-cve-database-nvd.txt");

    const std::vector<ztl::LoadedPlugin> plugins = ztl::load_plugins_dir("data/plugins");

    int protocol;

    cout << "Choose protocol:\n";
    cout << "1. TCP\n";
    cout << "2. UDP\n";
    cout << "3. ICMP (ping)\n";
    cout << "4. TCP port range scan\n";
    cout << "5. Full scan (CIDR + OS fingerprint)\n";
    cout << "Protocol: ";
    cin >> protocol;

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

        std::mutex results_mutex;
        std::vector<core::Port> open_ports;
        std::vector<core::Finding> findings;
        core::KnowledgeBase kb;

        {
            concurrency::ThreadPool pool(50);

            for (int p = start_port; p <= end_port; p++)
            {
                pool.enqueue([ip, p, &open_ports, &findings, &results_mutex, &plugins, &kb]()
                {
                    transport::Tcp tcp;
                    core::Port result = tcp.connect(ip, p, 1000);

                    if (result.state == core::PortState::OPEN)
                    {
                        std::string banner = tcp.receive(800);

                        if (banner.empty())
                        {
                            std::string http_request =
                                "GET / HTTP/1.0\r\n"
                                "Host: " + ip + "\r\n"
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

                        if (result.service.empty())
                        {
                            // swiezie polaczenie - to na ktorym probowalismy
                            // HTTP moglo zostac "zepsute" przez ta probe
                            transport::Tcp probe_tcp;
                            core::Port probe_check = probe_tcp.connect(ip, p, 1000);

                            if (probe_check.state == core::PortState::OPEN)
                            {
                                processor::try_active_probe(probe_tcp, result);
                            }
                        }

                        std::vector<core::Finding> local_findings;

                        std::vector<core::Finding> native_findings = vuln::run_native_checks(result, ip, kb);
                        for (core::Finding& f : native_findings) local_findings.push_back(std::move(f));

                        {
                            std::string detected_svc;
                            auto plugin_findings = ztl::run_for_port(plugins, ip, result.number, result.service, detected_svc);
                            if (result.service.empty() && !detected_svc.empty()) result.service = detected_svc;
                            for (const auto& f : plugin_findings) {
                                core::Finding cf;
                                cf.plugin_name = f.plugin_name;
                                cf.title = f.title;
                                cf.description = f.description + (f.evidence.empty() ? "" : " | evidence: " + f.evidence);
                                cf.port_number = f.port_number;
                                cf.service = f.service;
                                std::string sev = f.severity;
                                for (auto& c : sev) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
                                if      (sev == "CRITICAL") cf.severity = core::Severity::CRITICAL;
                                else if (sev == "HIGH")     cf.severity = core::Severity::HIGH;
                                else if (sev == "MEDIUM")   cf.severity = core::Severity::MEDIUM;
                                else if (sev == "LOW")      cf.severity = core::Severity::LOW;
                                else                        cf.severity = core::Severity::INFO;
                                if      (f.confidence >= 0.9) cf.confidence = core::Confidence::VERIFIED;
                                else if (f.confidence >= 0.5) cf.confidence = core::Confidence::VERSION_MATCH;
                                else                          cf.confidence = core::Confidence::UNKNOWN;
                                local_findings.push_back(std::move(cf));
                            }
                        }

                        std::vector<core::Finding> cve_findings = vuln::check_port(result);
                        for (core::Finding& f : cve_findings) local_findings.push_back(std::move(f));

                        std::lock_guard<std::mutex> lock(results_mutex);
                        open_ports.push_back(result);

                        for (const core::Finding& f : local_findings)
                        {
                            findings.push_back(f);
                        }
                    }
                });
            }
        }

        std::sort(open_ports.begin(), open_ports.end(), [](const core::Port& a, const core::Port& b)
        {
            return a.number < b.number;
        });

        cout << "\nOpen ports (" << open_ports.size() << "):\n";

        for (const core::Port& p : open_ports)
        {
            cout << "  " << p.number << "/tcp  OPEN";

            if (!p.service.empty())
            {
                cout << "  " << p.service;

                if (!p.product.empty())
                {
                    cout << "  " << p.product;

                    if (!p.version.empty())
                    {
                        cout << " " << p.version;
                    }
                }

                if (!p.distro.empty())
                {
                    cout << "  [" << p.distro << "]";
                }
            }

            cout << "\n";
        }

        std::sort(findings.begin(), findings.end(), [](const core::Finding& a, const core::Finding& b)
        {
            return a.port_number < b.port_number;
        });

        cout << "\nFindings (" << findings.size() << "):\n";

        for (const core::Finding& f : findings)
        {
            cout << "  [" << core::to_string(f.severity)
                 << "] [" << core::to_string(f.confidence) << "] "
                 << f.title
                 << " (port " << f.port_number << "/tcp";

            if (!f.product.empty())
            {
                cout << ", " << f.product;

                if (!f.version.empty())
                {
                    cout << " " << f.version;
                }
            }

            cout << ")\n";

            if (!f.description.empty())
            {
                cout << "      " << f.description << "\n";
            }
        }
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

                        if (result.service.empty())
                        {
                            transport::Tcp probe_tcp;
                            core::Port probe_check = probe_tcp.connect(target_ip, p, 1000);

                            if (probe_check.state == core::PortState::OPEN)
                            {
                                processor::try_active_probe(probe_tcp, result);
                            }
                        }

                        std::vector<core::Finding> local_findings;

                        std::vector<core::Finding> native_findings = vuln::run_native_checks(result, target_ip, kb);
                        for (core::Finding& f : native_findings) local_findings.push_back(std::move(f));

                        {
                            std::string detected_svc;
                            auto plugin_findings = ztl::run_for_port(plugins, target_ip, result.number, result.service, detected_svc);
                            if (result.service.empty() && !detected_svc.empty()) result.service = detected_svc;
                            for (const auto& f : plugin_findings) {
                                core::Finding cf;
                                cf.plugin_name = f.plugin_name;
                                cf.title = f.title;
                                cf.description = f.description + (f.evidence.empty() ? "" : " | evidence: " + f.evidence);
                                cf.port_number = f.port_number;
                                cf.service = f.service;
                                std::string sev = f.severity;
                                for (auto& c : sev) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
                                if      (sev == "CRITICAL") cf.severity = core::Severity::CRITICAL;
                                else if (sev == "HIGH")     cf.severity = core::Severity::HIGH;
                                else if (sev == "MEDIUM")   cf.severity = core::Severity::MEDIUM;
                                else if (sev == "LOW")      cf.severity = core::Severity::LOW;
                                else                        cf.severity = core::Severity::INFO;
                                if      (f.confidence >= 0.9) cf.confidence = core::Confidence::VERIFIED;
                                else if (f.confidence >= 0.5) cf.confidence = core::Confidence::VERSION_MATCH;
                                else                          cf.confidence = core::Confidence::UNKNOWN;
                                local_findings.push_back(std::move(cf));
                            }
                        }

                        std::vector<core::Finding> cve_findings = vuln::check_port(result);
                        for (core::Finding& f : cve_findings) local_findings.push_back(std::move(f));

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

            cout << "Host " << target_ip;
            if (!host.os_guess.empty()) cout << " [" << host.os_guess << ", ttl=" << host.ttl << "]";
            cout << " - " << host.ports.size() << " open ports, "
                 << host.findings.size() << " findings\n";

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