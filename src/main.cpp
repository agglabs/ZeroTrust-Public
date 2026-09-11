#include "transport/tcp.hpp"
#include "transport/udp.hpp"
#include "transport/icmp.hpp"
#include "processor/processor.hpp"
#include "protocols/dns/resolver.hpp"
#include "concurrency/thread_pool.hpp"
#include "ztl/interpreter.hpp"
#include "ztl/parser.hpp"
#include "vuln/vuln.hpp"
#include "core/knowledge_base.hpp"
#include "progress/reporter.hpp"
#include "import/nmap_probes.hpp"
#include "import/nvd.hpp"
#include "util/cidr.hpp"
#include "util/os_fingerprint.hpp"
#include "report/json_writer.hpp"
#include "report/reader.hpp"
#include "report/delta.hpp"
#include "port.h"
#include "host.h"
#include "finding.h"

#include <iostream>
#include <string>
#include <vector>
#include <mutex>
#include <algorithm>
#include <arpa/inet.h>

using namespace std;

int main()
{
    processor::load_patterns("data/zt-service-probes.txt");
    processor::load_patterns("data/zt-service-probes-nmap.txt");

    vuln::load_database("data/zt-cve-database.txt");
    vuln::load_database("data/zt-cve-database-nvd.txt");

    const std::vector<ztl::Plugin> plugins = ztl::load_plugins_from_dir("data/plugins");

    int protocol;

    cout << "Choose protocol:\n";
    cout << "1. TCP\n";
    cout << "2. UDP\n";
    cout << "3. ICMP (ping)\n";
    cout << "4. TCP port range scan\n";
    cout << "5. Full scan (CIDR + OS fingerprint + JSON report)\n";
    cout << "6. Compare two scan reports (delta)\n";
    cout << "7. Import external databases (nmap probes / NVD JSON)\n";
    cout << "Protocol: ";
    cin >> protocol;

    if (protocol == 7)
    {
        int subchoice = 0;
        cout << "  1. Import nmap-service-probes\n";
        cout << "  2. Import NVD JSON feed\n";
        cout << "  Choice: ";
        cin >> subchoice;

        cin.ignore(1024, '\n');

        if (subchoice == 1)
        {
            std::string src;
            cout << "  Source path (default /opt/homebrew/share/nmap/nmap-service-probes): ";
            std::getline(cin, src);
            if (src.empty()) src = "/opt/homebrew/share/nmap/nmap-service-probes";

            import_data::import_nmap_probes(src, "data/zt-service-probes-nmap.txt");
        }
        else if (subchoice == 2)
        {
            std::string src;
            cout << "  NVD JSON file path: ";
            std::getline(cin, src);
            if (src.empty()) {
                cerr << "  No path provided\n";
                return 1;
            }

            import_data::import_nvd(src, "data/zt-cve-database-nvd.txt");
        }
        else
        {
            cerr << "Invalid choice\n";
            return 1;
        }

        return 0;
    }

    if (protocol == 6)
    {
        std::string before_path;
        std::string after_path;

        cout << "Path to BEFORE scan.json: ";
        cin >> before_path;

        cout << "Path to AFTER  scan.json: ";
        cin >> after_path;

        auto before = report::read_scan_report(before_path);
        auto after  = report::read_scan_report(after_path);

        if (!before || !after) return 1;

        report::print_delta(*before, *after);
        return 0;
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

                        for (const ztl::Plugin& plugin : plugins)
                        {
                            auto f = ztl::execute(plugin, result, ip, kb);
                            if (f) local_findings.push_back(*f);
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

                        for (const ztl::Plugin& plugin : plugins)
                        {
                            auto f = ztl::execute(plugin, result, target_ip, kb);
                            if (f) local_findings.push_back(*f);
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

        report::write_json_report("scan.json", ip, hosts);

        cout << "\nDone. JSON report: scan.json\n";
    }
    else
    {
        cerr << "Invalid protocol\n";
        return 1;
    }

    return 0;
}