// delta.cpp

#include "report/delta.hpp"

#include <iostream>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace {
    struct FindingKey {
        std::string plugin_name;
        std::uint16_t port_number;
        std::string cve_id;
        std::string title;

        bool operator<(const FindingKey& o) const {
            if (plugin_name != o.plugin_name) return plugin_name < o.plugin_name;
            if (port_number != o.port_number) return port_number < o.port_number;
            if (cve_id != o.cve_id)           return cve_id < o.cve_id;
            return title < o.title;
        }
    };

    FindingKey key_of(const core::Finding& f) {
        return { f.plugin_name, f.port_number, f.cve_id, f.title };
    }

    std::map<std::string, const core::Host*> index_by_ip(const std::vector<core::Host>& hosts) {
        std::map<std::string, const core::Host*> out;
        for (const core::Host& h : hosts) out[h.ip] = &h;
        return out;
    }

    void print_host_changes(const core::Host& before, const core::Host& after) {
        std::map<std::uint16_t, const core::Port*> before_ports;
        std::map<std::uint16_t, const core::Port*> after_ports;
        for (const core::Port& p : before.ports) before_ports[p.number] = &p;
        for (const core::Port& p : after.ports)  after_ports[p.number]  = &p;

        std::vector<const core::Port*> new_ports, closed_ports;

        for (const auto& [num, p] : after_ports) {
            if (before_ports.find(num) == before_ports.end()) new_ports.push_back(p);
        }
        for (const auto& [num, p] : before_ports) {
            if (after_ports.find(num) == after_ports.end()) closed_ports.push_back(p);
        }

        std::map<FindingKey, const core::Finding*> before_findings;
        std::map<FindingKey, const core::Finding*> after_findings;
        for (const core::Finding& f : before.findings) before_findings[key_of(f)] = &f;
        for (const core::Finding& f : after.findings)  after_findings[key_of(f)]  = &f;

        std::vector<const core::Finding*> new_findings, resolved_findings;
        for (const auto& [k, f] : after_findings) {
            if (before_findings.find(k) == before_findings.end()) new_findings.push_back(f);
        }
        for (const auto& [k, f] : before_findings) {
            if (after_findings.find(k) == after_findings.end()) resolved_findings.push_back(f);
        }

        if (new_ports.empty() && closed_ports.empty() &&
            new_findings.empty() && resolved_findings.empty()) return;

        std::cout << "\nHost " << after.ip << ":\n";

        if (!new_ports.empty()) {
            std::cout << "  NEW PORTS (" << new_ports.size() << "):\n";
            for (const core::Port* p : new_ports) {
                std::cout << "    + " << p->number << "/tcp";
                if (!p->service.empty()) std::cout << "  " << p->service;
                if (!p->product.empty()) std::cout << "  " << p->product;
                if (!p->version.empty()) std::cout << " " << p->version;
                std::cout << "\n";
            }
        }

        if (!closed_ports.empty()) {
            std::cout << "  CLOSED PORTS (" << closed_ports.size() << "):\n";
            for (const core::Port* p : closed_ports) {
                std::cout << "    - " << p->number << "/tcp";
                if (!p->service.empty()) std::cout << "  " << p->service;
                std::cout << "\n";
            }
        }

        if (!new_findings.empty()) {
            std::cout << "  NEW FINDINGS (" << new_findings.size() << "):\n";
            for (const core::Finding* f : new_findings) {
                std::cout << "    + [" << core::to_string(f->severity)
                          << "] [" << core::to_string(f->confidence) << "] "
                          << f->title << " (port " << f->port_number << ")\n";
            }
        }

        if (!resolved_findings.empty()) {
            std::cout << "  RESOLVED FINDINGS (" << resolved_findings.size() << "):\n";
            for (const core::Finding* f : resolved_findings) {
                std::cout << "    - [" << core::to_string(f->severity) << "] "
                          << f->title << " (port " << f->port_number << ")\n";
            }
        }
    }
}

namespace report {
    void print_delta(const ScanReport& before, const ScanReport& after) {
        std::cout << "Delta between:\n";
        std::cout << "  BEFORE: " << before.target << " scanned at " << before.scanned_at << "\n";
        std::cout << "  AFTER:  " << after.target  << " scanned at " << after.scanned_at  << "\n";

        auto before_by_ip = index_by_ip(before.hosts);
        auto after_by_ip  = index_by_ip(after.hosts);

        std::vector<const core::Host*> new_hosts, removed_hosts, common_hosts;

        for (const auto& [ip, h] : after_by_ip) {
            if (before_by_ip.find(ip) == before_by_ip.end()) new_hosts.push_back(h);
            else                                              common_hosts.push_back(h);
        }
        for (const auto& [ip, h] : before_by_ip) {
            if (after_by_ip.find(ip) == after_by_ip.end()) removed_hosts.push_back(h);
        }

        if (!new_hosts.empty()) {
            std::cout << "\nNEW HOSTS (" << new_hosts.size() << "):\n";
            for (const core::Host* h : new_hosts) {
                std::cout << "  + " << h->ip;
                if (!h->os_guess.empty()) std::cout << " [" << h->os_guess << "]";
                std::cout << " - " << h->ports.size() << " open ports, "
                          << h->findings.size() << " findings\n";
            }
        }

        if (!removed_hosts.empty()) {
            std::cout << "\nREMOVED HOSTS (" << removed_hosts.size() << "):\n";
            for (const core::Host* h : removed_hosts) {
                std::cout << "  - " << h->ip << "\n";
            }
        }

        for (const core::Host* after_h : common_hosts) {
            const core::Host* before_h = before_by_ip[after_h->ip];
            print_host_changes(*before_h, *after_h);
        }

        if (new_hosts.empty() && removed_hosts.empty() && common_hosts.empty()) {
            std::cout << "\nNo changes detected.\n";
        }
    }
}
