// store.hpp

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace feed {
    struct CveEntry {
        std::string cve_id;
        std::string product;
        std::string version_min;
        std::string version_max;
        std::string severity;
        std::string description;
    };

    struct ProbeEntry {
        std::string service;
        std::string pattern;
        std::string flags;
        std::string source;
    };

    class Store {
    public:
        void load_cve_file(const std::string& path);
        void load_probe_file(const std::string& path, const std::string& source_tag);

        const std::vector<CveEntry>&  cves() const { return cves_; }
        const std::vector<ProbeEntry>& probes() const { return probes_; }

        std::optional<CveEntry> find_cve(const std::string& cve_id) const;
        std::vector<CveEntry>   search_cves(const std::string& product, const std::string& version) const;

    private:
        std::vector<CveEntry> cves_;
        std::vector<ProbeEntry> probes_;
    };
}
