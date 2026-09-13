// vuln.cpp

#include "scan/cve.hpp"
#include "protocols/ssh/terrapin.hpp"
#include "protocols/tls/checks.hpp"
#include "logging/logging.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <functional>
#include <sstream>
#include <unordered_map>

namespace {
    struct CveEntry {
        std::string cve_id;
        std::string product;
        std::string version_min;
        std::string version_max;
        core::Severity severity = core::Severity::MEDIUM;
        std::string description;
        double cvss = -1.0;
        std::string cvss_vector;
        std::string remediation;
        std::vector<std::string> references;
    };

    std::vector<CveEntry> cve_database;

    // Distro backport info harvested by tools/cve_sync.py from Ubuntu / Debian
    // security trackers. When present, we can turn a raw VERSION_MATCH hit into
    // a NOT_VULNERABLE finding for hosts running an OS whose package version
    // already contains the upstream fix.
    struct DistroFix {
        std::string cve;
        std::string distro;         // "ubuntu" | "debian"
        std::string release;        // "22.04", "12", "sid", ...
        std::string package;
        std::string fixed_version;  // e.g. "1:8.9p1-3ubuntu0.10"; empty for statuses like not-affected
        std::string status;         // "released", "not-affected", ...
    };

    std::vector<DistroFix> distro_fix_table;
    // cve+distro key → indexes into distro_fix_table.
    std::unordered_map<std::string, std::vector<std::size_t>> distro_fix_index;

    // ---- dpkg version comparison (Debian policy §5.6.12) ----
    //
    // Enough of dpkg --compare-versions to make sense of packages we see in
    // OpenSSH/nginx banners like "1:8.9p1-3ubuntu0.17" vs "1:8.9p1-3ubuntu0.10".
    // Full reference: manpage of deb-version(5).

    int dpkg_char_order(char c) {
        // '~' ranks below everything else, including the empty string,
        // then digits/letters/non-alphas in dpkg's specific order.
        if (c == '\0') return 0;
        if (c == '~') return -1;
        if (std::isalpha(static_cast<unsigned char>(c))) return c;
        return c + 256;
    }

    int dpkg_compare_str(const std::string& a, const std::string& b) {
        // Alternate non-digit and digit segments. Non-digit segments compare
        // character-by-character under dpkg_char_order. Digit segments compare
        // numerically (leading zeros ignored).
        std::size_t i = 0, j = 0;
        while (i < a.size() || j < b.size()) {
            // non-digit run
            while (i < a.size() || j < b.size()) {
                char ca = i < a.size() && !std::isdigit(static_cast<unsigned char>(a[i])) ? a[i] : '\0';
                char cb = j < b.size() && !std::isdigit(static_cast<unsigned char>(b[j])) ? b[j] : '\0';
                if (ca == '\0' && cb == '\0') break;
                int oa = dpkg_char_order(ca);
                int ob = dpkg_char_order(cb);
                if (oa != ob) return oa < ob ? -1 : 1;
                if (ca != '\0') i++;
                if (cb != '\0') j++;
            }
            // digit run
            while (i < a.size() && a[i] == '0') i++;
            while (j < b.size() && b[j] == '0') j++;
            std::size_t da = 0, db = 0;
            while (i + da < a.size() && std::isdigit(static_cast<unsigned char>(a[i + da]))) da++;
            while (j + db < b.size() && std::isdigit(static_cast<unsigned char>(b[j + db]))) db++;
            if (da != db) return da < db ? -1 : 1;
            for (std::size_t k = 0; k < da; k++) {
                if (a[i + k] != b[j + k]) return a[i + k] < b[j + k] ? -1 : 1;
            }
            i += da; j += db;
        }
        return 0;
    }

    struct DpkgVersion {
        std::string epoch;      // "" if absent (interpreted as "0")
        std::string upstream;
        std::string revision;   // "" if absent
    };

    DpkgVersion parse_dpkg_version(const std::string& raw) {
        DpkgVersion v;
        std::string rest = raw;
        auto colon = rest.find(':');
        if (colon != std::string::npos) {
            bool all_digits = colon > 0;
            for (std::size_t k = 0; k < colon; k++) {
                if (!std::isdigit(static_cast<unsigned char>(rest[k]))) { all_digits = false; break; }
            }
            if (all_digits) {
                v.epoch = rest.substr(0, colon);
                rest = rest.substr(colon + 1);
            }
        }
        auto dash = rest.rfind('-');
        if (dash != std::string::npos) {
            v.upstream = rest.substr(0, dash);
            v.revision = rest.substr(dash + 1);
        } else {
            v.upstream = rest;
        }
        return v;
    }

    [[maybe_unused]] int dpkg_compare(const std::string& a, const std::string& b) {
        DpkgVersion va = parse_dpkg_version(a);
        DpkgVersion vb = parse_dpkg_version(b);
        std::string ea = va.epoch.empty() ? "0" : va.epoch;
        std::string eb = vb.epoch.empty() ? "0" : vb.epoch;
        if (int c = dpkg_compare_str(ea, eb); c != 0) return c;
        if (int c = dpkg_compare_str(va.upstream, vb.upstream); c != 0) return c;
        return dpkg_compare_str(va.revision, vb.revision);
    }

    std::string distro_fix_key(const std::string& cve, const std::string& distro) {
        std::string out = cve;
        out += '|';
        for (char c : distro) out += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return out;
    }

    // Try to derive (distro, package_revision) from port.distro.
    // Values like "Ubuntu (Ubuntu-3ubuntu0.17)" become distro="ubuntu",
    // revision="3ubuntu0.17". Everything else returns two empty strings.
    struct DistroTag {
        std::string distro;
        std::string revision;
    };
    DistroTag parse_distro_tag(const std::string& tag) {
        DistroTag out;
        std::string lower = tag;
        for (auto& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if      (lower.find("ubuntu") != std::string::npos) out.distro = "ubuntu";
        else if (lower.find("debian") != std::string::npos) out.distro = "debian";
        else return out;

        // capture text inside the last "(...)" and strip a leading
        // "Ubuntu-" / "Debian-" marker.
        auto open = tag.rfind('(');
        auto close = tag.rfind(')');
        if (open == std::string::npos || close == std::string::npos || close <= open + 1) return out;
        std::string inside = tag.substr(open + 1, close - open - 1);
        auto strip = [](std::string s, const char* prefix) {
            std::size_t n = std::strlen(prefix);
            if (s.size() >= n && s.compare(0, n, prefix) == 0) return s.substr(n);
            return s;
        };
        inside = strip(inside, "Ubuntu-");
        inside = strip(inside, "Debian-");
        out.revision = inside;
        return out;
    }

    struct BackportOutcome {
        bool patched = false;             // installed >= a released fix for this CVE
        bool release_not_affected = false; // some Ubuntu/Debian release marks this CVE as not-affected
        std::string via;                   // human-readable evidence ("ubuntu 22.04: 1:8.9p1-3ubuntu0.10")
    };

    // Given the port and a CVE we already matched by upstream range, decide
    // whether the installed distro package is actually already patched.
    // Strategy: for each `released` fix row on the port's distro, compare
    // installed upstream+revision to the fix. If upstream matches exactly and
    // installed revision >= fix revision (per dpkg rules), we're patched.
    BackportOutcome check_backport(const std::string& cve_id, const core::Port& port) {
        BackportOutcome result;
        if (port.version.empty() || port.distro.empty()) return result;
        DistroTag tag = parse_distro_tag(port.distro);
        if (tag.distro.empty() || tag.revision.empty()) return result;

        std::string installed_full = port.version + "-" + tag.revision;

        auto it = distro_fix_index.find(distro_fix_key(cve_id, tag.distro));
        if (it == distro_fix_index.end()) return result;

        for (std::size_t idx : it->second) {
            const DistroFix& fix = distro_fix_table[idx];
            if (fix.status == "not-affected") {
                result.release_not_affected = true;
                continue;
            }
            // Ubuntu tracker uses "released", Debian tracker uses "resolved"
            // (and occasionally "fixed"). Anything with a concrete fix version
            // means a distro shipped a patch we can compare against.
            bool has_fix = fix.status == "released" || fix.status == "resolved" || fix.status == "fixed";
            if (!has_fix || fix.fixed_version.empty()) continue;

            DpkgVersion fv = parse_dpkg_version(fix.fixed_version);
            DpkgVersion iv = parse_dpkg_version(installed_full);
            if (dpkg_compare_str(fv.upstream, iv.upstream) != 0) continue;
            if (dpkg_compare_str(iv.revision, fv.revision) < 0) continue;

            result.patched = true;
            result.via = tag.distro + " " + fix.release + ": " + fix.package + " " + fix.fixed_version;
            return result;
        }
        return result;
    }

    std::string to_lower(const std::string& s) {
        std::string out = s;
        std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return out;
    }

    std::vector<std::string> split_by_tab(const std::string& line) {
        std::vector<std::string> fields;
        std::istringstream stream(line);
        std::string field;

        while (std::getline(stream, field, '\t')) {
            fields.push_back(field);
        }

        return fields;
    }

    core::Severity parse_severity(const std::string& s) {
        if (s == "INFO")     return core::Severity::INFO;
        if (s == "LOW")      return core::Severity::LOW;
        if (s == "MEDIUM")   return core::Severity::MEDIUM;
        if (s == "HIGH")     return core::Severity::HIGH;
        if (s == "CRITICAL") return core::Severity::CRITICAL;
        return core::Severity::MEDIUM;
    }

    double parse_cvss(const std::string& value) {
        if (value.empty() || value == "*") return -1.0;
        try { return std::stod(value); } catch (...) { return -1.0; }
    }

    std::vector<std::string> split_references(const std::string& value) {
        std::vector<std::string> references;
        std::istringstream stream(value);
        std::string reference;
        while (std::getline(stream, reference, '|')) {
            if (!reference.empty()) references.push_back(reference);
        }
        return references;
    }

    bool product_matches(const std::string& db_product, const std::string& port_product) {
        return to_lower(db_product) == to_lower(port_product);
    }
}

namespace vuln {
    Version VersionMatcher::parse(const std::string& raw) {
        Version version;
        version.raw = raw;

        std::size_t start = 0;
        while (start < raw.size() && !std::isdigit(static_cast<unsigned char>(raw[start]))) start++;

        std::size_t cursor = start;
        while (cursor < raw.size()) {
            if (!std::isdigit(static_cast<unsigned char>(raw[cursor]))) break;
            std::size_t end = cursor;
            while (end < raw.size() && std::isdigit(static_cast<unsigned char>(raw[end]))) end++;
            try {
                version.components.push_back(std::stoi(raw.substr(cursor, end - cursor)));
            } catch (...) {
                version.components.clear();
                return version;
            }
            if (end >= raw.size() || raw[end] != '.') break;
            cursor = end + 1;
        }

        return version;
    }

    int VersionMatcher::compare(const Version& left, const Version& right) {
        std::size_t count = std::max(left.components.size(), right.components.size());
        for (std::size_t i = 0; i < count; i++) {
            int left_part = i < left.components.size() ? left.components[i] : 0;
            int right_part = i < right.components.size() ? right.components[i] : 0;
            if (left_part != right_part) return left_part < right_part ? -1 : 1;
        }
        return 0;
    }

    bool VersionMatcher::in_range(const std::string& version, const VersionRange& range) {
        Version parsed = parse(version);
        if (parsed.components.empty()) return false;
        if (range.minimum != "*" && compare(parsed, parse(range.minimum)) < 0) return false;
        if (range.maximum != "*" && compare(parsed, parse(range.maximum)) > 0) return false;
        return true;
    }

    void load_distro_fixes(const std::string& path) {
        std::ifstream file(path);
        if (!file.is_open()) {
            logging::warn("Distro fix table not found (backport awareness disabled): " + path);
            return;
        }
        distro_fix_table.clear();
        distro_fix_index.clear();

        std::string line;
        int loaded = 0;
        while (std::getline(file, line)) {
            if (line.empty() || line[0] == '#') continue;
            auto fields = split_by_tab(line);
            if (fields.size() < 6) continue;   // cve, distro, release, package, fixed_version, status[, source_url]

            DistroFix fix;
            fix.cve           = fields[0];
            fix.distro        = to_lower(fields[1]);
            fix.release       = fields[2];
            fix.package       = fields[3];
            fix.fixed_version = fields[4];
            fix.status        = to_lower(fields[5]);

            distro_fix_table.push_back(std::move(fix));
            const DistroFix& stored = distro_fix_table.back();
            distro_fix_index[distro_fix_key(stored.cve, stored.distro)].push_back(distro_fix_table.size() - 1);
            loaded++;
        }
        logging::info("Loaded " + std::to_string(loaded) + " distro backport rows from " + path);
    }

    void load_database(const std::string& path) {

        std::ifstream file(path);

        if (!file.is_open()) {
            logging::error("Unable to open CVE database at " + path);
            return;
        }

        std::string line;
        int loaded = 0;

        while (std::getline(file, line)) {
            if (line.empty() || line[0] == '#') continue;

            std::vector<std::string> fields = split_by_tab(line);

            if (fields.size() < 6) {
                logging::warn("Invalid CVE line: " + line);
                continue;
            }

            CveEntry entry;
            entry.cve_id      = fields[0];
            entry.product     = fields[1];
            entry.version_min = fields[2];
            entry.version_max = fields[3];
            entry.severity    = parse_severity(fields[4]);
            entry.description = fields[5];
            if (fields.size() > 6) entry.cvss = parse_cvss(fields[6]);
            if (fields.size() > 7) entry.cvss_vector = fields[7];
            if (fields.size() > 8) entry.remediation = fields[8];
            if (fields.size() > 9) entry.references = split_references(fields[9]);

            cve_database.push_back(std::move(entry));
            loaded++;
        }

        logging::info("Loaded " + std::to_string(loaded) + " CVE entries from " + path);
    }

    std::string lookup(const std::string& product, const std::string& version) {
        std::string out;
        if (product.empty() || version.empty()) return out;
        for (const CveEntry& entry : cve_database) {
            if (!product_matches(entry.product, product)) continue;
            if (!VersionMatcher::in_range(version, {entry.version_min, entry.version_max})) continue;
            if (!out.empty()) out += ", ";
            out += entry.cve_id;
        }
        return out;
    }

    std::optional<CveMatch> match(const std::string& cve_id,
                                  const std::string& product,
                                  const std::string& version) {
        if (product.empty() || version.empty()) return std::nullopt;

        for (const CveEntry& entry : cve_database) {
            if (!cve_id.empty() && entry.cve_id != cve_id) continue;
            if (!product_matches(entry.product, product)) continue;
            if (!VersionMatcher::in_range(version, {entry.version_min, entry.version_max})) continue;

            CveMatch result;
            result.cve_id = entry.cve_id;
            result.product = product;
            result.version = version;
            result.severity = core::to_string(entry.severity);
            result.description = entry.description;
            result.cvss = entry.cvss;
            result.cvss_vector = entry.cvss_vector;
            result.remediation = entry.remediation;
            result.references = entry.references;
            return result;
        }

        return std::nullopt;
    }

    VerificationResult verify_version(const std::string& cve_id,
                                      const std::string& product,
                                      const std::string& version) {
        VerificationResult result;
        result.cve = cve_id;
        result.verification = "UNKNOWN";

        if (product.empty() || version.empty()) return result;

        auto found = match(cve_id, product, version);
        if (!found) {
            result.verification = "NOT_VULNERABLE";
            return result;
        }

        result.vulnerable = true;
        result.cve = found->cve_id;
        result.severity = found->severity;
        result.title = found->cve_id + ": " + found->description;
        result.description = found->description;
        result.evidence = found->product + " " + found->version;
        result.evidence_data = {"version", "cve-database", result.evidence, found->description};
        result.cvss = found->cvss;
        result.cvss_vector = found->cvss_vector;
        result.remediation = found->remediation;
        result.references = found->references;
        result.confidence = 0.5;
        result.verification = "VERSION_MATCH";
        return result;
    }

    std::vector<core::Finding> check_port(const core::Port& port) {
        std::vector<core::Finding> findings;

        if (port.product.empty() || port.version.empty()) {
            return findings;
        }

        for (const CveEntry& entry : cve_database) {
            if (!product_matches(entry.product, port.product)) continue;
            if (!VersionMatcher::in_range(port.version, {entry.version_min, entry.version_max})) continue;

            BackportOutcome backport = check_backport(entry.cve_id, port);

            core::Finding f;
            f.plugin_name = "cve-database";
            f.cve_id      = entry.cve_id;
            f.title       = entry.cve_id + ": " + entry.description;
            f.severity    = entry.severity;
            f.timestamp   = core::current_timestamp();
            f.port_number = port.number;
            f.service     = port.service;
            f.product     = port.product;
            f.version     = port.version;
            f.protocol    = port.protocol;
            f.scope       = "PORT";
            f.evidence    = port.product + " " + port.version;
            f.evidence_data = {"version", "cve-database", f.evidence, entry.description};
            f.cvss = entry.cvss;
            f.cvss_vector = entry.cvss_vector;
            f.remediation = entry.remediation;
            f.references = entry.references;

            if (backport.patched) {
                // Distro shipped a fix and the installed package is at or beyond
                // it. Downgrade the finding — the box is already patched.
                f.severity = core::Severity::INFO;
                f.confidence = core::Confidence::VERIFIED;
                f.confidence_score = 0.9;
                f.verification = "NOT_VULNERABLE";
                f.title = entry.cve_id + ": already patched by " + backport.via;
                f.description = "Upstream version " + port.version + " matches CVE range, "
                    "but the installed distro package appears to include the backport fix: " +
                    backport.via + ". Marking as NOT_VULNERABLE. Verify manually if the target "
                    "is high-value.";
                f.evidence_data = {"backport", "distro-fix-table", backport.via, entry.description};
            } else {
                f.confidence = core::Confidence::VERSION_MATCH;
                f.confidence_score = 0.5;
                f.verification = "VERSION_MATCH";

                std::string caveat =
                    "This finding is based on version comparison only and has not been verified "
                    "against actual server behavior.";

                if (!port.distro.empty()) {
                    caveat +=
                        " Distribution tag detected (" + port.distro +
                        ") which commonly backports security fixes without changing the upstream "
                        "version string. Confirm against the distribution security tracker before "
                        "treating this as exploitable.";
                }

                f.description = entry.description + " " + caveat;
            }

            findings.push_back(std::move(f));
        }

        return findings;
    }

    std::vector<core::Finding> run_native_checks(
        const core::Port& port,
        const std::string& target_ip,
        core::KnowledgeBase& kb
    ) {
        using NativeCheck = std::function<std::optional<core::Finding>(const core::Port&, const std::string&, core::KnowledgeBase&)>;

        struct RegisteredCheck {
            std::string service;
            NativeCheck fn;
        };

        static const std::vector<RegisteredCheck> registry = {
            { "ssh", check_terrapin }
        };

        std::vector<core::Finding> findings;

        for (const RegisteredCheck& entry : registry) {
            if (!entry.service.empty() && entry.service != port.service) continue;

            auto f = entry.fn(port, target_ip, kb);
            if (f) findings.push_back(*f);
        }

        std::vector<core::Finding> tls_findings = run_tls_checks(port, target_ip, kb);
        for (core::Finding& f : tls_findings) {
            findings.push_back(std::move(f));
        }

        return findings;
    }
}
