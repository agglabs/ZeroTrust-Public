// finding.h

#pragma once

#include "severity.h"
#include "confidence.h"
#include "protocol.h"

#include <cstdint>
#include <chrono>
#include <string>
#include <unordered_map>
#include <vector>

namespace core {
    inline std::int64_t current_timestamp() {
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    enum class VerificationStatus {
        UNKNOWN,
        VERSION_MATCH,
        CONFIG_MATCH,
        ACTIVE_CHECK,
        NOT_VULNERABLE
    };

    inline std::string to_string(VerificationStatus status) {
        switch (status) {
            case VerificationStatus::UNKNOWN:          return "UNKNOWN";
            case VerificationStatus::VERSION_MATCH:   return "VERSION_MATCH";
            case VerificationStatus::CONFIG_MATCH:    return "CONFIG_MATCH";
            case VerificationStatus::ACTIVE_CHECK:   return "ACTIVE_CHECK";
            case VerificationStatus::NOT_VULNERABLE: return "NOT_VULNERABLE";
        }
        return "UNKNOWN";
    }

    inline VerificationStatus verification_status_from_string(const std::string& value) {
        if (value == "VERSION_MATCH")   return VerificationStatus::VERSION_MATCH;
        if (value == "CONFIG_MATCH")    return VerificationStatus::CONFIG_MATCH;
        if (value == "ACTIVE_CHECK")   return VerificationStatus::ACTIVE_CHECK;
        if (value == "NOT_VULNERABLE") return VerificationStatus::NOT_VULNERABLE;
        return VerificationStatus::UNKNOWN;
    }

    inline std::string verification_label(const std::string& verification) {
        if (verification == "VERSION_MATCH") return "Potentially vulnerable";
        if (verification == "CONFIG_MATCH") return "Configuration verified";
        if (verification == "ACTIVE_CHECK") return "Actively verified";
        if (verification == "NOT_VULNERABLE") return "Not vulnerable";
        return "Verification unknown";
    }

    inline int verification_rank(const std::string& verification) {
        if (verification == "ACTIVE_CHECK") return 3;
        if (verification == "CONFIG_MATCH") return 2;
        if (verification == "VERSION_MATCH") return 1;
        return 0;
    }

    struct Evidence {
        std::string type;
        std::string source;
        std::string value;
        std::string details;
    };

    struct Finding {
        std::string plugin_name;
        std::string title;

        Severity severity = Severity::INFO;
        Confidence confidence = Confidence::UNKNOWN;
        std::string verification = "UNKNOWN";
        double confidence_score = 0.0;

        std::string host;
        std::uint16_t port_number = 0;
        Protocol protocol = Protocol::UNKNOWN;
        std::string scope = "PORT";

        std::string service;
        std::string product;
        std::string version;

        std::string description;
        std::string evidence;
        Evidence evidence_data;
        std::vector<std::string> references;
        std::string remediation;
        std::string cvss_vector;
        double cvss = -1.0;
        std::string cve_id;
        std::int64_t timestamp = 0;
    };

    inline std::string finding_identity(const Finding& finding) {
        std::string id = finding.cve_id.empty()
            ? finding.plugin_name + "|" + finding.title
            : finding.cve_id;
        std::string key = finding.host + "|" + finding.scope + "|" +
                          to_string(finding.protocol) + "|";
        if (finding.scope != "HOST") key += std::to_string(finding.port_number) + "|";
        key += finding.service + "|" + id;
        return key;
    }

    inline void deduplicate_findings(std::vector<Finding>& findings) {
        std::vector<Finding> unique;
        std::unordered_map<std::string, std::size_t> positions;
        unique.reserve(findings.size());

        for (Finding& finding : findings) {
            std::string key = finding_identity(finding);
            auto existing = positions.find(key);
            if (existing == positions.end()) {
                positions.emplace(std::move(key), unique.size());
                unique.push_back(std::move(finding));
                continue;
            }

            Finding& current = unique[existing->second];
            bool better = verification_rank(finding.verification) > verification_rank(current.verification) ||
                          (verification_rank(finding.verification) == verification_rank(current.verification) &&
                           finding.confidence_score > current.confidence_score);
            if (better || current.evidence.empty()) {
                if (finding.evidence.empty()) finding.evidence = current.evidence;
                if (finding.description.empty()) finding.description = current.description;
                current = std::move(finding);
            }
        }

        findings = std::move(unique);
    }
}
