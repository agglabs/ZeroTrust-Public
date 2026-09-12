// tls_checks.cpp

#include "protocols/tls/checks.hpp"
#include "transport/tls.hpp"

#include <string>

namespace {
    bool port_looks_like_tls(const core::Port& port) {
        std::uint16_t n = port.number;

        if (n == 443 || n == 465 || n == 636 || n == 989 || n == 990 ||
            n == 993 || n == 995 || n == 5061 || n == 8443)
        {
            return true;
        }

        return false;
    }

    core::Finding make_finding(
        const core::Port& port,
        const std::string& plugin_name,
        const std::string& title,
        core::Severity severity,
        const std::string& description
    ) {
        core::Finding f;
        f.plugin_name = plugin_name;
        f.title       = title;
        f.severity    = severity;
        f.confidence  = core::Confidence::VERIFIED;
        f.port_number = port.number;
        f.service     = port.service;
        f.product     = port.product;
        f.version     = port.version;
        f.description = description;
        return f;
    }

    std::optional<core::Finding> check_tls_supported(
        const core::Port& port,
        const transport::TlsHandshakeReport& handshake
    ) {
        std::string desc =
            "The service on this port accepts TLS connections. Protocol negotiated: " +
            handshake.protocol_version + ". Cipher: " + handshake.cipher_name + ".";

        return make_finding(
            port,
            "tls-supported",
            "TLS/SSL service detected on port " + std::to_string(port.number),
            core::Severity::INFO,
            desc
        );
    }

    std::optional<core::Finding> check_certificate_expired(
        const core::Port& port,
        const transport::TlsHandshakeReport& handshake
    ) {
        if (!handshake.certificate_present) return std::nullopt;
        if (!handshake.certificate.expired) return std::nullopt;

        std::string desc =
            "The X.509 certificate served by the TLS endpoint is expired. "
            "Subject: " + handshake.certificate.subject +
            ". Not After: " + handshake.certificate.not_after +
            ". Days since expiry: " + std::to_string(-handshake.certificate.days_until_expiry) + ".";

        return make_finding(
            port,
            "tls-cert-expired",
            "SSL Certificate Expired",
            core::Severity::HIGH,
            desc
        );
    }

    std::optional<core::Finding> check_certificate_self_signed(
        const core::Port& port,
        const transport::TlsHandshakeReport& handshake
    ) {
        if (!handshake.certificate_present) return std::nullopt;
        if (!handshake.certificate.self_signed) return std::nullopt;

        std::string desc =
            "The X.509 certificate served by the TLS endpoint is self-signed, meaning it is "
            "not issued by a trusted certificate authority. Clients will not be able to verify "
            "the identity of the server. Subject: " + handshake.certificate.subject + ".";

        return make_finding(
            port,
            "tls-cert-self-signed",
            "SSL Self-Signed Certificate",
            core::Severity::MEDIUM,
            desc
        );
    }

    std::optional<core::Finding> check_weak_signature(
        const core::Port& port,
        const transport::TlsHandshakeReport& handshake
    ) {
        if (!handshake.certificate_present) return std::nullopt;

        const std::string& sig = handshake.certificate.signature_algorithm;

        bool weak = false;
        std::string reason;

        if (sig.find("md5") != std::string::npos) {
            weak = true;
            reason = "MD5-based signature (broken hash)";
        } else if (sig.find("sha1") != std::string::npos || sig.find("sha-1") != std::string::npos) {
            weak = true;
            reason = "SHA-1 signature (deprecated, collision-vulnerable)";
        }

        if (!weak) return std::nullopt;

        std::string desc =
            "The X.509 certificate uses a weak signature algorithm: " + sig +
            " (" + reason + "). Modern trust stores reject or warn on such certificates.";

        return make_finding(
            port,
            "tls-cert-weak-signature",
            "SSL Certificate Signed With Weak Hash Algorithm",
            core::Severity::MEDIUM,
            desc
        );
    }

    std::optional<core::Finding> check_old_protocol(
        const core::Port& port,
        const transport::TlsHandshakeReport& handshake
    ) {
        const std::string& v = handshake.protocol_version;

        core::Severity sev = core::Severity::INFO;
        std::string reason;

        if (v == "SSLv3") {
            sev = core::Severity::HIGH;
            reason = "SSLv3 is broken (POODLE, CVE-2014-3566) and must be disabled";
        } else if (v == "TLSv1" || v == "TLSv1.0") {
            sev = core::Severity::MEDIUM;
            reason = "TLS 1.0 is deprecated (BEAST, RFC 8996) and must be disabled";
        } else if (v == "TLSv1.1") {
            sev = core::Severity::MEDIUM;
            reason = "TLS 1.1 is deprecated (RFC 8996) and must be disabled";
        } else {
            return std::nullopt;
        }

        std::string desc =
            "The server negotiated a deprecated TLS protocol version (" + v + "). " + reason + ".";

        return make_finding(
            port,
            "tls-old-protocol",
            "Deprecated TLS Protocol Version (" + v + ")",
            sev,
            desc
        );
    }

    bool cipher_is_anonymous(const std::string& name) {
        if (name.rfind("ADH-", 0) == 0)   return true;
        if (name.rfind("AECDH-", 0) == 0) return true;
        if (name.find("-ANON-") != std::string::npos) return true;
        return false;
    }

    bool cipher_is_null(const std::string& name) {
        if (name.find("-NULL-") != std::string::npos) return true;
        if (name.rfind("NULL-", 0) == 0) return true;
        if (name.find("-NULL") != std::string::npos &&
            name.find("-NULL@") == std::string::npos) return true;
        return false;
    }

    std::optional<core::Finding> check_anonymous_ciphers(
        const core::Port& port,
        const std::string& target_ip
    ) {
        transport::Tls tls;

        auto handshake = tls.handshake_with_ciphers(
            target_ip,
            port.number,
            "aNULL",
            3000
        );

        if (handshake.result != transport::TlsHandshakeResult::OK) return std::nullopt;
        if (!cipher_is_anonymous(handshake.cipher_name)) return std::nullopt;

        std::string desc =
            "The TLS server accepted an anonymous cipher suite (" + handshake.cipher_name +
            "). Anonymous ciphers offer no way to verify the server's identity and expose "
            "connections to man-in-the-middle attacks. Reconfigure the service to disable anonymous "
            "cipher suites (ADH / AECDH).";

        return make_finding(
            port,
            "tls-anonymous-ciphers",
            "SSL Anonymous Cipher Suites Supported",
            core::Severity::HIGH,
            desc
        );
    }

    std::optional<core::Finding> check_null_ciphers(
        const core::Port& port,
        const std::string& target_ip
    ) {
        transport::Tls tls;

        auto handshake = tls.handshake_with_ciphers(
            target_ip,
            port.number,
            "eNULL",
            3000
        );

        if (handshake.result != transport::TlsHandshakeResult::OK) return std::nullopt;
        if (!cipher_is_null(handshake.cipher_name)) return std::nullopt;

        std::string desc =
            "The TLS server accepted a NULL-encryption cipher suite (" + handshake.cipher_name +
            "). NULL ciphers provide integrity but no confidentiality — all data is sent in "
            "plain text over the wire. Disable NULL cipher suites (eNULL).";

        return make_finding(
            port,
            "tls-null-ciphers",
            "SSL NULL Cipher Suites Supported",
            core::Severity::CRITICAL,
            desc
        );
    }

    struct WeakCipherGroup {
        std::string openssl_expr;
        std::string finding_id;
        std::string title;
        core::Severity severity;
        std::string reason;
        std::string cipher_name_marker;
    };

    const std::vector<WeakCipherGroup>& weak_cipher_groups() {
        static const std::vector<WeakCipherGroup> groups = {
            {
                "RC4",
                "tls-rc4-supported",
                "SSL RC4 Cipher Suites Supported",
                core::Severity::HIGH,
                "RC4 has known biases that allow plaintext recovery (RFC 7465, CVE-2013-2566).",
                "RC4"
            },
            {
                "3DES",
                "tls-3des-supported",
                "SSL 3DES Cipher Suites Supported (Sweet32)",
                core::Severity::MEDIUM,
                "3DES uses a 64-bit block size and is vulnerable to birthday attacks on long sessions "
                "(Sweet32, CVE-2016-2183).",
                "3DES"
            },
            {
                "DES:!3DES",
                "tls-des-supported",
                "SSL DES Cipher Suites Supported",
                core::Severity::HIGH,
                "Single-DES uses a 56-bit key that is trivially brute-forced with modern hardware.",
                "-DES-"
            },
            {
                "EXPORT",
                "tls-export-supported",
                "SSL Export-Grade Cipher Suites Supported (FREAK/Logjam)",
                core::Severity::HIGH,
                "Export-grade ciphers use 40- or 56-bit keys and are broken by design (FREAK "
                "CVE-2015-0204, Logjam CVE-2015-4000).",
                "EXP"
            }
        };

        return groups;
    }

    std::optional<core::Finding> check_weak_cipher_group(
        const core::Port& port,
        const std::string& target_ip,
        const WeakCipherGroup& group
    ) {
        transport::Tls tls;

        auto handshake = tls.handshake_with_ciphers(
            target_ip,
            port.number,
            group.openssl_expr,
            3000
        );

        if (handshake.result != transport::TlsHandshakeResult::OK) return std::nullopt;
        if (handshake.cipher_name.find(group.cipher_name_marker) == std::string::npos) return std::nullopt;

        std::string desc =
            "The TLS server accepted a weak cipher suite (" + handshake.cipher_name +
            "). " + group.reason + " Disable this cipher category on the server.";

        return make_finding(
            port,
            group.finding_id,
            group.title,
            group.severity,
            desc
        );
    }
}

namespace vuln {
    std::vector<core::Finding> run_tls_checks(
        const core::Port& port,
        const std::string& target_ip,
        core::KnowledgeBase& kb
    ) {
        std::vector<core::Finding> findings;

        if (!port_looks_like_tls(port)) return findings;

        transport::Tls tls;
        auto handshake = tls.handshake(target_ip, port.number, 3000);

        if (handshake.result != transport::TlsHandshakeResult::OK) return findings;

        std::string port_prefix = "port/" + std::to_string(port.number) + "/tls/";
        kb.set(port_prefix + "protocol_version", handshake.protocol_version);
        kb.set(port_prefix + "cipher",           handshake.cipher_name);

        if (handshake.certificate_present) {
            kb.set(port_prefix + "cert_subject",    handshake.certificate.subject);
            kb.set(port_prefix + "cert_issuer",     handshake.certificate.issuer);
            kb.set(port_prefix + "cert_not_after",  handshake.certificate.not_after);
            kb.set(port_prefix + "cert_signature_algorithm", handshake.certificate.signature_algorithm);
            kb.set(port_prefix + "cert_self_signed", handshake.certificate.self_signed ? "true" : "false");
            kb.set(port_prefix + "cert_expired",     handshake.certificate.expired ? "true" : "false");
        }

        if (auto f = check_tls_supported(port, handshake))            findings.push_back(*f);
        if (auto f = check_certificate_expired(port, handshake))      findings.push_back(*f);
        if (auto f = check_certificate_self_signed(port, handshake))  findings.push_back(*f);
        if (auto f = check_weak_signature(port, handshake))            findings.push_back(*f);
        if (auto f = check_old_protocol(port, handshake))              findings.push_back(*f);
        if (auto f = check_anonymous_ciphers(port, target_ip))         findings.push_back(*f);
        if (auto f = check_null_ciphers(port, target_ip))              findings.push_back(*f);

        for (const WeakCipherGroup& group : weak_cipher_groups()) {
            if (auto f = check_weak_cipher_group(port, target_ip, group)) {
                findings.push_back(*f);
            }
        }

        return findings;
    }
}
