// tls.hpp

#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace transport {
    enum class TlsHandshakeResult {
        UNKNOWN,
        OK,
        REFUSED,
        TIMEOUT,
        NOT_TLS,
        HANDSHAKE_FAILED
    };

    struct TlsCertificateInfo {
        std::string subject;
        std::string issuer;
        std::string not_before;
        std::string not_after;
        std::string signature_algorithm;
        bool self_signed = false;
        bool expired = false;
        long days_until_expiry = 0;
    };

    struct TlsHandshakeReport {
        TlsHandshakeResult result = TlsHandshakeResult::UNKNOWN;
        std::string protocol_version;
        std::string cipher_name;

        TlsCertificateInfo certificate;
        bool certificate_present = false;

        std::vector<std::string> accepted_ciphers;
    };

    class Tls {
    public:
        Tls();
        ~Tls();

        Tls(const Tls&) = delete;
        Tls& operator=(const Tls&) = delete;

        TlsHandshakeReport handshake(const std::string& ip, int port, int timeout_ms = 3000);

        TlsHandshakeReport handshake_with_ciphers(
            const std::string& ip,
            int port,
            const std::string& cipher_list,
            int timeout_ms = 3000
        );

    private:
        void* ssl_ctx = nullptr;
    };
}
