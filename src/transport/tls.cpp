// tls.cpp

#include "transport/tls.hpp"
#include "logging/logging.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <ctime>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace {
    std::string x509_name_to_string(X509_NAME* name) {
        if (!name) return "";

        char* buffer = X509_NAME_oneline(name, nullptr, 0);
        if (!buffer) return "";

        std::string out(buffer);
        OPENSSL_free(buffer);
        return out;
    }

    std::string asn1_time_to_string(const ASN1_TIME* time) {
        if (!time) return "";

        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) return "";

        ASN1_TIME_print(bio, time);

        char* data = nullptr;
        long len = BIO_get_mem_data(bio, &data);

        std::string out(data, len);
        BIO_free(bio);
        return out;
    }

    long days_between_now_and(const ASN1_TIME* target) {
        if (!target) return 0;

        int days = 0;
        int seconds = 0;
        ASN1_TIME_diff(&days, &seconds, nullptr, target);
        return days;
    }

    bool is_self_signed(X509* cert) {
        if (!cert) return false;
        return X509_NAME_cmp(X509_get_subject_name(cert), X509_get_issuer_name(cert)) == 0;
    }

    std::string signature_algorithm(X509* cert) {
        if (!cert) return "";

        const X509_ALGOR* algo = nullptr;
        X509_get0_signature(nullptr, &algo, cert);

        if (!algo) return "";

        const ASN1_OBJECT* obj = nullptr;
        X509_ALGOR_get0(&obj, nullptr, nullptr, algo);

        if (!obj) return "";

        char buffer[256] = { 0 };
        OBJ_obj2txt(buffer, sizeof(buffer), obj, 0);
        return buffer;
    }

    int connect_tcp(const std::string& ip, int port, int timeout_ms) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd == -1) return -1;

        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);

        if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
            close(fd);
            return -1;
        }

        if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            close(fd);
            return -1;
        }

        return fd;
    }

    transport::TlsCertificateInfo extract_cert_info(SSL* ssl) {
        transport::TlsCertificateInfo info;

        X509* cert = SSL_get_peer_certificate(ssl);
        if (!cert) return info;

        info.subject = x509_name_to_string(X509_get_subject_name(cert));
        info.issuer  = x509_name_to_string(X509_get_issuer_name(cert));

        const ASN1_TIME* not_before = X509_get0_notBefore(cert);
        const ASN1_TIME* not_after  = X509_get0_notAfter(cert);

        info.not_before = asn1_time_to_string(not_before);
        info.not_after  = asn1_time_to_string(not_after);

        info.days_until_expiry = days_between_now_and(not_after);
        info.expired = info.days_until_expiry < 0;

        info.self_signed = is_self_signed(cert);
        info.signature_algorithm = signature_algorithm(cert);

        X509_free(cert);
        return info;
    }
}

namespace transport {
    Tls::Tls() {
        SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());

        if (ctx) {
            SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
            SSL_CTX_set_min_proto_version(ctx, SSL3_VERSION);
            SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
            SSL_CTX_set_security_level(ctx, 0);
        }

        ssl_ctx = ctx;
    }

    Tls::~Tls() {
        if (ssl_ctx) {
            SSL_CTX_free(static_cast<SSL_CTX*>(ssl_ctx));
            ssl_ctx = nullptr;
        }
    }

    TlsHandshakeReport Tls::handshake(const std::string& ip, int port, int timeout_ms) {
        return handshake_with_ciphers(ip, port, "", timeout_ms);
    }

    TlsHandshakeReport Tls::handshake_with_ciphers(
        const std::string& ip,
        int port,
        const std::string& cipher_list,
        int timeout_ms
    ) {
        TlsHandshakeReport report;

        if (!ssl_ctx) {
            report.result = TlsHandshakeResult::UNKNOWN;
            return report;
        }

        int fd = connect_tcp(ip, port, timeout_ms);
        if (fd == -1) {
            report.result = TlsHandshakeResult::REFUSED;
            return report;
        }

        SSL* ssl = SSL_new(static_cast<SSL_CTX*>(ssl_ctx));
        if (!ssl) {
            close(fd);
            report.result = TlsHandshakeResult::UNKNOWN;
            return report;
        }

        if (!cipher_list.empty()) {
            SSL_set_cipher_list(ssl, cipher_list.c_str());
            SSL_set_ciphersuites(ssl, cipher_list.c_str());
        }

        SSL_set_fd(ssl, fd);
        SSL_set_tlsext_host_name(ssl, ip.c_str());

        int rc = SSL_connect(ssl);

        if (rc == 1) {
            report.result = TlsHandshakeResult::OK;
            report.protocol_version = SSL_get_version(ssl);

            const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl);
            if (cipher) {
                report.cipher_name = SSL_CIPHER_get_name(cipher);
            }

            report.certificate = extract_cert_info(ssl);
            report.certificate_present = !report.certificate.subject.empty();
        } else {
            int err = SSL_get_error(ssl, rc);
            if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL) {
                report.result = TlsHandshakeResult::NOT_TLS;
            } else {
                report.result = TlsHandshakeResult::HANDSHAKE_FAILED;
            }
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(fd);

        return report;
    }
}
