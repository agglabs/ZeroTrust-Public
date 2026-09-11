// terrapin.cpp

#include "vuln/terrapin.hpp"
#include "transport/tcp.hpp"

#include <algorithm>
#include <cstdint>
#include <sstream>
#include <vector>

namespace {
    struct KexInit {
        std::vector<std::string> kex_algorithms;
        std::vector<std::string> encryption_algorithms_s_to_c;
        std::vector<std::string> mac_algorithms_s_to_c;
    };

    std::vector<std::uint8_t> encode_uint32(std::uint32_t v) {
        return {
            static_cast<std::uint8_t>((v >> 24) & 0xff),
            static_cast<std::uint8_t>((v >> 16) & 0xff),
            static_cast<std::uint8_t>((v >>  8) & 0xff),
            static_cast<std::uint8_t>( v        & 0xff)
        };
    }

    void append_name_list(std::vector<std::uint8_t>& out, const std::string& list) {
        auto length = encode_uint32(static_cast<std::uint32_t>(list.size()));
        out.insert(out.end(), length.begin(), length.end());
        out.insert(out.end(), list.begin(), list.end());
    }

    std::vector<std::uint8_t> build_kexinit_payload() {
        std::vector<std::uint8_t> p;
        p.push_back(20);

        for (int i = 0; i < 16; i++) p.push_back(0);

        append_name_list(p, "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256");
        append_name_list(p, "ssh-ed25519,rsa-sha2-256,rsa-sha2-512,ecdsa-sha2-nistp256");
        append_name_list(p, "aes128-ctr,aes192-ctr,aes256-ctr");
        append_name_list(p, "aes128-ctr,aes192-ctr,aes256-ctr");
        append_name_list(p, "hmac-sha2-256,hmac-sha2-512");
        append_name_list(p, "hmac-sha2-256,hmac-sha2-512");
        append_name_list(p, "none");
        append_name_list(p, "none");
        append_name_list(p, "");
        append_name_list(p, "");
        p.push_back(0);

        auto reserved = encode_uint32(0);
        p.insert(p.end(), reserved.begin(), reserved.end());

        return p;
    }

    std::vector<std::uint8_t> frame_ssh_packet(const std::vector<std::uint8_t>& payload) {
        std::size_t base = 1 + payload.size();
        std::size_t pad_len = 8 - (base % 8);
        if (pad_len < 4) pad_len += 8;

        std::uint32_t packet_length = static_cast<std::uint32_t>(1 + payload.size() + pad_len);

        std::vector<std::uint8_t> out;
        auto length_bytes = encode_uint32(packet_length);
        out.insert(out.end(), length_bytes.begin(), length_bytes.end());
        out.push_back(static_cast<std::uint8_t>(pad_len));
        out.insert(out.end(), payload.begin(), payload.end());
        for (std::size_t i = 0; i < pad_len; i++) out.push_back(0);

        return out;
    }

    bool read_name_list(const std::string& raw, std::size_t& pos, std::size_t end, std::vector<std::string>& out) {
        if (pos + 4 > end) return false;

        std::uint32_t list_len =
            (static_cast<std::uint8_t>(raw[pos])     << 24) |
            (static_cast<std::uint8_t>(raw[pos + 1]) << 16) |
            (static_cast<std::uint8_t>(raw[pos + 2]) <<  8) |
             static_cast<std::uint8_t>(raw[pos + 3]);

        pos += 4;

        if (pos + list_len > end) return false;

        std::string list_str(raw.data() + pos, list_len);
        pos += list_len;

        std::stringstream ss(list_str);
        std::string item;
        while (std::getline(ss, item, ',')) {
            if (!item.empty()) out.push_back(item);
        }

        return true;
    }

    std::optional<KexInit> parse_kexinit(const std::string& raw) {
        if (raw.size() < 6) return std::nullopt;

        std::uint32_t packet_length =
            (static_cast<std::uint8_t>(raw[0]) << 24) |
            (static_cast<std::uint8_t>(raw[1]) << 16) |
            (static_cast<std::uint8_t>(raw[2]) <<  8) |
             static_cast<std::uint8_t>(raw[3]);

        std::uint8_t pad_len = static_cast<std::uint8_t>(raw[4]);

        if (raw.size() < 4 + packet_length) return std::nullopt;

        std::size_t payload_start = 5;
        std::size_t payload_end = 4 + packet_length - pad_len;

        if (payload_start >= payload_end) return std::nullopt;
        if (static_cast<std::uint8_t>(raw[payload_start]) != 20) return std::nullopt;

        std::size_t pos = payload_start + 17;

        KexInit ki;
        std::vector<std::string> discard;

        if (!read_name_list(raw, pos, payload_end, ki.kex_algorithms))              return std::nullopt;
        if (!read_name_list(raw, pos, payload_end, discard))                        return std::nullopt;
        if (!read_name_list(raw, pos, payload_end, discard))                        return std::nullopt;
        if (!read_name_list(raw, pos, payload_end, ki.encryption_algorithms_s_to_c))return std::nullopt;
        if (!read_name_list(raw, pos, payload_end, discard))                        return std::nullopt;
        if (!read_name_list(raw, pos, payload_end, ki.mac_algorithms_s_to_c))       return std::nullopt;

        return ki;
    }

    bool contains(const std::vector<std::string>& list, const std::string& needle) {
        return std::find(list.begin(), list.end(), needle) != list.end();
    }

    bool any_cbc(const std::vector<std::string>& ciphers) {
        for (const std::string& c : ciphers) {
            if (c.find("-cbc") != std::string::npos) return true;
        }
        return false;
    }

    bool any_etm(const std::vector<std::string>& macs) {
        for (const std::string& m : macs) {
            if (m.find("-etm@") != std::string::npos) return true;
        }
        return false;
    }

    std::string receive_at_least(transport::Tcp& tcp, std::size_t needed, int timeout_ms) {
        std::string buffer;

        while (buffer.size() < needed) {
            std::string chunk = tcp.receive(timeout_ms);
            if (chunk.empty()) break;
            buffer += chunk;
        }

        return buffer;
    }

    std::string strip_pre_kexinit_lines(const std::string& raw) {
        std::size_t pos = 0;

        while (pos < raw.size()) {
            if (pos + 4 <= raw.size()) {
                std::uint32_t plen =
                    (static_cast<std::uint8_t>(raw[pos])     << 24) |
                    (static_cast<std::uint8_t>(raw[pos + 1]) << 16) |
                    (static_cast<std::uint8_t>(raw[pos + 2]) <<  8) |
                     static_cast<std::uint8_t>(raw[pos + 3]);

                if (plen > 0 && plen < 65536 && pos + 4 + plen <= raw.size()) {
                    std::size_t payload_offset = pos + 5;
                    if (payload_offset < raw.size() &&
                        static_cast<std::uint8_t>(raw[payload_offset]) == 20) {
                        return raw.substr(pos);
                    }
                }
            }

            std::size_t newline = raw.find('\n', pos);
            if (newline == std::string::npos) break;
            pos = newline + 1;
        }

        return raw;
    }
}

namespace {
    std::string join_algorithms(const std::vector<std::string>& list) {
        std::string out;
        for (std::size_t i = 0; i < list.size(); i++) {
            if (i > 0) out += ",";
            out += list[i];
        }
        return out;
    }
}

namespace vuln {
    std::optional<core::Finding> check_terrapin(
        const core::Port& port,
        const std::string& target_ip,
        core::KnowledgeBase& kb
    ) {
        if (port.service != "ssh") return std::nullopt;

        transport::Tcp tcp;
        core::Port state = tcp.connect(target_ip, port.number, 3000);

        if (state.state != core::PortState::OPEN) return std::nullopt;

        std::string server_banner = tcp.receive(2000);
        if (server_banner.substr(0, 4) != "SSH-") return std::nullopt;

        if (!tcp.send("SSH-2.0-ZeroTrust_Scanner\r\n")) return std::nullopt;

        std::vector<std::uint8_t> kexinit_payload = build_kexinit_payload();
        std::vector<std::uint8_t> packet = frame_ssh_packet(kexinit_payload);

        std::string packet_str(packet.begin(), packet.end());
        if (!tcp.send(packet_str)) return std::nullopt;

        std::string response = receive_at_least(tcp, 5, 3000);
        if (response.size() < 5) return std::nullopt;

        std::string trimmed = strip_pre_kexinit_lines(response);

        if (trimmed.size() < 5) return std::nullopt;

        std::uint32_t packet_length =
            (static_cast<std::uint8_t>(trimmed[0]) << 24) |
            (static_cast<std::uint8_t>(trimmed[1]) << 16) |
            (static_cast<std::uint8_t>(trimmed[2]) <<  8) |
             static_cast<std::uint8_t>(trimmed[3]);

        std::size_t total_needed = 4 + packet_length;

        while (trimmed.size() < total_needed) {
            std::string more = tcp.receive(2000);
            if (more.empty()) break;
            trimmed += more;
        }

        auto ki = parse_kexinit(trimmed);
        if (!ki) return std::nullopt;

        std::string port_prefix = "port/" + std::to_string(port.number) + "/ssh/";
        kb.set(port_prefix + "kex_algorithms",             join_algorithms(ki->kex_algorithms));
        kb.set(port_prefix + "encryption_algorithms_s2c",  join_algorithms(ki->encryption_algorithms_s_to_c));
        kb.set(port_prefix + "mac_algorithms_s2c",         join_algorithms(ki->mac_algorithms_s_to_c));

        bool has_strict_kex   = contains(ki->kex_algorithms, "kex-strict-s-v00@openssh.com");
        bool has_chacha       = contains(ki->encryption_algorithms_s_to_c, "chacha20-poly1305@openssh.com");
        bool cbc_etm_vuln     = any_cbc(ki->encryption_algorithms_s_to_c) && any_etm(ki->mac_algorithms_s_to_c);

        if (has_strict_kex || (!has_chacha && !cbc_etm_vuln)) {
            return std::nullopt;
        }

        core::Finding f;
        f.plugin_name = "ssh-terrapin";
        f.title       = "SSH Terrapin Prefix Truncation Weakness";
        f.severity    = core::Severity::MEDIUM;
        f.confidence  = core::Confidence::VERIFIED;
        f.cve_id      = "CVE-2023-48795";
        f.port_number = port.number;
        f.service     = port.service;
        f.product     = port.product;
        f.version     = port.version;

        std::string evidence;
        if (has_chacha) evidence += "chacha20-poly1305@openssh.com supported; ";
        if (cbc_etm_vuln) evidence += "CBC ciphers combined with Encrypt-then-MAC supported; ";
        evidence += "kex-strict-s-v00@openssh.com NOT offered by server";

        f.description =
            "The SSH server supports algorithms vulnerable to the Terrapin prefix-truncation "
            "attack (chacha20-poly1305 or CBC-with-Encrypt-then-MAC) and does not advertise the "
            "strict key exchange countermeasure. Evidence: " + evidence +
            ". Update the SSH server or restrict the offered algorithms.";

        return f;
    }
}
