// resolver.cpp

#include "resolver.hpp"

#include <vector>
#include <string>
#include <optional>
#include <arpa/inet.h>
#include "transport/udp.hpp"
#include <cstring>
#include <cstdlib>

namespace {
    #pragma pack(push, 1)
    struct DnsHeader {
        std::uint16_t id;
        std::uint16_t flags;
        std::uint16_t qdcount;
        std::uint16_t ancount;
        std::uint16_t nscount;
        std::uint16_t arcount;
    };
    #pragma pack(pop)

    std::vector<std::uint8_t> encode_hostname(const std::string& hostname) {
        std::vector<std::uint8_t> encoded;

        std::size_t start = 0;

        while (start < hostname.size()) {
            std::size_t dot = hostname.find('.', start);
            if (dot == std::string::npos) {
                dot = hostname.size();
            }

            std::uint8_t label_length = static_cast<std::uint8_t>(dot - start);
            encoded.push_back(label_length);

            for (std::size_t i = start; i < dot; i++) {
                encoded.push_back(static_cast<std::uint8_t>(hostname[i]));
            }

            start = dot + 1;
        }

        encoded.push_back(0);

        return encoded;
    }

    std::vector<std::uint8_t> build_query(const std::string& hostname, std::uint16_t query_id) {
        DnsHeader header{};
        header.id = htons(query_id);
        header.flags = htons(0x0100);
        header.qdcount = htons(1);
        header.ancount = htons(0);
        header.nscount = htons(0);
        header.arcount = htons(0);

        std::vector<std::uint8_t> packet;

        const std::uint8_t* header_bytes = reinterpret_cast<const std::uint8_t*>(&header);
        packet.insert(packet.end(), header_bytes, header_bytes + sizeof(header));

        std::vector<std::uint8_t> encoded_name = encode_hostname(hostname);
        packet.insert(packet.end(), encoded_name.begin(), encoded_name.end());

        std::uint16_t qtype = htons(1);
        std::uint16_t qclass = htons(1);

        const std::uint8_t* qtype_bytes = reinterpret_cast<const std::uint8_t*>(&qtype);
        packet.insert(packet.end(), qtype_bytes, qtype_bytes + sizeof(qtype));

        const std::uint8_t* qclass_bytes = reinterpret_cast<const std::uint8_t*>(&qclass);
        packet.insert(packet.end(), qclass_bytes, qclass_bytes + sizeof(qclass));

        return packet;
    }

    std::size_t skip_name(const std::vector<std::uint8_t>& data, std::size_t offset) {
        while (offset < data.size()) {
            std::uint8_t len = data[offset];

            if ((len & 0xC0) == 0xC0) {
                return offset + 2;
            }
            if (len == 0) {
                return offset + 1;
            }

            offset += 1 + len;
        }

        return offset;
    }
}

namespace dns {
    std::optional<std::string> resolve(const std::string& hostname, int timeout_ms) {
        transport::Udp udp;

        std::uint16_t query_id = static_cast<std::uint16_t>(rand() % 65536);
        std::vector<std::uint8_t> query = build_query(hostname, query_id);
        
        if (!udp.send("8.8.8.8", 53, query)) {
            return std::nullopt;
        }

        std::string raw_response = udp.receive(timeout_ms);
        if (raw_response.empty()) {
            return std::nullopt;
        }

        std::vector<std::uint8_t> response(raw_response.begin(), raw_response.end());
        
        if (response.size() < sizeof(DnsHeader)) {
            return std::nullopt;
        }

        DnsHeader header;
        std::memcpy(&header, response.data(), sizeof(header));

        std::uint16_t ancount = ntohs(header.ancount);
        if (ancount == 0) {
            return std::nullopt;
        }

        std::size_t offset = sizeof(DnsHeader);
        offset = skip_name(response, offset);
        offset += 4;

        for (std::uint16_t i = 0; i < ancount; i++) {
            offset = skip_name(response, offset);
            
            if (offset + 10 > response.size()) {
                return std::nullopt;
            }

            std::uint16_t type;
            std::memcpy(&type, response.data() + offset, 2);
            type = ntohs(type);

            std::uint16_t rdlength;
            std::memcpy(&rdlength, response.data() + offset + 8, 2);
            rdlength = ntohs(rdlength);

            offset += 10;

            if (type == 1 && rdlength == 4) {
                char ip_str[INET_ADDRSTRLEN];
                in_addr addr;
                std::memcpy(&addr, response.data() + offset, 4);
                inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));

                return std::string(ip_str);
            }

            offset += rdlength;
        }

        return std::nullopt;
    }
}