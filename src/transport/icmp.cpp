// icmp.cpp

#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "icmp.hpp"

namespace {
    #pragma pack(push, 1)
    struct IcmpHeader {
        std::uint8_t  type;
        std::uint8_t  code;
        std::uint16_t checksum;
        std::uint16_t identifier;
        std::uint16_t sequence;
    };
    #pragma pack(pop)

    std::uint16_t calculate_checksum(void* data, std::size_t length) {
        std::uint16_t* buf = reinterpret_cast<std::uint16_t*>(data);
        std::uint32_t sum = 0;

        while (length > 1) {
            sum += *buf++;
            length -= 2;
        }
        if (length == 1) {
            sum += *reinterpret_cast<std::uint8_t*>(buf);
        }

        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return static_cast<std::uint16_t>(~sum);
    }
}

namespace transport {
    Icmp::Icmp() {
        socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    }

    Icmp::~Icmp() {
        if (socket_fd != -1) {
            close(socket_fd);
        }  
    }

    core::Host Icmp::ping(const std::string& ip, int timeout_ms) {
        core::Host result;
        result.ip = ip;

        if (socket_fd == -1) {
            result.state = core::HostState::UNKNOWN;
            return result;
        }

        sockaddr_in address{};
        address.sin_family = AF_INET;
        if (inet_pton(AF_INET, ip.c_str(), &address.sin_addr) != 1) {
            result.state = core::HostState::UNKNOWN;
            return result;
        }

        IcmpHeader header{};
        header.type = 8;                               
        header.code = 0;
        header.checksum = 0;                         
        header.identifier = static_cast<std::uint16_t>(getpid());
        header.sequence = 1;

        header.checksum = calculate_checksum(&header, sizeof(header));

        ssize_t sent = sendto(
            socket_fd,
            &header,
            sizeof(header),
            0,
            reinterpret_cast<sockaddr*>(&address),
            sizeof(address)
        );

        if (sent != sizeof(header)) {
            result.state = core::HostState::UNKNOWN;
            return result;
        }

        pollfd pfd{};
        pfd.fd = socket_fd;
        pfd.events = POLLIN;

        int poll_result = poll(&pfd, 1, timeout_ms);

        if (poll_result == 0) {
            result.state = core::HostState::UNREACHABLE;  
            return result;
        }
        if (poll_result < 0) {
            result.state = core::HostState::UNKNOWN;
            return result;
        }

        char buffer[1024];
        ssize_t received = recvfrom(socket_fd, buffer, sizeof(buffer), 0, nullptr, nullptr);

        if (received <= 0) {
            result.state = core::HostState::UNREACHABLE;
            return result;
        }

        std::uint8_t ip_header_length = (buffer[0] & 0x0F) * 4;
        std::uint8_t ttl = static_cast<std::uint8_t>(buffer[8]);

        if (static_cast<std::size_t>(received) < ip_header_length + sizeof(IcmpHeader)) {
            result.state = core::HostState::UNKNOWN;
            return result;
        }

        IcmpHeader* reply = reinterpret_cast<IcmpHeader*>(buffer + ip_header_length);

        if (reply->type == 0 && reply->identifier == header.identifier) {
            result.state = core::HostState::ALIVE;
            result.ttl = ttl;
        } else {
            result.state = core::HostState::UNKNOWN;
        }

        return result;
    }
}