#include "udp.hpp"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <poll.h>

namespace transport {
    Udp::Udp()
    {
        socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    }

    Udp::~Udp()
    {
        if (socket_fd != -1)
        {
            close(socket_fd);
        }
    }

    bool Udp::bind(int port)
    {
        if (socket_fd == -1)
        {
            return false;
        }

        sockaddr_in address{};

        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_ANY);
        address.sin_port = htons(port);

        if (::bind(
            socket_fd,
            reinterpret_cast<sockaddr*>(&address),
            sizeof(address)
        ) < 0)
        {
            return false;
        }

        bound = true;
        return true;
    }

    bool Udp::send(const std::string& ip, int port, const std::vector<std::uint8_t>& data)
    {
        if (socket_fd == -1)
        {
            return false;
        }

        sockaddr_in address{};

        address.sin_family = AF_INET;
        address.sin_port = htons(port);

        if (inet_pton(
            AF_INET,
            ip.c_str(),
            &address.sin_addr
        ) != 1)
        {
            return false;
        }

        const ssize_t result = sendto(
            socket_fd,
            data.data(),
            data.size(),
            0,
            reinterpret_cast<sockaddr*>(&address),
            sizeof(address)
        );

        return result == static_cast<ssize_t>(data.size());
    }

    std::string Udp::receive(int timeout_ms) {
        if (socket_fd == -1) {
            return {};
        }

        pollfd pfd{};
        pfd.fd = socket_fd;
        pfd.events = POLLIN;

        int poll_result = poll(&pfd, 1, timeout_ms);

        if (poll_result <= 0) {
            return {};   
        }

        char buffer[4096];
        sockaddr_in sender{};
        socklen_t sender_length = sizeof(sender);

        const ssize_t received = recvfrom(
            socket_fd, buffer, sizeof(buffer), 0,
            reinterpret_cast<sockaddr*>(&sender), &sender_length
        );

        if (received < 0) {
            return {};
        }

        return std::string(buffer, static_cast<std::size_t>(received));
    }
};