// tcp.cpp

#include "tcp.hpp"
#include "port.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <cerrno>

namespace {
    bool set_nonblocking(int fd) {
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags == -1) {
            return false;
        }
        return fcntl(fd, F_SETFL, flags | O_NONBLOCK) != -1;
    }

    bool set_blocking(int fd) {
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags == -1) {
            return false;
        }
        return fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) != -1;
    }
}

namespace transport {
    Tcp::Tcp() 
    {
        socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    }

    Tcp::~Tcp()
    {
        if (socket_fd != -1)
        {
            close(socket_fd);
        }
    }

    core::Port Tcp::connect(const std::string& ip, int port, int timeout_ms)
    {
        core::Port result;

        result.number = static_cast<std::uint16_t>(port);
        result.protocol = core::Protocol::TCP;

        if (socket_fd == -1) {
            result.state = core::PortState::UNKNOWN;
            return result;
        }

        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(port);

        if (inet_pton(AF_INET, ip.c_str(), &address.sin_addr) <= 0) {
            result.state = core::PortState::UNKNOWN;
            return result;
        }

        if (!set_nonblocking(socket_fd)) {
            result.state = core::PortState::UNKNOWN;
            return result;
        }

        int rc = ::connect(
            socket_fd,
            reinterpret_cast<sockaddr*>(&address),
            sizeof(address)
        );

        if (rc == 0) {
            result.state = core::PortState::OPEN;
            set_blocking(socket_fd);
            return result;
        }

        if (errno != EINPROGRESS) {
            result.state = (errno == ECONNREFUSED)
                ? core::PortState::CLOSED
                : core::PortState::FILTERED;
            set_blocking(socket_fd);
            return result;
        }

        pollfd pfd{};
        pfd.fd = socket_fd;
        pfd.events = POLLOUT;

        int poll_result = poll(&pfd, 1, timeout_ms);

        if (poll_result == 0) {
            result.state = core::PortState::FILTERED;
            set_blocking(socket_fd);
            return result;
        }
        if (poll_result < 0) {
            result.state = core::PortState::UNKNOWN;
            set_blocking(socket_fd);
            return result;
        }

        int socket_error = 0;
        socklen_t len = sizeof(socket_error);
        getsockopt(socket_fd, SOL_SOCKET, SO_ERROR, &socket_error, &len);

        if (socket_error == 0) {
            result.state = core::PortState::OPEN;
        } else if (socket_error == ECONNREFUSED) {
            result.state = core::PortState::CLOSED;
        } else {
            result.state = core::PortState::FILTERED;
        }

        set_blocking(socket_fd);
        return result;
    }

    bool Tcp::send(const std::string& data)
    {
        if (socket_fd == -1) return false;

        std::size_t sent = 0;
        while (sent < data.size()) {
            ssize_t result = ::send(
                socket_fd,
                data.data() + sent,
                data.size() - sent,
                0
            );

            if (result > 0) {
                sent += static_cast<std::size_t>(result);
                continue;
            }
            if (result < 0 && errno == EINTR) continue;
            return false;
        }

        return true;
    }

    std::string Tcp::receive(int timeout_ms)
    {
        pollfd pfd{};
        pfd.fd = socket_fd;
        pfd.events = POLLIN;

        int poll_result = poll(&pfd, 1, timeout_ms);

        if (poll_result <= 0)
        {
            return {};
        }

        char buffer[4096];

        ssize_t bytes_received = ::recv(
            socket_fd,
            buffer,
            sizeof(buffer),
            0
        );

        if (bytes_received <= 0)
        {
            return {};
        }

        return std::string(buffer, bytes_received);
    }
}