#pragma once

#include <string>
#include <vector>

namespace transport {
    class Udp {
        private:
            int socket_fd = -1;
            bool bound = false;

        public:
            Udp();
            ~Udp();

            Udp(const Udp&) = delete;
            Udp& operator=(const Udp&) = delete;

            bool bind(int port);

            bool send(const std::string& ip, int port, const std::vector<std::uint8_t>& data);

            std::string receive(int timeout_ms);
    };
}