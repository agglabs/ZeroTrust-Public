// tcp.cpp

#pragma once

#include <string>

#include "port.h"

namespace transport {
    class Tcp {
        private: 
            int socket_fd = -1;
        public: 
            Tcp();
            ~Tcp();

            core::Port connect(const std::string& ip, int port, int timeout_ms = 2000);
            bool send(const std::string& data);
            std::string receive(int timeout_ms = 2000);
    };
}