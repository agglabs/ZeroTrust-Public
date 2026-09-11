// icmp.hpp

#pragma once

#include <string>
#include "host.h"

namespace transport {
    class Icmp {
        private:
            int socket_fd = -1;

        public:
            Icmp();
            ~Icmp();

            Icmp(const Icmp&) = delete;
            Icmp& operator=(const Icmp&) = delete;

            core::Host ping(const std::string& ip, int timeout_ms);
    };
}