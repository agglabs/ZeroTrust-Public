// cidr.cpp

#include "scan/cidr.hpp"
#include "logging/logging.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>

#include <cstdint>

namespace {
    constexpr std::uint32_t MAX_HOSTS = 65536;
}

namespace util {
    std::vector<std::string> expand_cidr(const std::string& input) {
        std::vector<std::string> hosts;

        auto slash = input.find('/');

        if (slash == std::string::npos) {
            hosts.push_back(input);
            return hosts;
        }

        std::string base   = input.substr(0, slash);
        std::string prefix = input.substr(slash + 1);

        int prefix_len = 0;
        try {
            prefix_len = std::stoi(prefix);
        } catch (...) {
            logging::error("Invalid CIDR prefix: " + prefix);
            return hosts;
        }

        if (prefix_len < 0 || prefix_len > 32) {
            logging::error("CIDR prefix out of range (0-32): " + prefix);
            return hosts;
        }

        in_addr addr{};
        if (inet_pton(AF_INET, base.c_str(), &addr) != 1) {
            logging::error("Invalid IPv4 base address: " + base);
            return hosts;
        }

        std::uint32_t base_ip = ntohl(addr.s_addr);
        std::uint32_t mask    = (prefix_len == 0) ? 0u : (~0u << (32 - prefix_len));
        std::uint32_t network = base_ip & mask;

        std::uint64_t count = (prefix_len == 32) ? 1ull : (1ull << (32 - prefix_len));

        if (count > MAX_HOSTS) {
            logging::warn(
                "CIDR expansion capped: " + input +
                " would produce " + std::to_string(count) +
                " hosts, limiting to " + std::to_string(MAX_HOSTS)
            );
            count = MAX_HOSTS;
        }

        hosts.reserve(static_cast<std::size_t>(count));

        for (std::uint64_t i = 0; i < count; i++) {
            std::uint32_t ip = network + static_cast<std::uint32_t>(i);

            in_addr a{};
            a.s_addr = htonl(ip);

            char buf[INET_ADDRSTRLEN] = { 0 };
            inet_ntop(AF_INET, &a, buf, sizeof(buf));
            hosts.emplace_back(buf);
        }

        return hosts;
    }
}
