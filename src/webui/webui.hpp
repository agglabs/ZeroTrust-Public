// webui.hpp

#pragma once

#include "ztl/runner.hpp"

#include <string>
#include <vector>

namespace webui {
    struct Config {
        std::string listen_host  = "127.0.0.1";
        int         listen_port  = 8344;
        std::string public_host  = "localhost";
        std::string public_url   = "http://localhost:8344";

        std::string client_id     = "23712557077-nnpfbtqte5qypaercy2b79cz4g3bp1fg.apps.agglabs.com";
        std::string redirect_uri  = "http://localhost:8344/callback";
        std::string scopes        = "openid profile email";

        std::string issuer        = "https://one.agglabs.com";
        std::string authorize_url = "https://one.agglabs.com/consent";
        std::string token_host    = "https://gate.one.agglabs.com";
        std::string token_path    = "/token";
        std::string userinfo_path = "/userinfo";

        int session_ttl_s = 3600;
    };

    // Runs the HTTP server until it fails to bind or is interrupted.
    int run(const Config& cfg, const std::vector<ztl::LoadedPlugin>& plugins,
            const std::string& db_path = "data/zerotrust.db");
}
