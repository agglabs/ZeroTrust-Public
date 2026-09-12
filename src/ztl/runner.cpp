// runner.cpp

#include "ztl/runner.hpp"

#include "ztl/interpreter.hpp"
#include "ztl/lexer.hpp"
#include "ztl/parser.hpp"
#include "transport/tcp.hpp"

#include <cctype>
#include <dirent.h>
#include <fstream>
#include <memory>
#include <sstream>
#include <sys/stat.h>

namespace ztl {
    struct KbShared {
        std::unordered_map<std::string, Value> data;
    };
}

namespace {
    using namespace ztl;

    // ---------- helpers ----------

    std::shared_ptr<NativeFn> nfn(const std::string& name, NativeCallback cb) {
        auto p = std::make_shared<NativeFn>();
        p->name = name;
        p->fn = std::move(cb);
        return p;
    }

    Value opt_named(CallContext& ctx, const std::string& key, Value fallback = Value{std::monostate{}}) {
        auto it = ctx.named.find(key);
        if (it != ctx.named.end()) return it->second;
        return fallback;
    }

    std::string need_string(const Value& v, const std::string& what, int line, int col) {
        if (auto s = as_string(v)) return *s;
        throw RuntimeError(what + " must be a string (got " + type_name_of(v) + ")", line, col);
    }

    int need_int(const Value& v, const std::string& what, int line, int col) {
        if (auto n = as_number(v)) return static_cast<int>(*n);
        throw RuntimeError(what + " must be a number (got " + type_name_of(v) + ")", line, col);
    }

    std::string lower(std::string s) {
        for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return s;
    }

    std::string trim(const std::string& s) {
        std::size_t a = 0, b = s.size();
        while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) a++;
        while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) b--;
        return s.substr(a, b - a);
    }

    // ---------- per-run state ----------

    struct RunState {
        PluginMeta meta;
        std::vector<FindingOut> findings;
        std::string target_host;
        int target_port = 0;
        std::string known_service;
        std::string set_service;
        bool meta_only = false;
        ztl::KbSharedPtr kb;
    };

    // ---------- Header / Response objects ----------

    std::shared_ptr<Object> make_header_obj(bool exists, const std::string& value) {
        auto o = std::make_shared<Object>();
        o->type_name = "Header";
        o->fields["_exists"] = Value{exists};
        o->fields["_value"] = Value{value};
        o->methods["exists"] = nfn("Header.exists", [](CallContext& c) -> Value {
            auto self = as_object(c.self);
            return self->fields["_exists"];
        });
        o->methods["value"] = nfn("Header.value", [](CallContext& c) -> Value {
            auto self = as_object(c.self);
            return self->fields["_value"];
        });
        return o;
    }

    struct RawHttpResponse {
        int status = 0;
        std::string status_line;
        std::vector<std::pair<std::string, std::string>> headers;
        std::string body;
        std::string raw;
    };

    RawHttpResponse parse_http_response(const std::string& raw) {
        RawHttpResponse r;
        r.raw = raw;
        std::size_t header_end = raw.find("\r\n\r\n");
        std::string head, body;
        if (header_end == std::string::npos) { head = raw; }
        else { head = raw.substr(0, header_end); body = raw.substr(header_end + 4); }
        r.body = std::move(body);

        std::istringstream is(head);
        std::string line;
        if (std::getline(is, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            r.status_line = line;
            std::size_t sp = line.find(' ');
            if (sp != std::string::npos) {
                std::size_t sp2 = line.find(' ', sp + 1);
                std::string code = (sp2 == std::string::npos) ? line.substr(sp + 1) : line.substr(sp + 1, sp2 - sp - 1);
                try { r.status = std::stoi(code); } catch (...) {}
            }
        }
        while (std::getline(is, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty()) break;
            std::size_t c = line.find(':');
            if (c == std::string::npos) continue;
            r.headers.emplace_back(trim(line.substr(0, c)), trim(line.substr(c + 1)));
        }
        return r;
    }

    std::shared_ptr<Object> make_response_obj(RawHttpResponse resp) {
        auto o = std::make_shared<Object>();
        o->type_name = "HttpResponse";
        auto state = std::make_shared<RawHttpResponse>(std::move(resp));
        o->native_state = state;

        o->methods["status"] = nfn("HttpResponse.status", [state](CallContext&) -> Value {
            return Value{static_cast<double>(state->status)};
        });
        o->methods["body"] = nfn("HttpResponse.body", [state](CallContext&) -> Value {
            return Value{state->body};
        });
        o->methods["headers"] = nfn("HttpResponse.headers", [state](CallContext&) -> Value {
            std::string out;
            for (const auto& [k, v] : state->headers) out += k + ": " + v + "\n";
            return Value{out};
        });
        o->methods["header"] = nfn("HttpResponse.header", [state](CallContext& c) -> Value {
            if (c.positional.empty()) throw RuntimeError("header(name) requires 1 argument", c.line, c.col);
            std::string name = lower(need_string(c.positional[0], "header name", c.line, c.col));
            for (const auto& [k, v] : state->headers) {
                if (lower(k) == name) return Value{make_header_obj(true, v)};
            }
            return Value{make_header_obj(false, "")};
        });
        return o;
    }

    // ---------- Tcp object ----------

    struct TcpState {
        std::unique_ptr<transport::Tcp> tcp;
        bool connected = false;
    };

    std::shared_ptr<Object> make_tcp_obj(const std::string& host, int port, int timeout_ms) {
        auto state = std::make_shared<TcpState>();
        state->tcp = std::make_unique<transport::Tcp>();
        core::Port pr = state->tcp->connect(host, port, timeout_ms);
        state->connected = (pr.state == core::PortState::OPEN);

        auto o = std::make_shared<Object>();
        o->type_name = "Tcp";
        o->native_state = state;
        o->fields["connected"] = Value{state->connected};

        o->methods["connected"] = nfn("Tcp.connected", [state](CallContext&) -> Value {
            return Value{state->connected};
        });
        o->methods["send"] = nfn("Tcp.send", [state](CallContext& c) -> Value {
            if (c.positional.empty()) throw RuntimeError("send(data) requires 1 argument", c.line, c.col);
            std::string data = need_string(c.positional[0], "data", c.line, c.col);
            if (!state->connected) return Value{false};
            return Value{state->tcp->send(data)};
        });
        o->methods["recv"] = nfn("Tcp.recv", [state](CallContext& c) -> Value {
            int timeout = 2000;
            auto it = c.named.find("timeout_ms");
            if (it != c.named.end()) timeout = need_int(it->second, "timeout_ms", c.line, c.col);
            if (!state->connected) return Value{std::string{}};
            return Value{state->tcp->receive(timeout)};
        });
        o->methods["recv_banner"] = nfn("Tcp.recv_banner", [state](CallContext& c) -> Value {
            int timeout = 2000;
            auto it = c.named.find("timeout_ms");
            if (it != c.named.end()) timeout = need_int(it->second, "timeout_ms", c.line, c.col);
            if (!state->connected) return Value{std::string{}};
            return Value{state->tcp->receive(timeout)};
        });
        return o;
    }

    // ---------- Http object ----------

    struct HttpState {
        std::string host;
        int port = 0;
        int timeout_ms = 3000;
    };

    std::shared_ptr<Object> make_http_obj(const std::string& host, int port, int timeout_ms) {
        auto state = std::make_shared<HttpState>();
        state->host = host; state->port = port; state->timeout_ms = timeout_ms;

        auto o = std::make_shared<Object>();
        o->type_name = "Http";
        o->native_state = state;
        o->fields["host"] = Value{host};
        o->fields["port"] = Value{static_cast<double>(port)};

        o->methods["request"] = nfn("Http.request", [state](CallContext& c) -> Value {
            std::string method = "GET";
            std::string path = "/";
            auto it = c.named.find("method"); if (it != c.named.end()) method = need_string(it->second, "method", c.line, c.col);
            it       = c.named.find("path");   if (it != c.named.end()) path   = need_string(it->second, "path",   c.line, c.col);
            std::string body_in;
            it       = c.named.find("body");   if (it != c.named.end()) body_in = need_string(it->second, "body", c.line, c.col);

            transport::Tcp tcp;
            core::Port pr = tcp.connect(state->host, state->port, state->timeout_ms);
            if (!(pr.state == core::PortState::OPEN)) return Value{std::monostate{}};

            std::ostringstream req;
            req << method << " " << path << " HTTP/1.1\r\n"
                << "Host: " << state->host << "\r\n"
                << "User-Agent: ZeroTrust/1.0\r\n"
                << "Accept: */*\r\n"
                << "Connection: close\r\n";
            if (!body_in.empty()) req << "Content-Length: " << body_in.size() << "\r\n";
            req << "\r\n" << body_in;

            if (!tcp.send(req.str())) return Value{std::monostate{}};

            std::string raw;
            for (int i = 0; i < 20; i++) {
                std::string chunk = tcp.receive(state->timeout_ms);
                if (chunk.empty()) break;
                raw += chunk;
                if (raw.size() > 128 * 1024) break;
            }
            if (raw.empty()) return Value{std::monostate{}};

            return Value{make_response_obj(parse_http_response(raw))};
        });
        return o;
    }

    // ---------- Plugin object ----------

    std::shared_ptr<Object> make_plugin_obj(std::shared_ptr<RunState> state) {
        auto o = std::make_shared<Object>();
        o->type_name = "Plugin";

        o->methods["name"] = nfn("Plugin.name", [state](CallContext& c) -> Value {
            if (!c.positional.empty()) state->meta.name = need_string(c.positional[0], "plugin name", c.line, c.col);
            return Value{std::monostate{}};
        });
        o->methods["description"] = nfn("Plugin.description", [state](CallContext& c) -> Value {
            if (!c.positional.empty()) state->meta.description = need_string(c.positional[0], "description", c.line, c.col);
            return Value{std::monostate{}};
        });
        o->methods["category"] = nfn("Plugin.category", [state](CallContext& c) -> Value {
            if (!c.positional.empty()) state->meta.category = need_string(c.positional[0], "category", c.line, c.col);
            return Value{std::monostate{}};
        });
        o->methods["filter"] = nfn("Plugin.filter", [state](CallContext& c) -> Value {
            auto any = c.named.find("any");
            if (any != c.named.end() && is_truthy(any->second)) state->meta.filter_any = true;
            auto svc = c.named.find("service");
            if (svc != c.named.end()) state->meta.filter_service = need_string(svc->second, "filter service", c.line, c.col);
            return Value{std::monostate{}};
        });
        o->methods["set_service"] = nfn("Plugin.set_service", [state](CallContext& c) -> Value {
            if (c.positional.empty()) throw RuntimeError("set_service(name) requires 1 argument", c.line, c.col);
            std::string svc = need_string(c.positional[0], "service name", c.line, c.col);
            state->set_service = svc;
            if (state->kb) {
                state->kb->data["service"] = Value{svc};
                auto vit = c.named.find("version");
                if (vit != c.named.end()) state->kb->data["version"] = vit->second;
                auto pit = c.named.find("product");
                if (pit != c.named.end()) state->kb->data["product"] = pit->second;
                auto bit = c.named.find("banner");
                if (bit != c.named.end()) state->kb->data["banner"] = bit->second;
            }
            return Value{std::monostate{}};
        });
        o->methods["run"] = nfn("Plugin.run", [state](CallContext& c) -> Value {
            if (!c.block) throw RuntimeError("plugin.run requires a { ... } block", c.line, c.col);
            if (state->meta_only) return Value{std::monostate{}};

            // Filter decision (unless we're in the service-detect pass where meta.filter_any=true)
            bool ok = false;
            if (state->meta.filter_any) ok = true;
            else if (state->meta.filter_service.empty()) ok = true;   // no filter → always run
            else if (state->meta.filter_service == state->known_service) ok = true;
            if (!ok) return Value{std::monostate{}};

            Environment scope(&c.interp->global_env());
            try {
                for (const auto& s : *c.block) c.interp->exec_stmt(*s, scope);
            } catch (const ReturnException&) {}
            return Value{std::monostate{}};
        });
        return o;
    }

    // ---------- Target object ----------

    std::shared_ptr<Object> make_target_obj(const std::string& host, int port, const std::string& service) {
        auto o = std::make_shared<Object>();
        o->type_name = "Target";
        o->fields["host"] = Value{host};
        o->fields["port"] = Value{static_cast<double>(port)};
        o->fields["service"] = Value{service};
        return o;
    }

    // ---------- finding() free function ----------

    std::shared_ptr<NativeFn> make_finding_fn(std::shared_ptr<RunState> state) {
        return nfn("finding", [state](CallContext& c) -> Value {
            FindingOut f;
            f.plugin_name = state->meta.name;
            f.port_number = static_cast<std::uint16_t>(state->target_port);
            f.service = state->set_service.empty() ? state->known_service : state->set_service;

            auto get = [&](const std::string& k) -> const Value* {
                auto it = c.named.find(k);
                return it == c.named.end() ? nullptr : &it->second;
            };
            if (auto v = get("severity"))    f.severity    = need_string(*v, "severity", c.line, c.col);
            if (auto v = get("title"))       f.title       = need_string(*v, "title", c.line, c.col);
            if (auto v = get("description")) f.description = need_string(*v, "description", c.line, c.col);
            if (auto v = get("evidence")) {
                if (auto s = as_string(*v)) f.evidence = *s;
                else f.evidence = value_to_string(*v);
            }
            if (auto v = get("confidence")) {
                if (auto n = as_number(*v)) f.confidence = *n;
            }
            if (f.severity.empty()) f.severity = "info";
            state->findings.push_back(std::move(f));
            return Value{std::monostate{}};
        });
    }

    // ---------- register globals ----------

    std::shared_ptr<Object> make_kb_obj(std::shared_ptr<RunState> state) {
        auto o = std::make_shared<Object>();
        o->type_name = "Kb";
        o->methods["set"] = nfn("Kb.set", [state](CallContext& c) -> Value {
            if (c.positional.size() < 2) throw RuntimeError("kb.set(key, value) requires 2 args", c.line, c.col);
            std::string key = need_string(c.positional[0], "key", c.line, c.col);
            if (state->kb) state->kb->data[key] = c.positional[1];
            return Value{std::monostate{}};
        });
        o->methods["get"] = nfn("Kb.get", [state](CallContext& c) -> Value {
            if (c.positional.empty()) throw RuntimeError("kb.get(key) requires 1 arg", c.line, c.col);
            std::string key = need_string(c.positional[0], "key", c.line, c.col);
            if (!state->kb) return Value{std::monostate{}};
            auto it = state->kb->data.find(key);
            if (it == state->kb->data.end()) return Value{std::monostate{}};
            return it->second;
        });
        o->methods["has"] = nfn("Kb.has", [state](CallContext& c) -> Value {
            if (c.positional.empty()) throw RuntimeError("kb.has(key) requires 1 arg", c.line, c.col);
            std::string key = need_string(c.positional[0], "key", c.line, c.col);
            if (!state->kb) return Value{false};
            return Value{state->kb->data.count(key) > 0};
        });
        return o;
    }

    void register_stdlib(Interpreter& interp, std::shared_ptr<RunState> state) {
        interp.define_global("plugin", Value{make_plugin_obj(state)});
        interp.define_global("target", Value{make_target_obj(state->target_host, state->target_port, state->known_service)});
        interp.define_global("finding", Value{make_finding_fn(state)});
        interp.define_global("kb", Value{make_kb_obj(state)});

        interp.define_global("net::tcp", Value{nfn("net::tcp", [](CallContext& c) -> Value {
            std::string host;
            int port = 0;
            int timeout = 2000;
            auto it = c.named.find("host"); if (it != c.named.end()) host = need_string(it->second, "host", c.line, c.col);
            it       = c.named.find("port"); if (it != c.named.end()) port = need_int(it->second, "port", c.line, c.col);
            it       = c.named.find("timeout_ms"); if (it != c.named.end()) timeout = need_int(it->second, "timeout_ms", c.line, c.col);
            if (host.empty() || port == 0) throw RuntimeError("net::tcp requires host: and port:", c.line, c.col);
            return Value{make_tcp_obj(host, port, timeout)};
        })});

        interp.define_global("net::http", Value{nfn("net::http", [](CallContext& c) -> Value {
            std::string host;
            int port = 80;
            int timeout = 3000;
            auto it = c.named.find("host"); if (it != c.named.end()) host = need_string(it->second, "host", c.line, c.col);
            it       = c.named.find("port"); if (it != c.named.end()) port = need_int(it->second, "port", c.line, c.col);
            it       = c.named.find("timeout_ms"); if (it != c.named.end()) timeout = need_int(it->second, "timeout_ms", c.line, c.col);
            if (host.empty()) throw RuntimeError("net::http requires host:", c.line, c.col);
            return Value{make_http_obj(host, port, timeout)};
        })});
    }
}

namespace ztl {
    KbSharedPtr make_kb() { return std::make_shared<KbShared>(); }

    LoadedPlugin load_plugin(const std::string& path) {
        std::ifstream in(path);
        if (!in.is_open()) throw std::runtime_error("cannot open plugin: " + path);
        std::ostringstream buf; buf << in.rdbuf();
        Lexer lx(buf.str());
        Parser ps(lx.tokenize());
        LoadedPlugin lp;
        lp.program = ps.parse_program();
        lp.source_path = path;

        // Meta preload: run once with meta_only to fill preview_meta.
        try {
            auto state = std::make_shared<RunState>();
            state->meta_only = true;
            state->target_host = "0.0.0.0";
            state->target_port = 0;
            Interpreter ip;
            register_stdlib(ip, state);
            ip.run_program(lp.program);
            lp.preview_meta = state->meta;
        } catch (...) {
            // Ignore preload errors — will surface at real run time.
        }
        return lp;
    }

    std::vector<LoadedPlugin> load_plugins_dir(const std::string& dir) {
        std::vector<LoadedPlugin> out;
        DIR* d = opendir(dir.c_str());
        if (!d) return out;
        struct dirent* e;
        while ((e = readdir(d)) != nullptr) {
            std::string name = e->d_name;
            if (name.size() < 5) continue;
            if (name.substr(name.size() - 4) != ".ztl") continue;
            try {
                out.push_back(load_plugin(dir + "/" + name));
            } catch (const std::exception&) {
                // skip broken plugins
            }
        }
        closedir(d);
        return out;
    }

    RunOutcome run_plugin(const LoadedPlugin& p,
                          const std::string& target_host,
                          int target_port,
                          const std::string& known_service,
                          KbSharedPtr kb) {
        auto state = std::make_shared<RunState>();
        state->target_host = target_host;
        state->target_port = target_port;
        state->known_service = known_service;
        state->kb = kb;

        Interpreter interp;
        register_stdlib(interp, state);
        try {
            interp.run_program(p.program);
        } catch (const ReturnException&) {
            // top-level return is allowed
        } catch (const std::exception& ex) {
            // Bury runtime errors — do not kill the scan; surface as a debug-severity finding.
            FindingOut f;
            f.plugin_name = state->meta.name.empty() ? p.source_path : state->meta.name;
            f.severity = "debug";
            f.title = "Plugin runtime error";
            f.description = ex.what();
            f.port_number = static_cast<std::uint16_t>(target_port);
            state->findings.push_back(std::move(f));
        }

        RunOutcome out;
        out.meta = state->meta;
        out.findings = std::move(state->findings);
        out.detected_service = state->set_service;
        out.detected_port = state->set_service.empty() ? 0 : target_port;
        return out;
    }

    std::vector<FindingOut> run_for_port(const std::vector<LoadedPlugin>& plugins,
                                         const std::string& host, int port,
                                         const std::string& initial_service,
                                         std::string& out_service) {
        auto kb = make_kb();
        if (!initial_service.empty()) kb->data["service"] = Value{initial_service};
        std::string svc = initial_service;
        std::vector<FindingOut> out;
        for (const auto& lp : plugins) {
            if (!lp.preview_meta.filter_any) continue;
            RunOutcome r = run_plugin(lp, host, port, svc, kb);
            if (!r.detected_service.empty()) svc = r.detected_service;
            for (auto& f : r.findings) out.push_back(std::move(f));
        }
        for (const auto& lp : plugins) {
            if (lp.preview_meta.filter_any) continue;
            if (!lp.preview_meta.filter_service.empty() && lp.preview_meta.filter_service != svc) continue;
            RunOutcome r = run_plugin(lp, host, port, svc, kb);
            for (auto& f : r.findings) out.push_back(std::move(f));
        }
        out_service = svc;
        return out;
    }

    std::vector<FindingOut> run_all(const std::vector<LoadedPlugin>& plugins,
                                    const std::string& host,
                                    const std::vector<int>& open_ports) {
        std::vector<FindingOut> all;
        std::unordered_map<int, std::string> service_of;
        std::unordered_map<int, KbSharedPtr> kbs;
        for (int p : open_ports) kbs[p] = make_kb();

        // Pass 1: filter_any (service-detect).
        for (const auto& lp : plugins) {
            if (!lp.preview_meta.filter_any) continue;
            for (int port : open_ports) {
                RunOutcome r = run_plugin(lp, host, port, service_of[port], kbs[port]);
                if (!r.detected_service.empty()) service_of[port] = r.detected_service;
                for (auto& f : r.findings) all.push_back(std::move(f));
            }
        }
        // Pass 2: filter_service (targeted checks).
        for (const auto& lp : plugins) {
            if (lp.preview_meta.filter_any) continue;
            for (int port : open_ports) {
                const std::string& svc = service_of[port];
                if (!lp.preview_meta.filter_service.empty() && lp.preview_meta.filter_service != svc) continue;
                RunOutcome r = run_plugin(lp, host, port, svc, kbs[port]);
                for (auto& f : r.findings) all.push_back(std::move(f));
            }
        }
        return all;
    }
}
