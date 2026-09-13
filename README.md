# ZeroTrust

An open-source network vulnerability scanner written from scratch in modern C++.

GPL-3.0. No telemetry, no phone-home, no license servers. What you scan stays on
your machine.

> **Status: alpha.** Functional and useful, but the plugin and CVE databases are
> intentionally small — the project is meant to be extended. Contributions welcome.

---

## What it does

- **Multi-protocol scanning** — TCP with `poll()`-based timeouts, UDP with timeout,
  raw ICMP for host discovery.
- **Concurrent** — 50-thread pool, scans thousands of ports in seconds.
- **CIDR expansion** — `192.168.1.0/24` expanded and scanned per-host.
- **DNS resolver** — custom implementation, parses A records.
- **Service fingerprinting** — regex-based on banners, active probing where
  banners are silent, HTTP fallback.
- **Distro detection** — recognises Ubuntu/Debian/RHEL/Fedora/etc. suffixes in
  service banners.
- **OS fingerprinting** — TTL heuristic from ICMP echo replies.
- **CVE database** — local text database in `data/zt-cve-database.txt`.
- **Service probe database** — local text database in `data/zt-service-probes.txt`.
- **Two flavours of vulnerability detection:**
  - `[VERIFIED]` — actual behaviour tested (e.g. anonymous FTP login,
    SSH Terrapin `CVE-2023-48795`, expired TLS certificate).
  - `[VERSION_MATCH]` — dictionary lookup by product + version, honestly
    labelled as unconfirmed. Distro tag surfaced when present so
    backported patches don't cause false alarms.
- **TLS/SSL checks** — TLS handshake, protocol version, certificate
  subject/issuer/expiry/self-signed detection, weak signature algorithms,
  anonymous / NULL / RC4 / 3DES / DES / export cipher suites (via OpenSSL).
- **ZeroTrust Language (ZTL)** — scripting language for plugins. `.ztl` files
  live in `data/plugins/`, parsed at startup, no recompilation to add checks.
  Supports variables, `if`/`else`, `return`, string methods, named arguments,
  and a small standard library (`net::tcp`, `net::http`, `plugin`, `target`,
  `kb`, `finding`).
- **Any-port service detection** — plugins with `plugin.filter(any: true)` run
  on every open port and can identify services on non-standard ports (SSH on
  22222 works the same as on 22).
- **Knowledge Base** — per-port key/value store shared between plugins on the
  same host+port (`kb.set`, `kb.get`, `kb.has`).

## Non-goals

- Not distributed — one process, one host.
- Not authenticated — no SSH/WinRM login. Everything is network-observable.
- Not a web application scanner — no SQLi/XSS heuristics yet.

## Requirements

- macOS or Linux (any Unix with POSIX sockets)
- C++20 compiler (Clang or GCC)
- CMake 3.20+
- OpenSSL 3.x (`brew install openssl@3` on macOS)
- Root/`sudo` for ICMP scanning (raw socket)

## Build

```bash
cmake -S . -B build
cmake --build build
```

The binary is written to `build/zerotrustd`.

## Quick start

```bash
./build/zerotrustd
# 4 - TCP port range scan
# 5 - Full scan (CIDR + OS fingerprint)
```

Output is nmap-inspired: a table of open ports with service/product/version,
followed by a list of findings tagged by severity and confidence.

## Databases

Two plain text files under `data/`:

- `zt-service-probes.txt` — `match<TAB>service<TAB>regex<TAB>flags(optional)`
- `zt-cve-database.txt` — `cve_id<TAB>product<TAB>version_min<TAB>version_max<TAB>severity<TAB>description`

Both are hand-editable. Comments start with `#`. Add entries directly.

## Architecture

```
src/
├── main.cpp
├── transport/          TCP / UDP / ICMP / TLS with timeouts
├── protocols/
│   ├── dns/            Custom DNS resolver
│   ├── ssh/            Native SSH checks (Terrapin CVE-2023-48795)
│   ├── tls/            OpenSSL-based TLS audit
│   └── tcp/            OS TTL fingerprinting
├── processor/          Service fingerprinting + thread pool
├── scan/               CIDR expansion, CVE matching, progress reporter
├── ztl/                ZeroTrust Language: lexer, parser, interpreter, runner
├── core/               Knowledge base
├── logging/            Simple info/warn/error logging
└── include/            Shared types (Port, Host, Finding, ...)
```

## Writing a plugin

Plugins live in `data/plugins/*.ztl` and are loaded at startup. Example:

```ztl
include("@zerotrust/plugin");
include("@zerotrust/net");

plugin.name("SSH service detection");
plugin.category("service-detect");
plugin.filter(any: true);

plugin.run
{
    tcp = net::tcp(host: target.host, port: target.port);
    if (!tcp.connected()) { return; }

    banner = tcp.recv_banner();
    if (!banner.starts_with("SSH-")) { return; }

    plugin.set_service("ssh", banner: banner.trim());
    kb.set("ssh.banner", banner.trim());

    finding(
        severity: "info",
        title: "SSH server detected",
        evidence: banner.trim(),
        confidence: 0.99
    );
}
```

The plugin runs on every open port (`filter(any: true)`). If it detects SSH,
downstream plugins with `plugin.filter(service: "ssh")` are then invoked on
that port and can read the banner from `kb`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

The lowest-friction contribution is a new ZTL plugin — no C++ compilation
needed. The next-easiest is expanding `data/zt-cve-database.txt` with more
hand-curated CVE entries.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).

The choice is deliberate: keeping the code GPL means it stays open — anyone
can fork, extend, and ship it, but modified versions must also be free
software.
