# ZeroTrust

An open-source network vulnerability scanner, written from scratch in modern C++.

Built in the spirit of pre-2005 Nessus — when the industry-standard vulnerability
scanner was free software that anyone could read, audit, and extend. GPL-3.0, no
telemetry, no phone-home, no license servers. What you scan stays on your machine.

> **Status: alpha.** This project is under active development. It is functional
> and useful, but the plugin/CVE database is still small compared to commercial
> products. Contributions welcome.

---

## What it does

- **Multi-protocol scanning** — TCP with `poll()`-based timeouts, UDP with timeout,
  raw ICMP for host discovery.
- **Concurrent** — 50-thread pool, scans thousands of ports in seconds.
- **CIDR expansion** — `192.168.1.0/24` expanded and scanned per-host.
- **DNS resolver** — custom implementation, parses A records; no dependency on libc.
- **Service fingerprinting** — regex-based on banners, binary parsing for MySQL,
  active probing for PostgreSQL, HTTP fallback.
- **Distro detection** — recognises Ubuntu/Debian/RHEL/Fedora/etc. suffixes in
  service banners (relevant for backport-aware CVE matching).
- **OS fingerprinting** — TTL heuristic from ICMP echo replies.
- **CVE database** — small hand-written seed plus optional import from
  [NIST NVD 2.0 JSON feeds](https://nvd.nist.gov/vuln/data-feeds).
- **Service probe database** — 14 curated patterns plus optional import from
  local `nmap-service-probes` (parses ~11 700 patterns compatible with
  `std::regex`).
- **Two flavours of vulnerability detection:**
  - `[VERIFIED]` — actual behaviour tested (e.g. anonymous FTP login,
    SSH Terrapin `CVE-2023-48795`, expired TLS certificate).
  - `[VERSION_MATCH]` — dictionary lookup by product + version, honestly
    labelled as unconfirmed. Distro tag surfaced when present so
    backported patches don't cause false alarms.
- **TLS/SSL checks** — TLS handshake, protocol version, certificate
  subject/issuer/expiry/self-signed detection, weak signature algorithms,
  anonymous / NULL / RC4 / 3DES / DES / export cipher suites (via OpenSSL).
- **Custom plugin language: ZTL** — plugins live in `data/plugins/*.ztl`,
  parsed at startup, no recompilation to add checks. Supports capture groups,
  variable substitution, required conditions, match modes, when-clauses, and
  UDP probes.
- **Knowledge Base** — thread-safe per-host store shared between plugins and
  native checks (e.g. Terrapin writes advertised algorithms, downstream
  plugins read them).
- **JSON reporting** — every scan writes a full report; a delta command
  diffs two reports to show new open ports, closed ports, new findings, and
  resolved findings.
- **Progress bar** — live progress during long scans.

## Non-goals

- Not trying to replace Nessus feature-for-feature. Nessus has 20+ years and
  a full-time team behind ~180 000 plugins. ZeroTrust is a smaller, focused
  tool that stays open.
- Not distributed — one process, one host. Ranges scanned concurrently but
  no agents.
- Not authenticated — no SSH/WinRM login. Everything is network-observable.
- Not a web application scanner — no SQLi/XSS heuristics yet.

## Requirements

- macOS or Linux (tested on macOS 27, should work on any Unix with POSIX sockets)
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
# Basic single-host TCP scan
./build/zerotrustd
# select 4, IP 192.0.2.1, ports 1-1024

# Full scan of a subnet with OS fingerprint + JSON report (requires sudo for ICMP)
sudo ./build/zerotrustd
# select 5, target 192.168.1.0/24, ports 1-10000

# Compare two scan reports
./build/zerotrustd
# select 6, provide two scan.json files
```

Every scan writes `scan.json` in the working directory. Full schema is documented
by example — run one scan and read the file.

## Import real content

The seed database is small. Import from public sources on first use:

**nmap service-probes** (`~/opt/homebrew/share/nmap/nmap-service-probes` on macOS):

```bash
./build/zerotrustd
# select 7, subchoice 1, accept default path
# writes data/zt-service-probes-nmap.txt
```

Adds ~11 700 service-detection patterns.

**NVD CVE feed** (JSON API 2.0):

```bash
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=2024-01-01T00:00:00.000&pubEndDate=2024-12-31T23:59:59.999&resultsPerPage=2000" \
    -o /tmp/nvd-2024.json

./build/zerotrustd
# select 7, subchoice 2, provide the JSON path
# writes data/zt-cve-database-nvd.txt
```

A rate limit and API key are recommended for larger imports;
see [NVD developer docs](https://nvd.nist.gov/developers/vulnerabilities).

## Architecture

```
src/
├── main.cpp                    Interactive CLI entry
├── transport/                  TCP/UDP/ICMP/TLS with timeouts
├── protocols/dns/              Custom DNS resolver
├── concurrency/                Thread pool
├── processor/                  Service fingerprinting + distro detection
├── vuln/                       Vulnerability engine
│   ├── vuln.cpp                CVE database matching
│   ├── terrapin.cpp            Native SSH CVE-2023-48795 check
│   └── tls_checks.cpp          OpenSSL-based TLS audit
├── ztl/                        ZeroTrust Language: plugin engine
│   ├── ast.hpp                 Plugin / Probe / Require
│   ├── parser.cpp              .ztl -> AST
│   └── interpreter.cpp         AST -> Finding
├── core/                       Knowledge base (shared plugin state)
├── report/                     JSON writer, reader, delta
├── util/                       CIDR, JSON parser, OS fingerprinting
├── import/                     nmap-service-probes + NVD importers
├── progress/                   CLI progress bar
├── logging/                    Simple info/warn/error logging
└── include/                    Shared types (Port, Host, Finding, etc.)
```

## Writing a plugin

Plugins live in `data/plugins/*.ztl` and are loaded at startup. Example:

```ztl
plugin ftp-anonymous {
    service     "ftp"
    severity    HIGH
    title       "Anonymous FTP login allowed"
    description "The FTP server accepted a login with the username 'anonymous'."

    probe {
        send   "USER anonymous\r\n"
        expect "^331"
    }

    probe {
        send   "PASS zerotrust@example.com\r\n"
        expect "^230"
    }
}
```

Plugin runs on any port where `service == "ftp"`. If all `probe` blocks
succeed, a `[VERIFIED] HIGH` finding is emitted. Full ZTL reference in
[docs/ZTL.md](docs/ZTL.md) *(TODO)*.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

The lowest-friction contribution is a new ZTL plugin — no C++ compilation
needed. The next-easiest is expanding `data/zt-cve-database.txt` with more
hand-curated CVE entries.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).

The choice is deliberate: this project exists because commercial vulnerability
scanners went closed. Keeping it GPL means it stays open — anyone can fork,
extend, and ship it, but modified versions must also be free software.

## Not affiliated

Not affiliated with Tenable, Nmap, or any commercial vulnerability scanner.
The `import` command reads local nmap-service-probes and NVD data at runtime,
but neither dataset is distributed with this project.
