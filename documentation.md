# ZeroTrust Plugin Language (ZTL)

## 1. Wprowadzenie

ZTL (ZeroTrust Language) is a small scripting language used to write ZeroTrust network scanner plugins.

Plugins are stored as `.ztl` files in:

```text
data/plugins/
```

They are loaded at application startup, lexed, parsed into an AST and executed by the ZTL runtime. Adding a normal plugin does not require recompiling the daemon.

ZTL is designed for:

- service discovery,
- banner and version detection,
- safe TCP probes,
- safe HTTP probes,
- configuration checks,
- CVE version correlation,
- active non-destructive checks,
- structured findings.

ZTL does not provide exploit payloads, persistence, credential theft, reverse shells or destructive actions.

## 2. Minimal Plugin

```ztl
include("@zerotrust/plugin");
include("@zerotrust/net");

plugin.name("Example service detection");
plugin.description("Detects an example service.");
plugin.category("service-detect");
plugin.filter(any: true);

plugin.run
{
    tcp = net::tcp(
        host: target.host,
        port: target.port,
        timeout_ms: 2000
    );

    if (!tcp.connected())
    {
        return;
    }

    banner = tcp.recv_banner(timeout_ms: 2000);

    if (!banner.starts_with("EXAMPLE"))
    {
        return;
    }

    plugin.set_service(
        "example",
        banner: banner.trim()
    );

    finding(
        severity: "info",
        title: "Example service detected",
        description: "The service returned an example banner.",
        evidence: banner.trim(),
        confidence: 0.95
    );
}
```

## 3. Plugin File Structure

A plugin normally contains:

```ztl
include("@zerotrust/plugin");
include("@zerotrust/net");

plugin.name("Plugin name");
plugin.description("Plugin description");
plugin.category("category");
plugin.filter(service: "http");

plugin.run
{
    // plugin code
}
```

Statements may end with semicolons. The parser also accepts the trailing block form used by `plugin.run`.

## 4. Includes

Syntax:

```ztl
include("@zerotrust/plugin");
include("@zerotrust/net");
```

The current runtime parses `include`, but include files are not loaded dynamically. Includes are currently no-ops; the standard library is registered automatically for every plugin.

The conventional include names are still recommended for readability and compatibility.

## 5. Comments

Single-line comments:

```ztl
// comment
# comment
```

Block comments:

```ztl
/*
   multi-line comment
*/
```

## 6. Literals and Values

Supported literal types:

```ztl
text = "hello";
number = 42;
decimal = 0.95;
enabled = true;
disabled = false;
missing = null;
```

The runtime value types are:

- null,
- boolean,
- number,
- string,
- object,
- native function.

The language currently has no user-defined classes, arrays, maps or user-defined functions.

## 7. Variables and Assignment

```ztl
banner = "SSH-2.0-OpenSSH_9.6p1";
product = "OpenSSH";
version = "9.6p1";
```

Variables are dynamically typed. Assignment can update a variable in the current scope or a parent scope.

Variable names may contain letters, digits and underscores, but must not start with a digit.

## 8. Conditional Statements

```ztl
if (banner == "")
{
    return;
}

if (response.status() == 200)
{
    finding(
        severity: "info",
        title: "HTTP response received"
    );
}
else
{
    return;
}
```

`else if` is supported through nested conditional syntax:

```ztl
if (code == 200)
{
    result = "ok";
}
else if (code == 404)
{
    result = "missing";
}
else
{
    result = "other";
}
```

## 9. Return

Return from a plugin block:

```ztl
if (!tcp.connected())
{
    return;
}
```

A return value is supported by the AST, but plugin execution uses return primarily to stop the current plugin.

## 10. Operators

Supported operators:

### Equality

```ztl
value == "ssh";
value != "ftp";
```

### Numeric comparison

```ztl
status >= 200;
status < 300;
status <= 399;
status > 0;
```

Numeric comparison requires numeric operands.

### Logical operators

```ztl
if (connected && banner != "")
{
    // both conditions are true
}

if (is_ssh || is_dropbear)
{
    // at least one condition is true
}
```

Logical operators use short-circuit evaluation.

### Arithmetic and concatenation

```ztl
sum = 1 + 2;
difference = 5 - 2;
message = "service: " + product;
```

`+` adds numbers when both operands are numbers. Otherwise it concatenates their string representations.

### Unary operators

```ztl
if (!tcp.connected())
{
    return;
}

negative = -1;
```

## 11. String Methods

All string methods use positional arguments.

### `length()` and `size()`

```ztl
if (banner.length() < 4)
{
    return;
}
```

Returns the string length as a number.

### `starts_with(prefix)`

```ztl
if (!banner.starts_with("SSH-"))
{
    return;
}
```

Returns boolean.

### `ends_with(suffix)`

```ztl
if (path.ends_with("/admin"))
{
    finding(severity: "info", title: "Admin path observed");
}
```

Returns boolean.

### `contains(text)`

```ztl
if (banner.to_lower().contains("openssh"))
{
    // match
}
```

Returns boolean.

### `slice(start, end)`

```ztl
prefix = banner.slice(0, 8);
rest = banner.slice(8);
```

The second argument is optional. Indexes are numeric and out-of-range values are clamped.

### `index_of(text)`

```ztl
position = banner.index_of("_");
if (position < 0)
{
    return;
}
```

Returns the index or `-1` when the substring is absent.

### `trim()`

```ztl
clean = banner.trim();
```

Removes whitespace at both ends.

### `to_lower()` and `to_upper()`

```ztl
lower = banner.to_lower();
upper = banner.to_upper();
```

### `byte_at(index)`

```ztl
first_byte = packet.byte_at(0);
if (first_byte == 10)
{
    // protocol marker
}
```

Returns the byte value as a number or `-1` outside the string.

## 12. Namespaced Calls

Network functions use the `::` namespace operator:

```ztl
tcp = net::tcp(host: target.host, port: target.port);
http = net::http(host: target.host, port: target.port);
```

The parser represents these as scoped names such as `net::tcp` and `net::http`.

## 13. Plugin Metadata API

### `plugin.name(name)`

Sets the plugin display name.

```ztl
plugin.name("SSH service detection");
```

### `plugin.description(description)`

Sets the plugin description.

```ztl
plugin.description("Detects an SSH server by reading its banner.");
```

### `plugin.category(category)`

Sets a free-form category.

```ztl
plugin.category("service-detect");
plugin.category("verified-test");
plugin.category("vulnerability");
```

### `plugin.filter(...)`

A service filter:

```ztl
plugin.filter(service: "ssh");
```

The plugin runs only when the current detected service is `ssh`.

A discovery filter:

```ztl
plugin.filter(any: true);
```

The plugin runs during the discovery pass for every open TCP port. It can claim a service with `plugin.set_service()`.

With no service filter, a plugin is applicable to every service pass.

### `plugin.run { ... }`

Defines the executable plugin body:

```ztl
plugin.run
{
    // statements
}
```

The runner executes discovery plugins first and service-filtered plugins afterward.

## 14. Target Object

The global `target` object is available in every plugin.

Fields:

| Field | Type | Meaning |
|---|---|---|
| `target.host` | string | Target IPv4 address or host value used by the scan |
| `target.port` | number | Current TCP port |
| `target.service` | string | Known service, when available |
| `target.product` | string | Detected product, when available |
| `target.version` | string | Detected version, when available |

Example:

```ztl
if (target.service != "http")
{
    return;
}

finding(
    severity: "info",
    title: "Target service context",
    evidence: target.host + ":" + target.port
);
```

`product` and `version` are initialized from service detection and shared plugin state. They may be empty.

## 15. `plugin.set_service()`

Syntax:

```ztl
plugin.set_service(
    "ssh",
    banner: banner,
    product: "OpenSSH",
    version: "9.6p1"
);
```

The first positional argument is the service name.

Supported named arguments:

- `banner`
- `product`
- `version`

Effects:

1. Sets the detected service for the current plugin run.
2. Stores service information in the shared ZTL KB.
3. Makes product/version available to later plugins on the same target port.
4. Updates `target.service`, `target.product` and `target.version`.

## 16. TCP API

### `net::tcp()`

Syntax:

```ztl
tcp = net::tcp(
    host: target.host,
    port: target.port,
    timeout_ms: 2000
);
```

Named arguments:

- `host`: required string;
- `port`: required number;
- `timeout_ms`: optional number, default `2000`.

The function immediately attempts an IPv4 TCP connection and returns a TCP object.

### `tcp.connected()`

```ztl
if (!tcp.connected())
{
    return;
}
```

Returns boolean.

### `tcp.send(data)`

```ztl
if (!tcp.send("HELLO\r\n"))
{
    return;
}
```

Sends a complete string. The native transport retries partial writes and interrupted system calls. Returns boolean.

### `tcp.recv(timeout_ms: ...)`

```ztl
response = tcp.recv(timeout_ms: 1500);
```

Returns one received string chunk or an empty string on timeout/error.

### `tcp.recv_banner(timeout_ms: ...)`

```ztl
banner = tcp.recv_banner(timeout_ms: 2000);
```

Current implementation uses the same single-read transport behavior as `recv()`. The method name expresses plugin intent.

## 17. HTTP API

### `net::http()`

Syntax:

```ztl
http = net::http(
    host: target.host,
    port: target.port,
    timeout_ms: 2500
);
```

Named arguments:

- `host`: required string;
- `port`: optional number, default `80`;
- `timeout_ms`: optional number, default `3000`.

### `http.request()`

Syntax:

```ztl
response = http.request(
    method: "HEAD",
    path: "/"
);
```

Supported named arguments:

- `method`, default `GET`;
- `path`, default `/`;
- `body`, optional string.

The runtime sends a HTTP/1.1 request with `Host`, `User-Agent`, `Accept` and `Connection: close` headers. The response is limited to 128 KiB and a bounded number of reads.

A failed request returns `null`.

### HTTP response methods

```ztl
response.status();
response.body();
response.headers();
server = response.header("Server");
```

`status()` returns a number. `body()` returns the response body. `headers()` returns all parsed headers as one string.

### Header object

```ztl
header = response.header("Strict-Transport-Security");

if (header.exists())
{
    value = header.value();
}
```

Methods:

- `header.exists()` returns boolean;
- `header.value()` returns the header value.

Header name matching is case-insensitive.

## 18. TLS API

### `net::tls()`

Creates a TLS client backed by the existing OpenSSL transport.

```ztl
tls = net::tls(
    host: target.host,
    port: target.port,
    timeout_ms: 3000
);
```

Named arguments:

- `host`: required string;
- `port`: optional number, default `443`;
- `timeout_ms`: optional number, default `3000`.

### `tls.handshake()`

Performs one bounded TLS handshake:

```ztl
report = tls.handshake();

if (!report.ok)
{
    return;
}
```

The returned report exposes:

| Field | Type | Meaning |
|---|---|---|
| `ok` | boolean | True when the handshake completed |
| `result` | string | `OK`, `REFUSED`, `TIMEOUT`, `NOT_TLS`, `HANDSHAKE_FAILED` or `UNKNOWN` |
| `protocol_version` | string | Negotiated TLS protocol |
| `cipher` | string | Negotiated cipher |
| `certificate_present` | boolean | Whether a peer certificate was received |
| `subject` | string | Certificate subject |
| `issuer` | string | Certificate issuer |
| `not_before` | string | Certificate start time |
| `not_after` | string | Certificate expiry time |
| `signature_algorithm` | string | Certificate signature algorithm |
| `self_signed` | boolean | Whether subject and issuer match |
| `expired` | boolean | Whether the certificate is expired |
| `days_until_expiry` | number | Days until expiry, or negative days after expiry |

The transport is an audit client: certificate verification is disabled so that expired, self-signed and otherwise weak certificates can be inspected. It must not be treated as a general-purpose secure TLS client.

### HTTPS detection example

```ztl
include("@zerotrust/plugin");
include("@zerotrust/net");

plugin.name("HTTPS service detection");
plugin.description("Detects an HTTPS service with a TLS handshake.");
plugin.category("service-detect");
plugin.filter(any: true);

plugin.run
{
    tls = net::tls(
        host: target.host,
        port: target.port,
        timeout_ms: 3000
    );

    report = tls.handshake();
    if (!report.ok) { return; }

    banner = "TLS " + report.protocol_version + " " + report.cipher;
    plugin.set_service("https", banner: banner);
    kb.set("tls.protocol", report.protocol_version);
    kb.set("tls.cipher", report.cipher);

    finding(
        severity: "info",
        title: "HTTPS service detected",
        description: "The endpoint completed a TLS handshake.",
        evidence: banner,
        verification: "UNKNOWN",
        confidence: 0.99
    );
}
```

This detects TLS/HTTPS transport. It does not make an HTTP request and does not prove that an HTTP application is available behind the TLS connection.

## 19. Knowledge Base API

The KB is shared by ZTL plugins executed for the same host/port run.

### Legacy methods

```ztl
kb.set("ssh.banner", banner);
banner = kb.get("ssh.banner");
known = kb.has("ssh.banner");
```

`kb.get()` returns `null` when the key is absent.

### Scoped methods

```ztl
kb.set_scoped("host", "os", "Linux");
kb.set_scoped("port", "service", "ssh");

os = kb.get_scoped("host", "os");
known = kb.has_scoped("port", "service");
```

Allowed scopes:

- `host`
- `port`

The resulting keys are `host.os` and `port.service`.

Recommended key conventions:

```text
host.os
host.hostname
port.service
port.product
port.version
ssh.banner
ssh.algorithms
tls.protocol
tls.cipher
```

The old unscoped methods remain supported for existing plugins.

## 20. Finding API

### `finding()`

A plugin can emit any number of findings.

```ztl
finding(
    severity: "high",
    title: "Anonymous FTP login accepted",
    description: "The FTP service accepted anonymous credentials.",
    cve: "CVE-XXXX-XXXX",
    evidence: "331 User OK | 230 Login successful",
    verification: "ACTIVE_CHECK",
    confidence: 0.99,
    remediation: "Disable anonymous FTP access.",
    cvss: 8.1,
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
);
```

Supported named arguments:

| Argument | Type | Meaning |
|---|---|---|
| `severity` | string | `info`, `low`, `medium`, `high` or `critical` |
| `title` | string | Finding title |
| `description` | string | Detailed explanation |
| `cve` | string | CVE identifier |
| `evidence` | any | Evidence converted to string |
| `verification` | string | Canonical verification status |
| `confidence` | number | Numeric evidence confidence |
| `remediation` | string | Suggested remediation |
| `cvss` | number | Optional CVSS score |
| `cvss_vector` | string | Optional CVSS vector |

Canonical verification values:

```text
UNKNOWN
VERSION_MATCH
CONFIG_MATCH
ACTIVE_CHECK
NOT_VULNERABLE
```

Important:

```text
confidence = 0.99
```

does not automatically mean `ACTIVE_CHECK`. The status must be supplied explicitly and must be supported by the check evidence.

`VERSION_MATCH` means a product/version correlation only. It means potentially vulnerable, not confirmed vulnerable.

## 21. CVE API

### `cve_lookup()`

Compatibility API returning a comma-separated string of matching CVE IDs:

```ztl
cves = cve_lookup(
    product: product,
    version: version
);
```

It does not return structured verification data.

### `cve.check()`

Syntax:

```ztl
result = cve.check(
    id: "CVE-2024-6387",
    product: "OpenSSH",
    version: target.version
);
```

The result object exposes:

- `vulnerable`
- `cve`
- `severity`
- `title`
- `description`
- `evidence`
- `confidence`
- `verification`
- `cvss`
- `cvss_vector`
- `remediation`

### `cve.verify()`

Syntax:

```ztl
result = cve.verify(
    id: "CVE-2024-6387",
    target: target
);
```

The target must be the current `target` object. The runtime reads `target.product` and `target.version`.

Current behavior:

- matching product/version: `vulnerable = true`, `verification = VERSION_MATCH`, confidence about `0.50`;
- no match with complete product/version: `vulnerable = false`, `verification = NOT_VULNERABLE`;
- missing product/version: `vulnerable = false`, `verification = UNKNOWN`.

`cve.verify()` does not run an exploit and does not grant `ACTIVE_CHECK`.

`ACTIVE_CHECK` is reserved for a concrete, safe active test, such as an explicit protocol probe that records evidence.

## 22. Verification Model

```text
VERSION_MATCH
  -> Potentially vulnerable
  -> confidence approximately 0.50

ACTIVE_CHECK
  -> Actively verified
  -> confidence normally 0.90 or higher

CONFIG_MATCH
  -> Configuration verified

NOT_VULNERABLE
  -> Not vulnerable for the requested check

UNKNOWN
  -> Verification unknown
```

A plugin should prefer `VERSION_MATCH` whenever it only has banner/product/version evidence.

Use `ACTIVE_CHECK` only when the plugin performs a deterministic, bounded, non-destructive test and stores the observed response as evidence.

## 23. Service Detection Plugin

Complete SSH-style example:

```ztl
include("@zerotrust/plugin");
include("@zerotrust/net");

plugin.name("SSH service detection");
plugin.description("Detects SSH on any TCP port.");
plugin.category("service-detect");
plugin.filter(any: true);

plugin.run
{
    tcp = net::tcp(
        host: target.host,
        port: target.port,
        timeout_ms: 2000
    );

    if (!tcp.connected()) { return; }

    banner = tcp.recv_banner(timeout_ms: 2000);
    if (banner == "") { return; }
    if (!banner.starts_with("SSH-")) { return; }

    banner = banner.trim();
    product = "OpenSSH";
    version = "";

    plugin.set_service(
        "ssh",
        banner: banner,
        product: product,
        version: version
    );

    kb.set_scoped("port", "service", "ssh");
    kb.set("ssh.banner", banner);

    finding(
        severity: "info",
        title: "SSH server detected",
        description: "The endpoint returned an SSH banner.",
        evidence: banner,
        verification: "UNKNOWN",
        confidence: 0.99
    );
}
```

## 24. Active Check Plugin

Active checks must be safe, bounded and evidence-based.

```ztl
include("@zerotrust/plugin");
include("@zerotrust/net");

plugin.name("HTTP TRACE active check");
plugin.description("Checks whether HTTP TRACE echoes a canary.");
plugin.category("verified-test");
plugin.filter(service: "http");

plugin.run
{
    tcp = net::tcp(
        host: target.host,
        port: target.port,
        timeout_ms: 2500
    );

    if (!tcp.connected()) { return; }

    canary = "ZT-CANARY-9F2A7B1E";
    request = "TRACE / HTTP/1.1\r\n" +
              "Host: " + target.host + "\r\n" +
              "X-Canary: " + canary + "\r\n" +
              "Connection: close\r\n\r\n";

    if (!tcp.send(request)) { return; }

    response = tcp.recv(timeout_ms: 2500);
    if (response == "") { return; }
    if (!response.starts_with("HTTP/1.")) { return; }
    if (!response.contains(" 200 ")) { return; }
    if (!response.contains(canary)) { return; }

    finding(
        severity: "medium",
        title: "HTTP TRACE is enabled",
        description: "The server echoed the request canary in the response.",
        evidence: response.slice(0, 400),
        verification: "ACTIVE_CHECK",
        confidence: 0.99,
        remediation: "Disable HTTP TRACE."
    );
}
```

## 25. CVE Plugin Pattern

```ztl
include("@zerotrust/plugin");
include("@zerotrust/net");

plugin.name("OpenSSH version correlation");
plugin.description("Checks an OpenSSH version against a local CVE range.");
plugin.category("vulnerability");
plugin.filter(service: "ssh");

plugin.run
{
    result = cve.verify(
        id: "CVE-2024-6387",
        target: target
    );

    if (!result.vulnerable)
    {
        return;
    }

    finding(
        severity: result.severity,
        title: result.title,
        description: result.description + " Confirm distribution backports separately.",
        cve: result.cve,
        evidence: result.evidence,
        verification: result.verification,
        confidence: result.confidence,
        cvss: result.cvss,
        cvss_vector: result.cvss_vector,
        remediation: result.remediation
    );
}
```

This plugin produces `VERSION_MATCH`. It does not prove exploitability.

## 26. Plugin Execution Order

The runner uses two passes for one host/port:

```text
Pass 1: filter(any: true)
  -> service discovery
  -> plugin.set_service()
  -> product/version/banner in shared KB

Pass 2: service-filtered plugins
  -> configuration checks
  -> active checks
  -> CVE correlation
  -> findings
```

Plugin findings are converted to the common `core::Finding` model and then sent to deduplication, SQLite, JSON, CLI and Web UI.

## 27. Error Handling

Typical plugin failure behavior:

- failed TCP connection: `connected()` is false;
- failed TCP send: `send()` returns false;
- receive timeout/error: empty string;
- failed HTTP request: `null` response;
- missing KB key: `null`;
- invalid object method or argument type: runtime error;
- parser error: plugin load failure;
- runtime exception: converted into a debug finding by the plugin runner.

Plugin loading errors from the directory loader may be skipped without a detailed user-facing message.

## 28. Safe Plugin Rules

A safe plugin should:

1. use bounded timeouts;
2. send only protocol-valid, non-destructive requests;
3. avoid credentials unless explicitly required by an authorized audit check;
4. never modify remote files or configuration;
5. never execute shell commands remotely;
6. record evidence for every active result;
7. use `VERSION_MATCH` for version correlation;
8. use `ACTIVE_CHECK` only for deterministic observed behavior;
9. return early when the protocol response is unexpected;
10. keep response sizes bounded.

## 29. Current Language Limitations

ZTL currently does not support:

- loops;
- user-defined functions;
- arrays;
- maps;
- dynamic module imports;
- asynchronous operations;
- TLS-specific DSL objects;
- IPv6-specific network APIs;
- a general-purpose exploit or payload API.

The language intentionally remains small and specialized for scanner plugins.

## 30. Plugin Checklist

Before adding a plugin, verify:

- [ ] metadata is present;
- [ ] the filter is correct;
- [ ] all network operations have timeouts;
- [ ] failed connections return early;
- [ ] service detection sets product/version only when evidence supports it;
- [ ] KB keys follow a stable namespace;
- [ ] version-only checks use `VERSION_MATCH`;
- [ ] active checks use explicit `ACTIVE_CHECK`;
- [ ] finding evidence describes the observed response;
- [ ] remediation is included for security findings;
- [ ] no destructive behavior is present.
