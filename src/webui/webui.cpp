// webui.cpp

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"

#include "webui/webui.hpp"
#include "scan/tcp_range.hpp"
#include "core/db.hpp"
#include "logging/logging.hpp"
#include "protocols/dns/resolver.hpp"
#include "severity.h"
#include "confidence.h"
#include "protocol.h"

#include <arpa/inet.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>

namespace {

// ---------- base64url / random / sha256 ----------

std::string b64url_encode(const unsigned char* data, size_t len) {
    BIO* mem = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO* chain = BIO_push(b64, mem);
    BIO_write(chain, data, static_cast<int>(len));
    BIO_flush(chain);
    BUF_MEM* buf; BIO_get_mem_ptr(mem, &buf);
    std::string s(buf->data, buf->length);
    BIO_free_all(chain);
    for (char& c : s) { if (c == '+') c = '-'; else if (c == '/') c = '_'; }
    while (!s.empty() && s.back() == '=') s.pop_back();
    return s;
}

std::string b64url_decode(const std::string& in) {
    std::string t = in;
    for (char& c : t) { if (c == '-') c = '+'; else if (c == '_') c = '/'; }
    while (t.size() % 4 != 0) t.push_back('=');
    BIO* mem = BIO_new_mem_buf(t.data(), static_cast<int>(t.size()));
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO* chain = BIO_push(b64, mem);
    std::string out(t.size(), '\0');
    int n = BIO_read(chain, out.data(), static_cast<int>(out.size()));
    BIO_free_all(chain);
    if (n < 0) n = 0;
    out.resize(n);
    return out;
}

std::string random_urlsafe(size_t bytes) {
    std::string buf(bytes, '\0');
    RAND_bytes(reinterpret_cast<unsigned char*>(buf.data()), static_cast<int>(bytes));
    return b64url_encode(reinterpret_cast<const unsigned char*>(buf.data()), bytes);
}

std::string sha256_urlsafe(const std::string& s) {
    unsigned char d[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(s.data()), s.size(), d);
    return b64url_encode(d, SHA256_DIGEST_LENGTH);
}

std::string urlencode(const std::string& s) {
    std::ostringstream o; o << std::hex;
    for (unsigned char c : s) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') o << static_cast<char>(c);
        else o << '%' << (c < 16 ? "0" : "") << static_cast<int>(c);
    }
    return o.str();
}

// ---------- tiny JSON reader (fields we actually consume) ----------

std::string json_string_field(const std::string& src, const std::string& key) {
    std::string pat = "\"" + key + "\"";
    auto p = src.find(pat); if (p == std::string::npos) return {};
    p = src.find(':', p + pat.size()); if (p == std::string::npos) return {};
    p++;
    while (p < src.size() && std::isspace(static_cast<unsigned char>(src[p]))) p++;
    if (p >= src.size() || src[p] != '"') return {};
    p++;
    std::string out;
    while (p < src.size() && src[p] != '"') {
        if (src[p] == '\\' && p + 1 < src.size()) {
            char e = src[p + 1];
            switch (e) {
                case 'n': out += '\n'; break;
                case 't': out += '\t'; break;
                case '"': out += '"';  break;
                case '\\': out += '\\'; break;
                case '/': out += '/';  break;
                default:  out += e;
            }
            p += 2;
        } else out += src[p++];
    }
    return out;
}

long json_number_field(const std::string& src, const std::string& key) {
    std::string pat = "\"" + key + "\"";
    auto p = src.find(pat); if (p == std::string::npos) return 0;
    p = src.find(':', p + pat.size()); if (p == std::string::npos) return 0;
    p++;
    while (p < src.size() && std::isspace(static_cast<unsigned char>(src[p]))) p++;
    long v = 0; bool neg = false;
    if (p < src.size() && src[p] == '-') { neg = true; p++; }
    while (p < src.size() && src[p] >= '0' && src[p] <= '9') { v = v * 10 + (src[p] - '0'); p++; }
    return neg ? -v : v;
}

// ---------- JSON writer helpers ----------

std::string json_escape(const std::string& s) {
    std::string o; o.reserve(s.size() + 4);
    for (char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) { char b[8]; std::snprintf(b, sizeof b, "\\u%04x", c); o += b; }
                else o += c;
        }
    }
    return o;
}

std::string json_string_array(const std::vector<std::string>& values) {
    std::string out = "[";
    for (std::size_t i = 0; i < values.size(); i++) {
        if (i > 0) out += ',';
        out += "\"" + json_escape(values[i]) + "\"";
    }
    out += ']';
    return out;
}

// ---------- state stores ----------

struct PendingFlow {
    std::string verifier;
    std::string nonce;
    std::chrono::steady_clock::time_point expires;
};

struct Session {
    std::string sub, email, username, picture;
    std::chrono::steady_clock::time_point expires;
};

struct ScanJob {
    std::string id;
    std::string target;      // display label; may be "host (ip)"
    std::string scan_ip;     // dotted IPv4 the scanner actually connects to
    int port_start = 0;
    int port_end   = 0;
    std::atomic<int> status{0};   // 0=queued 1=running 2=done 3=error
    std::atomic<int> scanned{0};  // live progress; updated per port probed
    long started_at   = 0;
    long completed_at = 0;
    std::mutex results_mu;
    std::vector<core::Port>    ports;
    std::vector<core::Finding> findings;
    std::string error;
};

long now_epoch() {
    return static_cast<long>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

std::string status_str(int s) {
    switch (s) { case 0: return "queued"; case 1: return "running"; case 2: return "done"; case 3: return "error"; default: return "unknown"; }
}

// ---------- Cookie helpers ----------

std::string cookie_value(const httplib::Request& req, const std::string& name) {
    if (!req.has_header("Cookie")) return {};
    std::string cookies = req.get_header_value("Cookie");
    std::string prefix = name + "=";
    for (size_t i = 0; i < cookies.size(); ) {
        while (i < cookies.size() && (cookies[i] == ' ' || cookies[i] == ';')) i++;
        size_t end = cookies.find(';', i);
        std::string kv = cookies.substr(i, end == std::string::npos ? std::string::npos : end - i);
        if (kv.rfind(prefix, 0) == 0) return kv.substr(prefix.size());
        if (end == std::string::npos) break;
        i = end + 1;
    }
    return {};
}

// ---------- HTTPS calls ----------

std::string http_post_form(const std::string& host, const std::string& path,
                           const std::string& body) {
    httplib::Client cli(host);
    cli.set_connection_timeout(10, 0);
    cli.set_read_timeout(15, 0);
    cli.enable_server_certificate_verification(true);
    auto res = cli.Post(path, body, "application/x-www-form-urlencoded");
    return res ? res->body : std::string{};
}

std::string http_get_bearer(const std::string& host, const std::string& path,
                            const std::string& bearer) {
    httplib::Client cli(host);
    cli.set_connection_timeout(10, 0);
    cli.set_read_timeout(15, 0);
    cli.enable_server_certificate_verification(true);
    httplib::Headers h = {{"Authorization", "Bearer " + bearer}, {"Accept", "application/json"}};
    auto res = cli.Get(path, h);
    return res ? res->body : std::string{};
}

// ---------- id_token decode (unverified signature — TODO: JWKS RS256) ----------

struct IdTokenClaims { std::string iss, sub, aud, email, nonce; long exp = 0; };

std::optional<IdTokenClaims> decode_id_token(const std::string& jwt) {
    auto p1 = jwt.find('.');
    auto p2 = (p1 == std::string::npos) ? std::string::npos : jwt.find('.', p1 + 1);
    if (p1 == std::string::npos || p2 == std::string::npos) return std::nullopt;
    std::string payload = b64url_decode(jwt.substr(p1 + 1, p2 - p1 - 1));
    if (payload.empty()) return std::nullopt;
    IdTokenClaims c;
    c.iss   = json_string_field(payload, "iss");
    c.sub   = json_string_field(payload, "sub");
    c.aud   = json_string_field(payload, "aud");
    c.email = json_string_field(payload, "email");
    c.nonce = json_string_field(payload, "nonce");
    c.exp   = json_number_field(payload, "exp");
    return c;
}

// ---------- HTML pages ----------

const char* LOGIN_HTML = R"HTML(<!doctype html><html><head><meta charset="utf-8"><title>ZeroTrust — Sign in</title>
<style>
html,body{margin:0;padding:0;font-family:-apple-system,system-ui,sans-serif;background:#f6f7fb;color:#111}
.wrap{max-width:380px;margin:12vh auto;padding:32px;background:#fff;border-radius:16px;
box-shadow:0 1px 3px rgba(0,0,0,.06),0 8px 24px rgba(0,0,0,.04)}
h1{margin:0 0 8px;font-size:22px}
p{color:#555;margin:0 0 24px;font-size:14px;line-height:1.5}
a.btn{display:block;background:#111;color:#fff;padding:12px 16px;border-radius:10px;
text-align:center;text-decoration:none;font-weight:600;font-size:14px}
a.btn:hover{background:#000}
.lock{width:38px;height:38px;background:#111;border-radius:10px;display:flex;align-items:center;justify-content:center;margin-bottom:16px;color:#fff;font-weight:700}
small{display:block;margin-top:16px;color:#888;font-size:12px;text-align:center}
</style></head><body><div class="wrap">
<div class="lock">ZT</div>
<h1>Sign in to ZeroTrust</h1>
<p>Use your AGG One account. This device is a public OIDC client and uses PKCE — no shared secret leaves your machine.</p>
<a class="btn" href="/auth/start">Continue with AGG One</a>
<small>zerotrust · public + pkce</small>
</div></body></html>
)HTML";

const char* DASHBOARD_HTML = R"HTML(<!doctype html><html><head><meta charset="utf-8"><title>ZeroTrust — Dashboard</title>
<style>
:root{--fg:#111;--muted:#666;--bg:#f6f7fb;--card:#fff;--line:#ececec;--accent:#111}
html,body{margin:0;padding:0;font-family:-apple-system,system-ui,sans-serif;background:var(--bg);color:var(--fg)}
header{background:var(--card);padding:14px 24px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between}
header .brand{font-weight:700}
header .who{display:flex;align-items:center;gap:12px;font-size:14px}
header .who img{width:28px;height:28px;border-radius:50%}
header a{color:var(--muted);font-size:13px;text-decoration:none}
header a:hover{color:var(--fg)}
main{max-width:1100px;margin:24px auto;padding:0 24px}
.card{background:var(--card);border-radius:14px;padding:20px 24px;box-shadow:0 1px 2px rgba(0,0,0,.04);margin-bottom:16px}
h1{font-size:20px;margin:0 0 4px}
h2{font-size:12px;margin:0 0 12px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.06em}
form.new-scan{display:grid;grid-template-columns:1fr 100px 100px auto;gap:8px;align-items:center}
input,button{font:inherit;font-size:14px}
input[type=text],input[type=number]{border:1px solid var(--line);padding:9px 12px;border-radius:8px;background:#fff}
input:focus{outline:2px solid #ddd}
button{background:var(--accent);color:#fff;border:0;padding:10px 16px;border-radius:8px;font-weight:600;cursor:pointer}
button:hover{background:#000}
button:disabled{opacity:.5;cursor:not-allowed}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{padding:9px 10px;text-align:left;border-bottom:1px solid #f0f0f0}
th{color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.05em}
tr:hover td{background:#fafbff;cursor:pointer}
.badge{display:inline-block;padding:2px 8px;border-radius:6px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em}
.badge-running{background:#fef3c7;color:#92400e}
.badge-done{background:#dcfce7;color:#166534}
.badge-error{background:#fee2e2;color:#991b1b}
.badge-queued{background:#e5e7eb;color:#374151}
.sev{padding:2px 8px;border-radius:6px;font-size:11px;font-weight:600}
.sev-INFO{background:#e0e7ff;color:#3730a3}
.sev-LOW{background:#fef3c7;color:#92400e}
.sev-MEDIUM{background:#fed7aa;color:#9a3412}
.sev-HIGH{background:#fecaca;color:#991b1b}
.sev-CRITICAL{background:#111;color:#fff}
pre.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;color:#333;white-space:pre-wrap;word-break:break-all;margin:0}
</style></head><body>
<header>
  <div class="brand">ZeroTrust</div>
  <div class="who">
    <img id="avatar" alt="">
    <span id="whoami">…</span>
    <a href="/logout">Sign out</a>
  </div>
</header>
<main>

<div class="card">
  <h1>New scan</h1>
  <p style="color:#666;font-size:13px;margin:0 0 12px">TCP port range scan with service fingerprinting, ZTL plugins and CVE lookup.</p>
  <form class="new-scan" onsubmit="event.preventDefault();startScan();">
    <input id="target"    type="text"   placeholder="target IP or hostname"  required>
    <input id="pstart"    type="number" placeholder="start port" min="1" max="65535" value="1" required>
    <input id="pend"      type="number" placeholder="end port"   min="1" max="65535" value="1024" required>
    <button id="go" type="submit">Scan</button>
  </form>
  <p id="err" style="color:#991b1b;font-size:13px;margin:12px 0 0"></p>
</div>

<div class="card">
  <h2>Scans</h2>
  <table>
    <thead><tr><th>ID</th><th>Target</th><th>Range</th><th>Status</th><th>Scanned</th><th>Open</th><th>Findings</th><th>Started</th></tr></thead>
    <tbody id="scans"></tbody>
  </table>
</div>

<div class="card" id="details" hidden>
  <h2 id="detailsTitle">Scan details</h2>
  <div id="detailsBody"></div>
</div>

</main>
<script>
async function j(url,opts){const r=await fetch(url,{credentials:'include',...opts});if(!r.ok)throw new Error(await r.text());return r.json()}
async function loadMe(){try{const m=await j('/me');document.getElementById('whoami').textContent=m.email||m.username||'signed in';if(m.picture)document.getElementById('avatar').src=m.picture}catch(e){location.href='/login'}}
function fmtTime(t){if(!t)return '-';const d=new Date(t*1000);return d.toLocaleTimeString()}
function escapeHtml(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
async function loadScans(){const l=await j('/api/scans');const tb=document.getElementById('scans');tb.innerHTML='';for(const s of l.scans){const tr=document.createElement('tr');tr.onclick=()=>openScan(s.id);const range=`${s.port_start}-${s.port_end}`;const total=s.port_end-s.port_start+1;const scanned=s.scanned_ports||(s.status==='done'?total:0);tr.innerHTML=`<td><code>${s.id.slice(0,8)}</code></td><td>${escapeHtml(s.target)}</td><td>${range}</td><td><span class="badge badge-${s.status}">${s.status}</span></td><td>${scanned}/${total}</td><td>${s.open_ports}</td><td>${s.findings}</td><td>${fmtTime(s.started_at)}</td>`;tb.appendChild(tr)}}
async function startScan(){document.getElementById('err').textContent='';const b={target:document.getElementById('target').value.trim(),port_start:+document.getElementById('pstart').value,port_end:+document.getElementById('pend').value};try{const r=await j('/api/scans',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});await loadScans();openScan(r.id)}catch(e){document.getElementById('err').textContent=e.message||'scan start failed'}}

// Live view state — one at a time. New scan replaces the previous stream.
let liveState=null;
let liveStream=null;

function renderLive(){
  const s=liveState;if(!s)return;
  const el=document.getElementById('details');const body=document.getElementById('detailsBody');
  const total=s.port_end-s.port_start+1;
  const scanBar=s.scanned!=null?`<div style="height:4px;background:#eee;border-radius:2px;overflow:hidden;margin:8px 0 12px"><div style="height:100%;background:#111;width:${Math.min(100,(s.scanned/total*100)).toFixed(1)}%"></div></div><p style="color:#666;font-size:12px;margin:-8px 0 12px">${s.scanned}/${total} ports probed</p>`:'';
  document.getElementById('detailsTitle').textContent=`Scan ${s.id.slice(0,8)} — ${s.target} — ${s.status}`;
  el.hidden=false;
  let h=scanBar;
  h+='<h2 style="margin-top:8px">Open ports</h2>';
  if(!s.ports.length)h+='<p style="color:#666;font-size:13px">none yet</p>';
  else{h+='<table><thead><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th></tr></thead><tbody>';for(const p of s.ports)h+=`<tr><td>${p.number}/tcp</td><td>${escapeHtml(p.service)}</td><td>${escapeHtml(p.product)}</td><td>${escapeHtml(p.version)}</td></tr>`;h+='</tbody></table>'}
  h+='<h2 style="margin-top:20px">Findings</h2>';
  if(!s.findings.length)h+='<p style="color:#666;font-size:13px">none yet</p>';
    else{h+='<table><thead><tr><th>Sev</th><th>Verification</th><th>Confidence</th><th>Port</th><th>Title</th></tr></thead><tbody>';for(const f of s.findings)h+=`<tr><td><span class="sev sev-${f.severity}">${f.severity}</span></td><td>${escapeHtml(f.verification_label||f.verification||'Verification unknown')}</td><td>${escapeHtml(String(f.confidence_score??f.confidence??0))}</td><td>${f.port_number}/tcp</td><td>${escapeHtml(f.title)}<br><pre class="mono">${escapeHtml(f.description)}</pre></td></tr>`;h+='</tbody></table>'}
  body.innerHTML=h;
}

async function openScan(id){
  // Stop any previous live stream first.
  if(liveStream){liveStream.close();liveStream=null}
  // Seed with the full state (works whether scan is running or already done).
  const s=await j('/api/scans/'+id);
  liveState={id:s.id,target:s.target,status:s.status,port_start:s.port_start,port_end:s.port_end,scanned:s.status==='done'?(s.port_end-s.port_start+1):0,ports:s.ports||[],findings:s.findings||[]};
  renderLive();
  if(s.status!=='running'&&s.status!=='queued')return;
  // Subscribe to the live event stream for progress + new results.
  const es=new EventSource('/api/scans/'+id+'/stream');
  liveStream=es;
  es.addEventListener('progress',ev=>{const d=JSON.parse(ev.data);liveState.scanned=d.scanned;renderLive()});
  es.addEventListener('port',ev=>{liveState.ports.push(JSON.parse(ev.data));liveState.ports.sort((a,b)=>a.number-b.number);renderLive()});
  es.addEventListener('finding',ev=>{liveState.findings.push(JSON.parse(ev.data));liveState.findings.sort((a,b)=>a.port_number-b.port_number);renderLive()});
  es.addEventListener('status',ev=>{const d=JSON.parse(ev.data);liveState.status=d.status;renderLive()});
  es.addEventListener('end',()=>{es.close();liveStream=null;loadScans()});
  es.onerror=()=>{es.close();liveStream=null};
}

loadMe();loadScans();setInterval(loadScans,3000);
</script></body></html>
)HTML";

// ---------- Server implementation ----------

class Server {
public:
    Server(const webui::Config& cfg, const std::vector<ztl::LoadedPlugin>& plugins,
           core::Db* db)
        : cfg_(cfg), plugins_(plugins), db_(db) {}

    int run() {
        srv_.Get("/",           [&](const httplib::Request& r, httplib::Response& s){ root(r, s); });
        srv_.Get("/login",      [&](const httplib::Request&, httplib::Response& s){ s.set_content(LOGIN_HTML, "text/html; charset=utf-8"); });
        srv_.Get("/auth/start", [&](const httplib::Request&, httplib::Response& s){ auth_start(s); });
        srv_.Get("/callback",   [&](const httplib::Request& r, httplib::Response& s){ callback(r, s); });
        srv_.Get("/logout",     [&](const httplib::Request& r, httplib::Response& s){ logout(r, s); });
        srv_.Get("/me",         [&](const httplib::Request& r, httplib::Response& s){ me(r, s); });

        srv_.Get("/api/scans",  [&](const httplib::Request& r, httplib::Response& s){ list_scans(r, s); });
        srv_.Post("/api/scans", [&](const httplib::Request& r, httplib::Response& s){ start_scan(r, s); });
        srv_.Get(R"(/api/scans/([A-Za-z0-9_-]+))", [&](const httplib::Request& r, httplib::Response& s){ get_scan(r, s); });
        srv_.Get(R"(/api/scans/([A-Za-z0-9_-]+)/stream)", [&](const httplib::Request& r, httplib::Response& s){ stream_scan(r, s); });

        std::cout << "zerotrust webui listening on " << cfg_.public_url << "/\n"
                  << "  Register this redirect URI in AGG One: " << cfg_.redirect_uri << "\n"
                  << "  Ctrl-C to stop\n" << std::flush;

        return srv_.listen(cfg_.listen_host, cfg_.listen_port) ? 0 : 1;
    }

private:
    webui::Config cfg_;
    const std::vector<ztl::LoadedPlugin>& plugins_;
    core::Db* db_ = nullptr;
    std::mutex db_mu_;
    httplib::Server srv_;

    std::mutex flow_mu_;
    std::unordered_map<std::string, PendingFlow> pending_;

    std::mutex sess_mu_;
    std::unordered_map<std::string, Session> sessions_;

    std::mutex jobs_mu_;
    std::unordered_map<std::string, std::shared_ptr<ScanJob>> jobs_;
    std::vector<std::string> jobs_order_;

    // ---- auth helpers ----

    std::optional<Session> get_session(const httplib::Request& req) {
        std::string sid = cookie_value(req, "zt_session");
        if (sid.empty()) return std::nullopt;
        std::lock_guard<std::mutex> g(sess_mu_);
        auto it = sessions_.find(sid);
        if (it == sessions_.end()) return std::nullopt;
        if (std::chrono::steady_clock::now() > it->second.expires) { sessions_.erase(it); return std::nullopt; }
        return it->second;
    }

    bool require_session(const httplib::Request& req, httplib::Response& res) {
        auto s = get_session(req);
        if (!s) { res.status = 401; res.set_content("{\"error\":\"not_signed_in\"}", "application/json"); return false; }
        return true;
    }

    // ---- routes ----

    void root(const httplib::Request& req, httplib::Response& res) {
        auto s = get_session(req);
        if (!s) { res.set_redirect("/login"); return; }
        res.set_content(DASHBOARD_HTML, "text/html; charset=utf-8");
    }

    void auth_start(httplib::Response& res) {
        std::string verifier  = random_urlsafe(32);
        std::string challenge = sha256_urlsafe(verifier);
        std::string state     = random_urlsafe(24);
        std::string nonce     = random_urlsafe(24);
        {
            std::lock_guard<std::mutex> g(flow_mu_);
            pending_[state] = { verifier, nonce,
                std::chrono::steady_clock::now() + std::chrono::seconds(600) };
        }
        std::string u = cfg_.authorize_url
            + "?response_type=code"
            + "&client_id="             + urlencode(cfg_.client_id)
            + "&redirect_uri="          + urlencode(cfg_.redirect_uri)
            + "&scope="                 + urlencode(cfg_.scopes)
            + "&state="                 + urlencode(state)
            + "&nonce="                 + urlencode(nonce)
            + "&code_challenge="        + urlencode(challenge)
            + "&code_challenge_method=S256";
        res.set_redirect(u);
    }

    void callback(const httplib::Request& req, httplib::Response& res) {
        if (req.has_param("error")) { res.status = 400; res.set_content("SSO error: " + req.get_param_value("error"), "text/plain"); return; }
        if (!req.has_param("code") || !req.has_param("state")) { res.status = 400; res.set_content("missing code/state", "text/plain"); return; }
        std::string code  = req.get_param_value("code");
        std::string state = req.get_param_value("state");

        PendingFlow flow;
        {
            std::lock_guard<std::mutex> g(flow_mu_);
            auto it = pending_.find(state);
            if (it == pending_.end()) { res.status = 400; res.set_content("unknown state", "text/plain"); return; }
            if (std::chrono::steady_clock::now() > it->second.expires) { pending_.erase(it); res.status = 400; res.set_content("state expired", "text/plain"); return; }
            flow = it->second;
            pending_.erase(it);
        }

        std::string body =
            "grant_type=authorization_code"
            "&code="          + urlencode(code)
            + "&redirect_uri="  + urlencode(cfg_.redirect_uri)
            + "&client_id="     + urlencode(cfg_.client_id)
            + "&code_verifier=" + urlencode(flow.verifier);

        std::string token_json = http_post_form(cfg_.token_host, cfg_.token_path, body);
        if (token_json.empty()) { res.status = 502; res.set_content("token endpoint unreachable", "text/plain"); return; }

        std::string access_token = json_string_field(token_json, "access_token");
        std::string id_token     = json_string_field(token_json, "id_token");
        if (access_token.empty() || id_token.empty()) { res.status = 400; res.set_content("token exchange failed: " + token_json, "text/plain"); return; }

        auto claims = decode_id_token(id_token);
        if (!claims)                     { res.status = 400; res.set_content("bad id_token", "text/plain"); return; }
        if (claims->iss != cfg_.issuer)  { res.status = 401; res.set_content("bad iss: " + claims->iss, "text/plain"); return; }
        if (claims->aud != cfg_.client_id){ res.status = 401; res.set_content("bad aud: " + claims->aud, "text/plain"); return; }
        if (claims->nonce != flow.nonce) { res.status = 401; res.set_content("nonce mismatch", "text/plain"); return; }
        if (claims->exp > 0 && now_epoch() > claims->exp) { res.status = 401; res.set_content("id_token expired", "text/plain"); return; }

        std::string ui = http_get_bearer(cfg_.token_host, cfg_.userinfo_path, access_token);

        Session sess;
        sess.sub     = claims->sub;
        sess.email   = claims->email.empty() ? json_string_field(ui, "email") : claims->email;
        sess.username = json_string_field(ui, "preferred_username");
        if (sess.username.empty()) sess.username = json_string_field(ui, "username");
        sess.picture = json_string_field(ui, "picture");
        sess.expires = std::chrono::steady_clock::now() + std::chrono::seconds(cfg_.session_ttl_s);

        std::string sid = random_urlsafe(32);
        { std::lock_guard<std::mutex> g(sess_mu_); sessions_[sid] = sess; }

        std::string cookie = "zt_session=" + sid
            + "; HttpOnly; SameSite=Lax; Path=/; Max-Age=" + std::to_string(cfg_.session_ttl_s);
        res.set_header("Set-Cookie", cookie);
        res.set_redirect("/");
    }

    void logout(const httplib::Request& req, httplib::Response& res) {
        std::string sid = cookie_value(req, "zt_session");
        if (!sid.empty()) { std::lock_guard<std::mutex> g(sess_mu_); sessions_.erase(sid); }
        res.set_header("Set-Cookie", "zt_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");
        res.set_redirect("/login");
    }

    void me(const httplib::Request& req, httplib::Response& res) {
        if (!require_session(req, res)) return;
        auto s = get_session(req);
        std::ostringstream o;
        o << "{\"sub\":\"" << json_escape(s->sub) << "\","
          << "\"email\":\"" << json_escape(s->email) << "\","
          << "\"username\":\"" << json_escape(s->username) << "\","
          << "\"picture\":\"" << json_escape(s->picture) << "\"}";
        res.set_content(o.str(), "application/json");
    }

    // ---- scan endpoints ----

    void start_scan(const httplib::Request& req, httplib::Response& res) {
        if (!require_session(req, res)) return;
        auto ses = get_session(req);

        std::string target = json_string_field(req.body, "target");
        long ps = json_number_field(req.body, "port_start");
        long pe = json_number_field(req.body, "port_end");
        if (target.empty() || ps <= 0 || pe <= 0 || pe < ps || pe > 65535) {
            res.status = 400;
            res.set_content("{\"error\":\"invalid_input\"}", "application/json");
            return;
        }

        // The TCP layer only accepts dotted IPv4. Resolve hostnames via the
        // built-in DNS client before spawning the scan; keep the resolved IP
        // as the target the job actually runs against, so results are honest.
        std::string resolved = target;
        sockaddr_in probe{};
        if (inet_pton(AF_INET, target.c_str(), &probe.sin_addr) != 1) {
            auto ip = dns::resolve(target, 2000);
            if (!ip) {
                res.status = 400;
                res.set_content("{\"error\":\"dns_failed\",\"message\":\"could not resolve " + json_escape(target) + "\"}",
                                "application/json");
                return;
            }
            resolved = *ip;
        }

        auto job = std::make_shared<ScanJob>();
        job->id         = random_urlsafe(16);
        job->target     = (resolved == target) ? target : (target + " (" + resolved + ")");
        job->scan_ip    = resolved;
        job->port_start = static_cast<int>(ps);
        job->port_end   = static_cast<int>(pe);
        job->started_at = now_epoch();

        {
            std::lock_guard<std::mutex> g(jobs_mu_);
            jobs_[job->id] = job;
            jobs_order_.push_back(job->id);
        }

        if (db_) {
            core::ScanRow row;
            row.id            = job->id;
            row.user_sub      = ses ? ses->sub : "";
            row.target        = job->target;
            row.port_start    = job->port_start;
            row.port_end      = job->port_end;
            row.status        = "queued";
            row.started_at    = job->started_at;
            std::lock_guard<std::mutex> g(db_mu_);
            db_->upsert_scan(row);
        }

        std::thread([this, job]() {
            job->status = 1;
            if (db_) {
                std::lock_guard<std::mutex> g(db_mu_);
                db_->update_scan_status(job->id, "running", 0, 0, "");
            }
            try {
                scan::LiveSink sink;
                sink.progress = &job->scanned;
                sink.on_port_open = [job](const core::Port& p, const std::vector<core::Finding>& fs) {
                    std::lock_guard<std::mutex> g(job->results_mu);
                    job->ports.push_back(p);
                    for (const auto& f : fs) job->findings.push_back(f);
                };
                auto r = scan::tcp_range_scan(job->scan_ip, job->port_start, job->port_end, plugins_, sink);
                job->status = 2;
                job->completed_at = now_epoch();
                if (db_) {
                    std::lock_guard<std::mutex> g(db_mu_);
                    db_->update_scan_status(job->id, "done", job->completed_at, job->scanned.load(), "");
                    // Save the sorted authoritative results (return value) — the
                    // live-pushed vectors are the same rows in probe-completion
                    // order; use r.* for stable ordering on reload.
                    db_->save_ports(job->id, r.ports);
                    db_->save_findings(job->id, r.findings);
                }
            } catch (const std::exception& e) {
                {
                    std::lock_guard<std::mutex> g(job->results_mu);
                    job->error  = e.what();
                }
                job->status = 3;
                job->completed_at = now_epoch();
                if (db_) {
                    std::lock_guard<std::mutex> g(db_mu_);
                    db_->update_scan_status(job->id, "error", job->completed_at, 0, e.what());
                }
            }
        }).detach();

        std::ostringstream o;
        o << "{\"id\":\"" << job->id << "\",\"status\":\"queued\"}";
        res.set_content(o.str(), "application/json");
    }

    void list_scans(const httplib::Request& req, httplib::Response& res) {
        if (!require_session(req, res)) return;

        std::vector<core::ScanRow> rows;
        if (db_) { std::lock_guard<std::mutex> g(db_mu_); rows = db_->list_scans(200); }

        std::ostringstream o;
        o << "{\"scans\":[";
        bool first = true;
        for (const auto& r : rows) {
            std::shared_ptr<ScanJob> live;
            { std::lock_guard<std::mutex> g(jobs_mu_); auto it = jobs_.find(r.id); if (it != jobs_.end()) live = it->second; }

            int open = 0, findings = 0, scanned = r.scanned_ports;
            std::string status = r.status;
            if (live) {
                std::lock_guard<std::mutex> g(live->results_mu);
                open     = static_cast<int>(live->ports.size());
                findings = static_cast<int>(live->findings.size());
                status   = status_str(live->status);
                scanned  = live->scanned.load();
            } else if (db_) {
                std::lock_guard<std::mutex> g(db_mu_);
                open     = static_cast<int>(db_->load_ports(r.id).size());
                findings = static_cast<int>(db_->load_findings(r.id).size());
            }

            if (!first) o << ",";
            first = false;
            o << "{\"id\":\"" << r.id
              << "\",\"target\":\"" << json_escape(r.target)
              << "\",\"port_start\":" << r.port_start
              << ",\"port_end\":" << r.port_end
              << ",\"status\":\"" << status << "\""
              << ",\"open_ports\":" << open
              << ",\"findings\":" << findings
              << ",\"scanned_ports\":" << scanned
              << ",\"started_at\":" << r.started_at
              << ",\"completed_at\":" << r.completed_at
              << "}";
        }
        o << "]}";
        res.set_content(o.str(), "application/json");
    }

    void stream_scan(const httplib::Request& req, httplib::Response& res) {
        if (!require_session(req, res)) return;
        std::string id = req.matches[1];
        std::shared_ptr<ScanJob> job;
        { std::lock_guard<std::mutex> g(jobs_mu_); auto it = jobs_.find(id); if (it != jobs_.end()) job = it->second; }
        if (!job) { res.status = 404; res.set_content("event: end\ndata: {\"error\":\"not_found\"}\n\n", "text/event-stream"); return; }

        res.set_header("Cache-Control", "no-cache");
        res.set_header("X-Accel-Buffering", "no");

        auto job_ref = job;
        res.set_chunked_content_provider("text/event-stream",
            [job_ref](std::size_t /*offset*/, httplib::DataSink& sink) -> bool {
                std::size_t sent_ports = 0, sent_findings = 0;
                int last_scanned = -1;
                int last_status  = -1;
                // Best-effort framing: strings we push contain no embedded \n
                // that would break the SSE grammar (JSON \n is escaped).
                auto push = [&](const std::string& event, const std::string& data) {
                    std::string frame = "event: " + event + "\ndata: " + data + "\n\n";
                    return sink.write(frame.c_str(), frame.size());
                };

                // Initial snapshot so the browser doesn't wait for the first delta.
                if (!push("hello", "{}")) return false;

                for (;;) {
                    int status = job_ref->status.load();
                    int scanned = job_ref->scanned.load();

                    std::vector<core::Port>    new_ports;
                    std::vector<core::Finding> new_findings;
                    {
                        std::lock_guard<std::mutex> g(job_ref->results_mu);
                        if (job_ref->ports.size() > sent_ports) {
                            new_ports.assign(job_ref->ports.begin() + sent_ports, job_ref->ports.end());
                            sent_ports = job_ref->ports.size();
                        }
                        if (job_ref->findings.size() > sent_findings) {
                            new_findings.assign(job_ref->findings.begin() + sent_findings, job_ref->findings.end());
                            sent_findings = job_ref->findings.size();
                        }
                    }

                    if (scanned != last_scanned) {
                        std::ostringstream o;
                        o << "{\"scanned\":" << scanned << "}";
                        if (!push("progress", o.str())) return false;
                        last_scanned = scanned;
                    }
                    for (const auto& p : new_ports) {
                        std::ostringstream o;
                        o << "{\"number\":" << p.number
                          << ",\"protocol\":\"" << core::to_string(p.protocol) << "\""
                          << ",\"service\":\"" << json_escape(p.service) << "\""
                          << ",\"product\":\"" << json_escape(p.product) << "\""
                          << ",\"version\":\"" << json_escape(p.version) << "\""
                          << ",\"distro\":\"" << json_escape(p.distro) << "\""
                          << "}";
                        if (!push("port", o.str())) return false;
                    }
                    for (const auto& f : new_findings) {
                        std::ostringstream o;
                        o << "{\"plugin_name\":\"" << json_escape(f.plugin_name) << "\""
                          << ",\"title\":\"" << json_escape(f.title) << "\""
                          << ",\"description\":\"" << json_escape(f.description) << "\""
                          << ",\"severity\":\"" << core::to_string(f.severity) << "\""
                          << ",\"confidence\":" << f.confidence_score
                          << ",\"verification\":\"" << json_escape(f.verification) << "\""
                          << ",\"verification_label\":\"" << json_escape(core::verification_label(f.verification)) << "\""
                          << ",\"cve\":\"" << json_escape(f.cve_id) << "\""
                          << ",\"host\":\"" << json_escape(f.host) << "\""
                          << ",\"port_number\":" << f.port_number
                          << ",\"protocol\":\"" << core::to_string(f.protocol) << "\""
                          << ",\"scope\":\"" << json_escape(f.scope) << "\""
                          << ",\"service\":\"" << json_escape(f.service) << "\""
                          << ",\"product\":\"" << json_escape(f.product) << "\""
                          << ",\"version\":\"" << json_escape(f.version) << "\""
                          << ",\"evidence\":\"" << json_escape(f.evidence) << "\""
                          << ",\"evidence_data\":{\"type\":\"" << json_escape(f.evidence_data.type)
                          << "\",\"source\":\"" << json_escape(f.evidence_data.source)
                          << "\",\"value\":\"" << json_escape(f.evidence_data.value)
                          << "\",\"details\":\"" << json_escape(f.evidence_data.details) << "\"}"
                          << ",\"references\":" << json_string_array(f.references)
                          << ",\"remediation\":\"" << json_escape(f.remediation) << "\""
                          << ",\"cvss\":" << f.cvss
                          << ",\"cvss_vector\":\"" << json_escape(f.cvss_vector) << "\""
                          << ",\"timestamp\":" << f.timestamp
                          << "}";
                        if (!push("finding", o.str())) return false;
                    }
                    if (status != last_status) {
                        std::ostringstream o;
                        o << "{\"status\":\"" << status_str(status) << "\"}";
                        if (!push("status", o.str())) return false;
                        last_status = status;
                    }

                    if (status == 2 || status == 3) {
                        push("end", "{}");
                        sink.done();
                        return true;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(200));
                }
            });
    }

    void get_scan(const httplib::Request& req, httplib::Response& res) {
        if (!require_session(req, res)) return;
        std::string id = req.matches[1];

        std::shared_ptr<ScanJob> live;
        { std::lock_guard<std::mutex> g(jobs_mu_); auto it = jobs_.find(id); if (it != jobs_.end()) live = it->second; }

        std::string target, status, error;
        int port_start = 0, port_end = 0;
        long started_at = 0, completed_at = 0;
        std::vector<core::Port>    ports;
        std::vector<core::Finding> findings;

        if (live) {
            target       = live->target;
            port_start   = live->port_start;
            port_end     = live->port_end;
            started_at   = live->started_at;
            completed_at = live->completed_at;
            status       = status_str(live->status);
            std::lock_guard<std::mutex> g(live->results_mu);
            ports    = live->ports;
            findings = live->findings;
            error    = live->error;
        } else {
            if (!db_) { res.status = 404; res.set_content("{\"error\":\"not_found\"}", "application/json"); return; }
            std::lock_guard<std::mutex> g(db_mu_);
            auto row = db_->get_scan(id);
            if (!row) { res.status = 404; res.set_content("{\"error\":\"not_found\"}", "application/json"); return; }
            target       = row->target;
            port_start   = row->port_start;
            port_end     = row->port_end;
            started_at   = row->started_at;
            completed_at = row->completed_at;
            status       = row->status;
            error        = row->error;
            ports        = db_->load_ports(id);
            findings     = db_->load_findings(id);
        }

        std::ostringstream o;
        o << "{\"id\":\"" << id
          << "\",\"target\":\"" << json_escape(target)
          << "\",\"port_start\":" << port_start
          << ",\"port_end\":" << port_end
          << ",\"status\":\"" << status << "\""
          << ",\"started_at\":" << started_at
          << ",\"completed_at\":" << completed_at
          << ",\"error\":\"" << json_escape(error) << "\"";

        o << ",\"ports\":[";
        for (size_t i = 0; i < ports.size(); i++) {
            const auto& p = ports[i];
            if (i) o << ",";
            o << "{\"number\":" << p.number
              << ",\"protocol\":\""  << core::to_string(p.protocol) << "\""
              << ",\"service\":\""   << json_escape(p.service) << "\""
              << ",\"product\":\""   << json_escape(p.product) << "\""
              << ",\"version\":\""   << json_escape(p.version) << "\""
              << ",\"distro\":\""    << json_escape(p.distro)  << "\""
              << "}";
        }
        o << "]";

        o << ",\"findings\":[";
        for (size_t i = 0; i < findings.size(); i++) {
            const auto& f = findings[i];
            if (i) o << ",";
            o << "{\"plugin_name\":\"" << json_escape(f.plugin_name)     << "\""
              << ",\"title\":\""       << json_escape(f.title)           << "\""
              << ",\"description\":\"" << json_escape(f.description)     << "\""
              << ",\"severity\":\""    << core::to_string(f.severity)    << "\""
              << ",\"confidence\":"    << f.confidence_score
              << ",\"verification\":\"" << json_escape(f.verification) << "\""
              << ",\"verification_label\":\"" << json_escape(core::verification_label(f.verification)) << "\""
              << ",\"cve\":\""          << json_escape(f.cve_id)         << "\""
              << ",\"host\":\""          << json_escape(f.host)            << "\""
              << ",\"port_number\":"   << f.port_number
              << ",\"protocol\":\""    << core::to_string(f.protocol)    << "\""
              << ",\"scope\":\""       << json_escape(f.scope)           << "\""
              << ",\"service\":\""     << json_escape(f.service)         << "\""
              << ",\"product\":\""     << json_escape(f.product)         << "\""
              << ",\"version\":\""     << json_escape(f.version)         << "\""
              << ",\"evidence\":\""    << json_escape(f.evidence)        << "\""
              << ",\"evidence_data\":{\"type\":\"" << json_escape(f.evidence_data.type)
              << "\",\"source\":\"" << json_escape(f.evidence_data.source)
              << "\",\"value\":\"" << json_escape(f.evidence_data.value)
              << "\",\"details\":\"" << json_escape(f.evidence_data.details) << "\"}"
              << ",\"references\":" << json_string_array(f.references)
              << ",\"remediation\":\"" << json_escape(f.remediation)      << "\""
              << ",\"cvss\":"          << f.cvss
              << ",\"cvss_vector\":\"" << json_escape(f.cvss_vector)     << "\""
              << ",\"timestamp\":"      << f.timestamp
              << "}";
        }
        o << "]";
        o << "}";
        res.set_content(o.str(), "application/json");
    }
};

} // namespace

namespace webui {
    int run(const Config& cfg, const std::vector<ztl::LoadedPlugin>& plugins,
            const std::string& db_path) {
        core::Db db;
        core::Db* db_ptr = nullptr;
        if (db.open(db_path)) {
            db_ptr = &db;
            logging::info("scan history: " + db_path);
        } else {
            logging::warn("scan history: db unavailable; scans will not persist");
        }
        Server s(cfg, plugins, db_ptr);
        return s.run();
    }
}
