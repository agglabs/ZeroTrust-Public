// db.cpp

#include "core/db.hpp"
#include "logging/logging.hpp"

#include <sqlite3.h>

#include <stdexcept>
#include <sstream>

namespace core {
    namespace {
        std::string join_references(const std::vector<std::string>& references) {
            std::string out;
            for (const std::string& reference : references) {
                if (!out.empty()) out += '|';
                out += reference;
            }
            return out;
        }

        std::vector<std::string> split_references(const char* value) {
            std::vector<std::string> out;
            if (!value) return out;
            std::istringstream stream(value);
            std::string reference;
            while (std::getline(stream, reference, '|')) {
                if (!reference.empty()) out.push_back(reference);
            }
            return out;
        }
    }

    Db::Db() = default;
    Db::~Db() { if (db_) sqlite3_close(db_); }

    void Db::exec_(const std::string& sql) {
        char* err = nullptr;
        int rc = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err);
        if (rc != SQLITE_OK) {
            std::string msg = err ? err : "sqlite error";
            sqlite3_free(err);
            throw std::runtime_error("db exec failed: " + msg);
        }
    }

    bool Db::open(const std::string& path) {
        if (sqlite3_open(path.c_str(), &db_) != SQLITE_OK) {
            logging::error("cannot open db: " + std::string(sqlite3_errmsg(db_)));
            return false;
        }
        try {
            exec_("PRAGMA journal_mode=WAL");
            exec_("PRAGMA synchronous=NORMAL");
            exec_(R"(
                CREATE TABLE IF NOT EXISTS scans (
                    id             TEXT PRIMARY KEY,
                    user_sub       TEXT NOT NULL DEFAULT '',
                    target         TEXT NOT NULL,
                    port_start     INTEGER NOT NULL,
                    port_end       INTEGER NOT NULL,
                    status         TEXT NOT NULL,
                    started_at     INTEGER NOT NULL,
                    completed_at   INTEGER NOT NULL DEFAULT 0,
                    scanned_ports  INTEGER NOT NULL DEFAULT 0,
                    error          TEXT NOT NULL DEFAULT ''
                );
            )");
            exec_("CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at DESC)");
            exec_(R"(
                CREATE TABLE IF NOT EXISTS scan_ports (
                    scan_id     TEXT NOT NULL,
                    number      INTEGER NOT NULL,
                    protocol    TEXT NOT NULL,
                    service     TEXT NOT NULL DEFAULT '',
                    product     TEXT NOT NULL DEFAULT '',
                    version     TEXT NOT NULL DEFAULT '',
                    distro      TEXT NOT NULL DEFAULT '',
                    tls         INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY(scan_id, number, protocol)
                );
            )");
            exec_(R"(
                CREATE TABLE IF NOT EXISTS scan_findings (
                    scan_id      TEXT NOT NULL,
                    idx          INTEGER NOT NULL,
                    plugin_name  TEXT NOT NULL DEFAULT '',
                    title        TEXT NOT NULL DEFAULT '',
                    description  TEXT NOT NULL DEFAULT '',
                    severity     TEXT NOT NULL DEFAULT 'INFO',
                    confidence   TEXT NOT NULL DEFAULT 'UNKNOWN',
                    confidence_score REAL NOT NULL DEFAULT 0,
                    verification TEXT NOT NULL DEFAULT 'UNKNOWN',
                    host         TEXT NOT NULL DEFAULT '',
                    port_number  INTEGER NOT NULL DEFAULT 0,
                    protocol     TEXT NOT NULL DEFAULT 'UNKNOWN',
                    scope        TEXT NOT NULL DEFAULT 'PORT',
                    service      TEXT NOT NULL DEFAULT '',
                    product      TEXT NOT NULL DEFAULT '',
                    version      TEXT NOT NULL DEFAULT '',
                    evidence     TEXT NOT NULL DEFAULT '',
                    evidence_type TEXT NOT NULL DEFAULT '',
                    evidence_source TEXT NOT NULL DEFAULT '',
                    evidence_details TEXT NOT NULL DEFAULT '',
                    reference_list TEXT NOT NULL DEFAULT '',
                    remediation  TEXT NOT NULL DEFAULT '',
                    cvss         REAL NOT NULL DEFAULT -1,
                    cvss_vector  TEXT NOT NULL DEFAULT '',
                    timestamp    INTEGER NOT NULL DEFAULT 0,
                    cve_id       TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY(scan_id, idx)
                );
            )");
            auto ensure_finding_column = [&](const char* column, const char* definition) {
                bool exists = false;
                sqlite3_stmt* columns = nullptr;
                if (sqlite3_prepare_v2(db_, "PRAGMA table_info(scan_findings)", -1, &columns, nullptr) == SQLITE_OK) {
                    while (sqlite3_step(columns) == SQLITE_ROW) {
                        const unsigned char* name = sqlite3_column_text(columns, 1);
                        if (name && std::string(reinterpret_cast<const char*>(name)) == column) {
                            exists = true;
                            break;
                        }
                    }
                }
                if (columns) sqlite3_finalize(columns);
                if (!exists) exec_(std::string("ALTER TABLE scan_findings ADD COLUMN ") + column + " " + definition);
            };
            ensure_finding_column("confidence_score", "REAL NOT NULL DEFAULT 0");
            ensure_finding_column("verification", "TEXT NOT NULL DEFAULT 'UNKNOWN'");
            ensure_finding_column("host", "TEXT NOT NULL DEFAULT ''");
            ensure_finding_column("protocol", "TEXT NOT NULL DEFAULT 'UNKNOWN'");
            ensure_finding_column("scope", "TEXT NOT NULL DEFAULT 'PORT'");
            ensure_finding_column("product", "TEXT NOT NULL DEFAULT ''");
            ensure_finding_column("version", "TEXT NOT NULL DEFAULT ''");
            ensure_finding_column("evidence", "TEXT NOT NULL DEFAULT ''");
            ensure_finding_column("evidence_type", "TEXT NOT NULL DEFAULT ''");
            ensure_finding_column("evidence_source", "TEXT NOT NULL DEFAULT ''");
            ensure_finding_column("evidence_details", "TEXT NOT NULL DEFAULT ''");
            ensure_finding_column("reference_list", "TEXT NOT NULL DEFAULT ''");
            ensure_finding_column("remediation", "TEXT NOT NULL DEFAULT ''");
            ensure_finding_column("cvss", "REAL NOT NULL DEFAULT -1");
            ensure_finding_column("cvss_vector", "TEXT NOT NULL DEFAULT ''");
            ensure_finding_column("timestamp", "INTEGER NOT NULL DEFAULT 0");
        } catch (const std::exception& e) {
            logging::error(std::string("db schema init failed: ") + e.what());
            return false;
        }
        return true;
    }

    // ---- scans ----

    void Db::upsert_scan(const ScanRow& r) {
        const char* sql =
            "INSERT INTO scans(id,user_sub,target,port_start,port_end,status,started_at,completed_at,scanned_ports,error) "
            "VALUES(?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET "
            "status=excluded.status,completed_at=excluded.completed_at,"
            "scanned_ports=excluded.scanned_ports,error=excluded.error";
        sqlite3_stmt* st = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &st, nullptr) != SQLITE_OK) return;
        sqlite3_bind_text (st, 1, r.id.c_str(),       -1, SQLITE_TRANSIENT);
        sqlite3_bind_text (st, 2, r.user_sub.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text (st, 3, r.target.c_str(),   -1, SQLITE_TRANSIENT);
        sqlite3_bind_int  (st, 4, r.port_start);
        sqlite3_bind_int  (st, 5, r.port_end);
        sqlite3_bind_text (st, 6, r.status.c_str(),   -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 7, r.started_at);
        sqlite3_bind_int64(st, 8, r.completed_at);
        sqlite3_bind_int  (st, 9, r.scanned_ports);
        sqlite3_bind_text (st,10, r.error.c_str(),    -1, SQLITE_TRANSIENT);
        sqlite3_step(st);
        sqlite3_finalize(st);
    }

    void Db::update_scan_status(const std::string& id, const std::string& status,
                                long completed_at, int scanned_ports,
                                const std::string& error) {
        const char* sql =
            "UPDATE scans SET status=?, completed_at=?, scanned_ports=?, error=? WHERE id=?";
        sqlite3_stmt* st = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &st, nullptr) != SQLITE_OK) return;
        sqlite3_bind_text (st, 1, status.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, completed_at);
        sqlite3_bind_int  (st, 3, scanned_ports);
        sqlite3_bind_text (st, 4, error.c_str(),  -1, SQLITE_TRANSIENT);
        sqlite3_bind_text (st, 5, id.c_str(),     -1, SQLITE_TRANSIENT);
        sqlite3_step(st);
        sqlite3_finalize(st);
    }

    static ScanRow row_from_stmt(sqlite3_stmt* st) {
        ScanRow r;
        r.id            = reinterpret_cast<const char*>(sqlite3_column_text(st, 0));
        r.user_sub      = reinterpret_cast<const char*>(sqlite3_column_text(st, 1));
        r.target        = reinterpret_cast<const char*>(sqlite3_column_text(st, 2));
        r.port_start    = sqlite3_column_int(st, 3);
        r.port_end      = sqlite3_column_int(st, 4);
        r.status        = reinterpret_cast<const char*>(sqlite3_column_text(st, 5));
        r.started_at    = sqlite3_column_int64(st, 6);
        r.completed_at  = sqlite3_column_int64(st, 7);
        r.scanned_ports = sqlite3_column_int(st, 8);
        const unsigned char* err = sqlite3_column_text(st, 9);
        if (err) r.error = reinterpret_cast<const char*>(err);
        return r;
    }

    std::optional<ScanRow> Db::get_scan(const std::string& id) {
        const char* sql =
            "SELECT id,user_sub,target,port_start,port_end,status,started_at,completed_at,scanned_ports,error "
            "FROM scans WHERE id=?";
        sqlite3_stmt* st = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &st, nullptr) != SQLITE_OK) return std::nullopt;
        sqlite3_bind_text(st, 1, id.c_str(), -1, SQLITE_TRANSIENT);
        std::optional<ScanRow> out;
        if (sqlite3_step(st) == SQLITE_ROW) out = row_from_stmt(st);
        sqlite3_finalize(st);
        return out;
    }

    std::vector<ScanRow> Db::list_scans(int limit) {
        std::vector<ScanRow> out;
        const char* sql =
            "SELECT id,user_sub,target,port_start,port_end,status,started_at,completed_at,scanned_ports,error "
            "FROM scans ORDER BY started_at DESC LIMIT ?";
        sqlite3_stmt* st = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &st, nullptr) != SQLITE_OK) return out;
        sqlite3_bind_int(st, 1, limit);
        while (sqlite3_step(st) == SQLITE_ROW) out.push_back(row_from_stmt(st));
        sqlite3_finalize(st);
        return out;
    }

    // ---- ports ----

    void Db::save_ports(const std::string& scan_id, const std::vector<core::Port>& ports) {
        exec_("BEGIN");
        const char* sql =
            "INSERT OR REPLACE INTO scan_ports(scan_id,number,protocol,service,product,version,distro,tls) "
            "VALUES(?,?,?,?,?,?,?,?)";
        sqlite3_stmt* st = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &st, nullptr) != SQLITE_OK) { exec_("ROLLBACK"); return; }
        for (const auto& p : ports) {
            sqlite3_bind_text (st, 1, scan_id.c_str(),                   -1, SQLITE_TRANSIENT);
            sqlite3_bind_int  (st, 2, p.number);
            sqlite3_bind_text (st, 3, core::to_string(p.protocol).c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (st, 4, p.service.c_str(),                 -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (st, 5, p.product.c_str(),                 -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (st, 6, p.version.c_str(),                 -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (st, 7, p.distro.c_str(),                  -1, SQLITE_TRANSIENT);
            sqlite3_bind_int  (st, 8, p.tls ? 1 : 0);
            sqlite3_step(st);
            sqlite3_reset(st);
        }
        sqlite3_finalize(st);
        exec_("COMMIT");
    }

    void Db::save_findings(const std::string& scan_id, const std::vector<core::Finding>& findings) {
        exec_("BEGIN");
        const char* sql =
            "INSERT OR REPLACE INTO scan_findings"
            "(scan_id,idx,plugin_name,title,description,severity,confidence,confidence_score,verification,host,port_number,protocol,scope,service,product,version,evidence,evidence_type,evidence_source,evidence_details,reference_list,remediation,cvss,cvss_vector,timestamp,cve_id) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
        sqlite3_stmt* st = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &st, nullptr) != SQLITE_OK) { exec_("ROLLBACK"); return; }
        for (size_t i = 0; i < findings.size(); i++) {
            const auto& f = findings[i];
            sqlite3_bind_text (st, 1, scan_id.c_str(),                    -1, SQLITE_TRANSIENT);
            sqlite3_bind_int  (st, 2, static_cast<int>(i));
            sqlite3_bind_text (st, 3, f.plugin_name.c_str(),              -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (st, 4, f.title.c_str(),                    -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (st, 5, f.description.c_str(),              -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (st, 6, core::to_string(f.severity).c_str(),   -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (st, 7, core::to_string(f.confidence).c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_double(st, 8, f.confidence_score);
            sqlite3_bind_text (st, 9, f.verification.c_str(),              -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (st,10, f.host.c_str(),                      -1, SQLITE_TRANSIENT);
            sqlite3_bind_int  (st,11, f.port_number);
            sqlite3_bind_text (st,12, core::to_string(f.protocol).c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (st,13, f.scope.c_str(),                     -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (st,14, f.service.c_str(),                   -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (st,15, f.product.c_str(),                   -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (st,16, f.version.c_str(),                   -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (st,17, f.evidence.c_str(),                  -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (st,18, f.evidence_data.type.c_str(),         -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (st,19, f.evidence_data.source.c_str(),       -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (st,20, f.evidence_data.details.c_str(),      -1, SQLITE_TRANSIENT);
            std::string references = join_references(f.references);
            sqlite3_bind_text (st,21, references.c_str(),                   -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (st,22, f.remediation.c_str(),               -1, SQLITE_TRANSIENT);
            sqlite3_bind_double(st,23, f.cvss);
            sqlite3_bind_text (st,24, f.cvss_vector.c_str(),               -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(st,25, f.timestamp);
            sqlite3_bind_text (st,26, f.cve_id.c_str(),                    -1, SQLITE_TRANSIENT);
            sqlite3_step(st);
            sqlite3_reset(st);
        }
        sqlite3_finalize(st);
        exec_("COMMIT");
    }

    std::vector<core::Port> Db::load_ports(const std::string& scan_id) {
        std::vector<core::Port> out;
        const char* sql =
            "SELECT number,protocol,service,product,version,distro,tls FROM scan_ports "
            "WHERE scan_id=? ORDER BY number ASC";
        sqlite3_stmt* st = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &st, nullptr) != SQLITE_OK) return out;
        sqlite3_bind_text(st, 1, scan_id.c_str(), -1, SQLITE_TRANSIENT);
        while (sqlite3_step(st) == SQLITE_ROW) {
            core::Port p;
            p.number   = static_cast<std::uint16_t>(sqlite3_column_int(st, 0));
            std::string proto = reinterpret_cast<const char*>(sqlite3_column_text(st, 1));
            p.protocol = (proto == "TCP") ? core::Protocol::TCP :
                         (proto == "UDP") ? core::Protocol::UDP :
                         (proto == "ICMP")? core::Protocol::ICMP : core::Protocol::UNKNOWN;
            p.state    = core::PortState::OPEN;
            p.service  = reinterpret_cast<const char*>(sqlite3_column_text(st, 2));
            p.product  = reinterpret_cast<const char*>(sqlite3_column_text(st, 3));
            p.version  = reinterpret_cast<const char*>(sqlite3_column_text(st, 4));
            p.distro   = reinterpret_cast<const char*>(sqlite3_column_text(st, 5));
            p.tls      = sqlite3_column_int(st, 6) != 0;
            out.push_back(std::move(p));
        }
        sqlite3_finalize(st);
        return out;
    }

    static core::Severity parse_severity(const char* s) {
        std::string v = s ? s : "INFO";
        if (v == "CRITICAL") return core::Severity::CRITICAL;
        if (v == "HIGH")     return core::Severity::HIGH;
        if (v == "MEDIUM")   return core::Severity::MEDIUM;
        if (v == "LOW")      return core::Severity::LOW;
        return core::Severity::INFO;
    }
    static core::Confidence parse_conf(const char* s) {
        std::string v = s ? s : "UNKNOWN";
        if (v == "VERIFIED")      return core::Confidence::VERIFIED;
        if (v == "VERSION_MATCH") return core::Confidence::VERSION_MATCH;
        return core::Confidence::UNKNOWN;
    }

    std::vector<core::Finding> Db::load_findings(const std::string& scan_id) {
        std::vector<core::Finding> out;
        const char* sql =
            "SELECT plugin_name,title,description,severity,confidence,confidence_score,verification,host,port_number,protocol,scope,service,product,version,evidence,evidence_type,evidence_source,evidence_details,reference_list,remediation,cvss,cvss_vector,timestamp,cve_id "
            "FROM scan_findings WHERE scan_id=? ORDER BY idx ASC";
        sqlite3_stmt* st = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &st, nullptr) != SQLITE_OK) return out;
        sqlite3_bind_text(st, 1, scan_id.c_str(), -1, SQLITE_TRANSIENT);
        while (sqlite3_step(st) == SQLITE_ROW) {
            core::Finding f;
            f.plugin_name = reinterpret_cast<const char*>(sqlite3_column_text(st, 0));
            f.title       = reinterpret_cast<const char*>(sqlite3_column_text(st, 1));
            f.description = reinterpret_cast<const char*>(sqlite3_column_text(st, 2));
            f.severity    = parse_severity(reinterpret_cast<const char*>(sqlite3_column_text(st, 3)));
            f.confidence  = parse_conf(reinterpret_cast<const char*>(sqlite3_column_text(st, 4)));
            f.confidence_score = sqlite3_column_double(st, 5);
            f.verification = reinterpret_cast<const char*>(sqlite3_column_text(st, 6));
            f.host        = reinterpret_cast<const char*>(sqlite3_column_text(st, 7));
            f.port_number = static_cast<std::uint16_t>(sqlite3_column_int(st, 8));
            std::string protocol = reinterpret_cast<const char*>(sqlite3_column_text(st, 9));
            f.protocol = (protocol == "TCP") ? core::Protocol::TCP :
                         (protocol == "UDP") ? core::Protocol::UDP :
                         (protocol == "ICMP") ? core::Protocol::ICMP : core::Protocol::UNKNOWN;
            f.scope      = reinterpret_cast<const char*>(sqlite3_column_text(st, 10));
            f.service    = reinterpret_cast<const char*>(sqlite3_column_text(st, 11));
            f.product    = reinterpret_cast<const char*>(sqlite3_column_text(st, 12));
            f.version    = reinterpret_cast<const char*>(sqlite3_column_text(st, 13));
            f.evidence   = reinterpret_cast<const char*>(sqlite3_column_text(st, 14));
            f.evidence_data.type = reinterpret_cast<const char*>(sqlite3_column_text(st, 15));
            f.evidence_data.source = reinterpret_cast<const char*>(sqlite3_column_text(st, 16));
            f.evidence_data.value = f.evidence;
            f.evidence_data.details = reinterpret_cast<const char*>(sqlite3_column_text(st, 17));
            f.references = split_references(reinterpret_cast<const char*>(sqlite3_column_text(st, 18)));
            f.remediation = reinterpret_cast<const char*>(sqlite3_column_text(st, 19));
            f.cvss       = sqlite3_column_double(st, 20);
            f.cvss_vector = reinterpret_cast<const char*>(sqlite3_column_text(st, 21));
            f.timestamp  = sqlite3_column_int64(st, 22);
            f.cve_id     = reinterpret_cast<const char*>(sqlite3_column_text(st, 23));
            out.push_back(std::move(f));
        }
        sqlite3_finalize(st);
        return out;
    }
}
