// db.hpp
//
// Thin SQLite3 wrapper for persisting scan history. Not general-purpose — the
// project stores every scan (metadata, open ports, findings) in one file so the
// web UI survives a restart.

#pragma once

#include "port.h"
#include "finding.h"

#include <optional>
#include <string>
#include <vector>

struct sqlite3;

namespace core {
    struct ScanRow {
        std::string id;
        std::string user_sub;      // OIDC subject of the user who started it
        std::string target;
        int port_start = 0;
        int port_end   = 0;
        std::string status;        // queued | running | done | error
        long started_at   = 0;
        long completed_at = 0;
        int  scanned_ports = 0;
        std::string error;
    };

    class Db {
    public:
        Db();
        ~Db();
        Db(const Db&) = delete;
        Db& operator=(const Db&) = delete;

        // Open (creates schema if missing). Returns false on failure.
        bool open(const std::string& path);

        // ---- Scans ----

        void upsert_scan(const ScanRow& row);
        void update_scan_status(const std::string& id, const std::string& status,
                                long completed_at, int scanned_ports,
                                const std::string& error = {});
        std::optional<ScanRow> get_scan(const std::string& id);
        std::vector<ScanRow>   list_scans(int limit = 200);

        // ---- Ports / Findings (bulk-insert at scan completion) ----

        void save_ports(const std::string& scan_id, const std::vector<core::Port>& ports);
        void save_findings(const std::string& scan_id, const std::vector<core::Finding>& findings);

        std::vector<core::Port>    load_ports(const std::string& scan_id);
        std::vector<core::Finding> load_findings(const std::string& scan_id);

    private:
        sqlite3* db_ = nullptr;
        void exec_(const std::string& sql);
    };
}
