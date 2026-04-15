#!/usr/bin/env python3
"""
hybrid_vas — Unified Database Initialiser
Run once to create all tables in ~/hybrid_vas/database/hybrid_vas.db
"""

import sqlite3
import os
from pathlib import Path

DB_PATH = Path.home() / "hybrid_vas" / "database" / "hybrid_vas.db"

SCHEMA = """
-- ─────────────────────────────────────────────────────────
--  USERS & ACCESS CONTROL
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    UNIQUE NOT NULL,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'viewer',
    active        INTEGER NOT NULL DEFAULT 1,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT,
    action     TEXT,
    detail     TEXT,
    ip_address TEXT,
    ts         DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ─────────────────────────────────────────────────────────
--  TOOL RUN TRACKER
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tool_logs (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    tool_name TEXT,
    operator  TEXT,
    run_time  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ─────────────────────────────────────────────────────────
--  DOMAIN CHECKER
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS domain_logs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    domain         TEXT    NOT NULL,
    ip_address     TEXT,
    registrar      TEXT,
    created        TEXT,
    expires        TEXT,
    vt_malicious   INTEGER DEFAULT 0,
    vt_suspicious  INTEGER DEFAULT 0,
    vt_clean       INTEGER DEFAULT 0,
    result         TEXT    NOT NULL,
    risk_score     INTEGER DEFAULT 0,
    operator       TEXT,
    timestamp      DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS dns_records (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    domain       TEXT,
    record_type  TEXT,
    record_value TEXT,
    timestamp    DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ─────────────────────────────────────────────────────────
--  PORT SCANNER
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS port_scans (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    target     TEXT,
    scan_type  TEXT,
    result     TEXT,
    risk_score INTEGER,
    geo_info   TEXT,
    timestamp  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ─────────────────────────────────────────────────────────
--  NETWORK SCANNER
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS network_scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    subnet      TEXT,
    hosts_found INTEGER DEFAULT 0,
    unknown_hosts INTEGER DEFAULT 0,
    result      TEXT,
    operator    TEXT,
    timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS network_hosts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER REFERENCES network_scans(id),
    ip_address  TEXT,
    mac_address TEXT,
    hostname    TEXT,
    vendor      TEXT,
    status      TEXT,
    timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ─────────────────────────────────────────────────────────
--  USB SCANNER
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS usb_scans (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    usb_name       TEXT,
    scan_mode      TEXT,
    quick_or_deep  TEXT,
    result         TEXT,
    timestamp      DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ─────────────────────────────────────────────────────────
--  MALWARE SCANNER (AI + static)
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS malware_scan_logs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    file_name      TEXT,
    file_path      TEXT,
    sha256         TEXT,
    result         TEXT,
    malware_family TEXT,
    confidence     REAL,
    scan_method    TEXT DEFAULT 'static',
    operator       TEXT,
    timestamp      DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ─────────────────────────────────────────────────────────
--  BACKDOOR SCANNER
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS backdoor_scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type       TEXT,
    suspicious_pids TEXT,
    suspicious_ports TEXT,
    cron_findings   TEXT,
    startup_findings TEXT,
    verdict         TEXT,
    risk_score      INTEGER DEFAULT 0,
    operator        TEXT,
    timestamp       DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ─────────────────────────────────────────────────────────
--  VULNERABILITY SCANNER
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS vuln_scans (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    target    TEXT,
    operator  TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS vuln_findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER REFERENCES vuln_scans(id),
    cve_id      TEXT,
    service     TEXT,
    version     TEXT,
    severity    TEXT,
    cvss_score  REAL,
    description TEXT,
    timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ─────────────────────────────────────────────────────────
--  URL FUZZER
-- ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS fuzz_results (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    target_url   TEXT,
    found_url    TEXT,
    http_status  INTEGER,
    vt_verdict   TEXT,
    operator     TEXT,
    timestamp    DATETIME DEFAULT CURRENT_TIMESTAMP
);
"""

def init_db():
    os.makedirs(DB_PATH.parent, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.executescript(SCHEMA)

    # Seed default admin user (password: admin123 — sha256 hashed)
    import hashlib
    default_users = [
        ("admin",    hashlib.sha256(b"admin123").hexdigest(),   "admin"),
        ("analyst1", hashlib.sha256(b"analyst123").hexdigest(), "analyst"),
        ("viewer1",  hashlib.sha256(b"viewer123").hexdigest(),  "viewer"),
    ]
    for username, pw_hash, role in default_users:
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
                (username, pw_hash, role)
            )
        except sqlite3.IntegrityError:
            pass  # already exists

    conn.commit()
    conn.close()
    print(f"[✔] Database initialised at: {DB_PATH}")
    print(f"[✔] Tables created: users, audit_log, tool_logs, domain_logs,")
    print(f"    dns_records, port_scans, network_scans, network_hosts,")
    print(f"    usb_scans, malware_scan_logs, backdoor_scans,")
    print(f"    vuln_scans, vuln_findings, fuzz_results")

if __name__ == "__main__":
    init_db()
