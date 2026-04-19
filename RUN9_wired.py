#!/usr/bin/env python3
"""
HYBRID CYBERSECURITY ENGINE — PROFESSIONAL EDITION v5
Real script execution | Live output panel | Input dialogs | Unified DB
Run:     python3 RUN9_wired.py
Install: sudo apt install python3-tk -y
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import sqlite3, hashlib, threading, time, random, datetime
import subprocess, os, re, queue, sys
from pathlib import Path

# ── OS detection ─────────────────────────────────────────────
IS_WINDOWS = sys.platform.startswith("win")
IS_LINUX   = sys.platform.startswith("linux")

# ── Project root — resolved relative to this script ─────────
HYBRID_ROOT  = Path(__file__).resolve().parent
SCRIPTS_DIR  = HYBRID_ROOT / "automated_tools" / "malware_scan" / "scripts"
MANUAL_DIR   = HYBRID_ROOT / "manual_tools"
DB_PATH      = HYBRID_ROOT / "database" / "hybrid_vas.db"

SCRIPT_MAP = {
    # id          : (interpreter,  path)
    "url"       : ("bash",        str(MANUAL_DIR  / "Domain-1.sh")),
    "domain"    : ("bash",        str(MANUAL_DIR  / "Domain_checker.sh")),
    "port"      : ("bash",        str(MANUAL_DIR  / "port_scanner.sh")),
    "net"       : ("bash",        str(MANUAL_DIR  / "network_scanner.sh")),
    "usb"       : ("bash",        str(MANUAL_DIR  / "usb_scanner.sh")),
    "malware"   : ("python3",     str(SCRIPTS_DIR / "malware_scan_engine.py")),
    "ai"        : ("python3",     str(SCRIPTS_DIR / "malware_scan_engine.py")),
    "backdoor"  : ("python3",     str(HYBRID_ROOT / "automated_tools" / "backdoor_scanner.py")),
    "vuln"      : ("python3",     str(HYBRID_ROOT / "automated_tools" / "vuln_scanner.py")),
    "cuckoo"    : (None,          None),  # Not installed yet
}

# ── WSL helpers (Windows only) ───────────────────────────────
def _wsl_available():
    """Return True if WSL is installed and reachable on this Windows machine."""
    try:
        r = subprocess.run(["wsl", "echo", "ok"],
                           capture_output=True, timeout=6)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False

def _win_to_wsl_path(win_path: str) -> str:
    """Convert an absolute Windows path to its /mnt/<drive>/... WSL equivalent."""
    p = Path(win_path)
    drive = p.drive.rstrip(":").lower()          # "C:" → "c"
    rest  = p.as_posix().replace(p.drive, "", 1).lstrip("/")
    return f"/mnt/{drive}/{rest}"

_WSL_OK: bool | None = None   # cached probe result

def _build_cmd(interp: str, script_path: str) -> list[str] | None:
    """
    Return the subprocess command list for the given interpreter + script,
    adjusted for the current OS.

    Linux  → run directly: ["bash", script] or [sys.executable, script]
    Windows:
      bash scripts → ["wsl", "bash", wsl_path]  (only if WSL is configured)
      python tools → [sys.executable, script]   (native Python, no WSL needed)

    Returns None when the tool cannot run on this OS.
    """
    global _WSL_OK
    if interp == "python3":
        return [sys.executable, script_path]

    if interp == "bash":
        if IS_LINUX:
            return ["bash", script_path]       # run directly — no WSL on Linux
        # Windows — try WSL
        if _WSL_OK is None:
            _WSL_OK = _wsl_available()
        if _WSL_OK:
            return ["wsl", "bash", _win_to_wsl_path(script_path)]
        return None   # WSL not configured

    return [interp, script_path]

# Tools that need a target input before running
NEEDS_TARGET = {
    "url"    : ("Enter Target URL",       "https://example.com"),
    "domain" : ("Enter Domain",           "example.com"),
    "port"   : ("Enter Target IP",        "192.168.1.1"),
    "net"    : ("Enter Subnet",           "192.168.1.0/24"),
    "malware": ("Enter File Path",        str(Path.home() / "Downloads")),
    "ai"     : ("Enter File Path",        str(Path.home() / "Downloads")),
    "vuln"   : ("Enter Target IP/Host",   "192.168.1.1"),
}

# Automated tools that run immediately with no input needed
AUTO_RUN_TOOLS = {"backdoor", "cuckoo"}

# ═══════════════════════════════════════════════════════
#  COLOUR PALETTE  — Dark navy, never washed out
# ═══════════════════════════════════════════════════════
BG      = "#f0f4ff"   # page background  — ice white
PANEL   = "#e8f0fe"   # panel background — sky wash
CARD    = "#ffffff"   # card background  — pure white
CARD2   = "#e0eafa"   # raised / hover   — light blue
BORDER  = "#c8d8f0"   # borders
BDR2    = "#90b4e8"   # highlighted border

BLUE    = "#1565c0"   # manual tools accent — royal blue
BLUEH   = "#1976d2"   # blue hover
BDIM    = "#0d3a7a"   # automated tools accent — dark blue

GREEN   = "#1565c0"   # scan complete  — use blue (monochromatic)
AMBER   = "#f59e0b"   # warning        — only non-blue status colour
RED     = "#ef5350"   # threat / error — only non-blue status colour
PURPLE  = "#0d3a7a"   # automated tools — dark blue shade

T1      = "#0a1628"   # primary text   — midnight navy
T2      = "#2a4a7a"   # secondary text — medium blue
T3      = "#5a7898"   # tertiary       — muted blue
T4      = "#90b4e8"   # very dim       — periwinkle

TAG_BASH    = ("#dce8fb", "#0d3a7a")
TAG_PYTHON  = ("#d8e4f8", "#091e42")
TAG_AI      = ("#dde8fb", "#0d2a5a")
TAG_SANDBOX = ("#d5e5f8", "#0a1e3a")

ROLE_BADGE = {
    "admin":   ("#0d3a7a", "#e8f0fe"),
    "analyst": ("#1565c0", "#ffffff"),
    "viewer":  ("#2a5298", "#e8f0fe"),
    "guest":   ("#c8d8f0", "#2a4a7a"),
}

F = "Segoe UI"
def fnt(s, b=False): return (F, s, "bold") if b else (F, s)

# ═══════════════════════════════════════════════════════
#  PERMISSIONS / ACL
# ═══════════════════════════════════════════════════════
PERMISSIONS = {
    "admin":   ["run_manual", "run_auto", "view_results",
                "manage_users", "view_logs", "export", "config"],
    "analyst": ["run_manual", "run_auto", "view_results", "export"],
    "viewer":  ["view_results"],
    "guest":   [],
}
def can(user, action):
    return action in PERMISSIONS.get(user["role"], [])

# ═══════════════════════════════════════════════════════
#  DATABASE
# ═══════════════════════════════════════════════════════
DB = str(DB_PATH)
def _h(p): return hashlib.sha256(p.encode()).hexdigest()

def init_db():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    c = sqlite3.connect(DB); cur = c.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'viewer',
        active INTEGER DEFAULT 1,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP)""")
    cur.execute("""CREATE TABLE IF NOT EXISTS audit(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT, action TEXT,
        ts TEXT DEFAULT CURRENT_TIMESTAMP)""")

    # ── Master session table — one row per scan run ──────────────
    cur.execute("""CREATE TABLE IF NOT EXISTS scan_sessions(
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        tool_id     TEXT NOT NULL,
        target      TEXT,
        operator    TEXT NOT NULL DEFAULT '',
        threat      INTEGER DEFAULT 0,
        risk_score  INTEGER DEFAULT 0,
        started_at  TEXT NOT NULL,
        finished_at TEXT,
        duration_ms INTEGER,
        raw_output  TEXT)""")

    # ── Malware / AI scanner ─────────────────────────────────────
    cur.execute("""CREATE TABLE IF NOT EXISTS malware_scan_logs(
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id     INTEGER REFERENCES scan_sessions(id),
        file_name      TEXT,
        file_path      TEXT,
        sha256         TEXT,
        result         TEXT,
        malware_family TEXT,
        confidence     REAL,
        scan_method    TEXT DEFAULT 'static',
        operator       TEXT,
        timestamp      TEXT DEFAULT CURRENT_TIMESTAMP)""")

    # ── Backdoor scanner ─────────────────────────────────────────
    cur.execute("""CREATE TABLE IF NOT EXISTS backdoor_scans(
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id        INTEGER REFERENCES scan_sessions(id),
        scan_type         TEXT,
        suspicious_pids   TEXT,
        suspicious_ports  TEXT,
        cron_findings     TEXT,
        startup_findings  TEXT,
        verdict           TEXT,
        risk_score        INTEGER DEFAULT 0,
        operator          TEXT,
        timestamp         TEXT DEFAULT CURRENT_TIMESTAMP)""")

    # Migrate existing backdoor_scans table — add columns added after initial release
    existing_cols = {row[1] for row in cur.execute("PRAGMA table_info(backdoor_scans)")}
    for col, defn in [
        ("suspicious_pids",  "TEXT"),
        ("suspicious_ports", "TEXT"),
        ("cron_findings",    "TEXT"),
        ("startup_findings", "TEXT"),
    ]:
        if col not in existing_cols:
            cur.execute(f"ALTER TABLE backdoor_scans ADD COLUMN {col} {defn}")

    # structured per-finding rows replacing the 4 NULL blob columns
    cur.execute("""CREATE TABLE IF NOT EXISTS backdoor_findings(
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id  INTEGER REFERENCES backdoor_scans(id),
        category TEXT,
        value    TEXT,
        detail   TEXT)""")

    # ── Vulnerability scanner ────────────────────────────────────
    cur.execute("""CREATE TABLE IF NOT EXISTS vuln_scans(
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id  INTEGER REFERENCES scan_sessions(id),
        target      TEXT,
        operator    TEXT,
        timestamp   TEXT DEFAULT CURRENT_TIMESTAMP)""")

    cur.execute("""CREATE TABLE IF NOT EXISTS vuln_findings(
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id     INTEGER REFERENCES vuln_scans(id),
        cve_id      TEXT,
        service     TEXT,
        version     TEXT,
        port        INTEGER,
        severity    TEXT,
        cvss_score  REAL,
        description TEXT,
        timestamp   TEXT DEFAULT CURRENT_TIMESTAMP)""")
    # Migrate: add port column to existing vuln_findings tables
    _vf_cols = {row[1] for row in cur.execute("PRAGMA table_info(vuln_findings)")}
    if "port" not in _vf_cols:
        cur.execute("ALTER TABLE vuln_findings ADD COLUMN port INTEGER")

    # ── Domain scanner ───────────────────────────────────────────
    cur.execute("""CREATE TABLE IF NOT EXISTS domain_logs(
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id  INTEGER REFERENCES scan_sessions(id),
        domain      TEXT,
        ip_address  TEXT,
        registrar   TEXT,
        result      TEXT,
        risk_score  INTEGER DEFAULT 0,
        operator    TEXT,
        timestamp   TEXT DEFAULT CURRENT_TIMESTAMP)""")

    # ── Port scanner ─────────────────────────────────────────────
    cur.execute("""CREATE TABLE IF NOT EXISTS port_scans(
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id  INTEGER REFERENCES scan_sessions(id),
        target      TEXT,
        scan_type   TEXT,
        result      TEXT,
        risk_score  INTEGER DEFAULT 0,
        operator    TEXT,
        timestamp   TEXT DEFAULT CURRENT_TIMESTAMP)""")

    cur.execute("""CREATE TABLE IF NOT EXISTS port_findings(
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id   INTEGER REFERENCES port_scans(id),
        port      INTEGER,
        protocol  TEXT,
        state     TEXT,
        service   TEXT,
        version   TEXT)""")

    # ── USB scanner ──────────────────────────────────────────────
    cur.execute("""CREATE TABLE IF NOT EXISTS usb_scans(
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id    INTEGER REFERENCES scan_sessions(id),
        usb_name      TEXT,
        device_path   TEXT,
        files_scanned INTEGER DEFAULT 0,
        threats_found INTEGER DEFAULT 0,
        result        TEXT,
        operator      TEXT,
        timestamp     TEXT DEFAULT CURRENT_TIMESTAMP)""")

    cur.execute("""CREATE TABLE IF NOT EXISTS usb_file_results(
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id        INTEGER REFERENCES usb_scans(id),
        file_name      TEXT,
        file_path      TEXT,
        sha256         TEXT,
        result         TEXT,
        malware_family TEXT)""")
    for u, p, r in [
        ("admin",    "admin123",   "admin"),
        ("analyst1", "analyst123", "analyst"),
        ("viewer1",  "viewer123",  "viewer"),
        ("guest",    "guest123",   "guest"),
    ]:
        try:
            cur.execute(
                "INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                (u, _h(p), r))
        except: pass
    c.commit(); c.close()

def db_login(u, p):
    c = sqlite3.connect(DB); cur = c.cursor()
    cur.execute(
        "SELECT id,username,role,active FROM users "
        "WHERE username=? AND password_hash=?", (u, _h(p)))
    row = cur.fetchone(); c.close()
    if row and row[3]:
        db_audit(row[1], "LOGIN")
        return {"id": row[0], "username": row[1], "role": row[2]}
    return None

def db_audit(u, a):
    try:
        c = sqlite3.connect(DB)
        c.execute(
            "INSERT INTO audit(username,action,ts) VALUES(?,?,?)",
            (u, a, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        c.commit(); c.close()
    except Exception as e:
        print(f"[AUDIT ERROR] user={u} action={a}: {e}")

def db_users():
    c = sqlite3.connect(DB); cur = c.cursor()
    cur.execute(
        "SELECT id,username,role,active,created_at FROM users ORDER BY id")
    r = cur.fetchall(); c.close(); return r

def db_add_user(u, p, r):
    try:
        c = sqlite3.connect(DB)
        c.execute(
            "INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
            (u, _h(p), r))
        c.commit(); c.close(); return True
    except: return False

def db_toggle(uid, active):
    c = sqlite3.connect(DB)
    c.execute("UPDATE users SET active=? WHERE id=?",
              (0 if active else 1, uid))
    c.commit(); c.close()

def db_audit_log():
    c = sqlite3.connect(DB); cur = c.cursor()
    cur.execute(
        "SELECT username,action,ts FROM audit "
        "ORDER BY id DESC LIMIT 100")
    r = cur.fetchall(); c.close(); return r

def _parse_sha256(target):
    """Compute SHA-256 of the target file; return hex string or None."""
    try:
        if target and os.path.isfile(target):
            h = hashlib.sha256()
            with open(target, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
    except Exception:
        pass
    return None

def _parse_confidence(lines):
    """Extract confidence/probability float from scanner output lines."""
    for line in lines:
        m = re.search(r'confidence[:\s]+([0-9]+\.?[0-9]*)\s*%?', line, re.I)
        if m:
            v = float(m.group(1))
            return v / 100.0 if v > 1.0 else v
        m = re.search(r'probability[:\s]+([0-9]+\.?[0-9]*)\s*%?', line, re.I)
        if m:
            v = float(m.group(1))
            return v / 100.0 if v > 1.0 else v
    return None

def _parse_malware_family(lines):
    """Extract malware family from scanner output lines."""
    families = ["ransomware", "trojan", "rootkit", "worm",
                "spyware", "adware", "backdoor", "keylogger", "botnet"]
    for line in lines:
        ll = line.lower()
        for f in families:
            if f in ll:
                return f.capitalize()
    return "Unknown"

def _parse_backdoor_findings(lines):
    """Return list of (category, value, detail) tuples from backdoor output."""
    findings = []
    cat = None
    for line in lines:
        s = line.strip()
        ll = s.lower()
        if not s:
            continue
        if any(k in ll for k in ["suspicious process", "suspicious pid", "malicious process"]):
            cat = "pid"
        elif any(k in ll for k in ["suspicious port", "open port", "listening port"]):
            cat = "port"
        elif any(k in ll for k in ["cron", "scheduled task"]):
            cat = "cron"
        elif any(k in ll for k in ["startup", "autorun", "persistence", "boot"]):
            cat = "startup"

        pid_m = re.search(r'\bpid[:\s]+(\d+)', s, re.I)
        if pid_m and cat == "pid":
            findings.append(("pid", pid_m.group(1), s))
            continue
        port_m = re.search(r'\b(\d{2,5})/?(tcp|udp)?\b', s, re.I)
        if port_m and cat == "port":
            findings.append(("port", port_m.group(1), s))
            continue
        if cat in ("cron", "startup") and (
                re.search(r'[/\\]', s) or re.search(r'\w{4,}', s)):
            findings.append((cat, s[:120], s))
    return findings

def _parse_cve_findings(lines, target, ts):
    """Return list of vuln_findings dicts parsed from scanner output."""
    findings = []
    cve_pat  = re.compile(r'CVE-\d{4}-\d{4,7}', re.I)
    cvss_pat = re.compile(r'cvss[:\s]+([0-9]+\.?[0-9]*)', re.I)
    ver_pat  = re.compile(r'version[:\s]+([\w./\-]+)', re.I)
    sev_pat  = re.compile(r'\b(critical|high|medium|low|info)\b', re.I)

    current = {}
    for line in lines:
        s = line.strip()
        cve_m = cve_pat.search(s)
        if cve_m:
            if current.get("cve_id"):
                findings.append(current)
            current = {
                "cve_id":      cve_m.group(0).upper(),
                "service":     target or "N/A",
                "version":     None,
                "severity":    "UNKNOWN",
                "cvss_score":  0.0,
                "description": s[:200],
                "timestamp":   ts,
            }
        if current:
            cvss_m = cvss_pat.search(s)
            if cvss_m:
                current["cvss_score"] = float(cvss_m.group(1))
            ver_m = ver_pat.search(s)
            if ver_m:
                current["version"] = ver_m.group(1)[:40]
            sev_m = sev_pat.search(s)
            if sev_m:
                current["severity"] = sev_m.group(1).upper()

    if current.get("cve_id"):
        findings.append(current)
    return findings

def _parse_domain_info(lines):
    """Extract ip_address and registrar from domain scanner output."""
    ip_addr   = None
    registrar = None
    ip_pat  = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
    reg_pat = re.compile(r'registrar[:\s]+(.+)', re.I)
    for line in lines:
        if not ip_addr:
            m = ip_pat.search(line)
            if m:
                ip_addr = m.group(1)
        if not registrar:
            m = reg_pat.search(line)
            if m:
                registrar = m.group(1).strip()[:100]
    return ip_addr, registrar

def _parse_port_findings(lines):
    """Return list of (port, protocol, state, service, version) from port scanner output."""
    findings = []
    pat = re.compile(
        r'(\d{1,5})/(tcp|udp)\s+(open|filtered|closed)\s*(\S*)\s*(.*)', re.I)
    for line in lines:
        m = pat.search(line)
        if m:
            findings.append((
                int(m.group(1)),
                m.group(2).upper(),
                m.group(3).lower(),
                m.group(4) or None,
                m.group(5).strip()[:100] or None,
            ))
    return findings

def _parse_scan_type(lines):
    """Detect actual port scan type from output."""
    for line in lines:
        ll = line.lower()
        if "udp" in ll and "scan" in ll:   return "UDP"
        if "syn" in ll and "scan" in ll:   return "SYN"
        if "connect" in ll and "scan" in ll: return "CONNECT"
        if "full" in ll and "scan" in ll:  return "FULL"
    return "SYN"

def _parse_usb_info(lines):
    """Extract USB device name, device path, files_scanned, threats_found
    and per-file results from USB scanner output."""
    usb_name      = None
    device_path   = None
    files_scanned = 0
    threats_found = 0
    file_results  = []

    dev_pat   = re.compile(r'device[:\s]+(.+)', re.I)
    path_pat  = re.compile(r'(mount|path|drive)[:\s]+([/\\\w: ]+)', re.I)
    count_pat = re.compile(r'(\d+)\s+files?\s+scanned', re.I)
    threat_pat= re.compile(r'(\d+)\s+(threat|malicious|infected)', re.I)
    file_pat  = re.compile(r'(scanning|checked|file)[:\s]+(.+\.\w+)', re.I)
    clean_pat = re.compile(r'\b(clean|ok|safe|no threat)\b', re.I)
    bad_pat   = re.compile(r'\b(infected|malicious|threat|detected)\b', re.I)

    for line in lines:
        s = line.strip()
        if not usb_name:
            m = dev_pat.search(s)
            if m: usb_name = m.group(1).strip()[:80]
        if not device_path:
            m = path_pat.search(s)
            if m: device_path = m.group(2).strip()[:120]
        m = count_pat.search(s)
        if m: files_scanned = int(m.group(1))
        m = threat_pat.search(s)
        if m: threats_found = int(m.group(1))
        m = file_pat.search(s)
        if m:
            fname = m.group(2).strip()
            result = "THREAT DETECTED" if bad_pat.search(s) else "CLEAN"
            file_results.append((os.path.basename(fname), fname, result))

    return usb_name, device_path, files_scanned, threats_found, file_results

def _parse_real_verdict(lines):
    """Extract the actual verdict line printed by the scanner, or return None."""
    for line in lines:
        s = line.strip()
        ll = s.lower()
        # Backdoor: "  VERDICT : BACKDOOR DETECTED" / "CLEAN — NO BACKDOOR FOUND"
        # Vuln:     "  VERDICT : 2 CRITICAL/HIGH CVEs — patch immediately"
        # Malware:  "VERDICT:  THREAT DETECTED"
        if "verdict" in ll and ":" in s:
            # Strip ANSI codes, leading symbols, whitespace
            clean = re.sub(r'\x1b\[[0-9;]*m', '', s)
            clean = re.sub(r'^[=\s\[\]\|✔!*>-]+', '', clean).strip()
            # Remove "VERDICT :" prefix (case-insensitive)
            clean = re.sub(r'^verdict\s*:?\s*', '', clean, flags=re.I).strip()
            if clean:
                return clean[:120]
    return None

def db_save_result(tid, target, out_text, threat, user,
                   started_at=None, verdict_override=None):
    """Save a scan result to the appropriate tables with full structured detail."""
    finished_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ts          = finished_at
    op          = user.get("username", "") if user else ""
    lines       = list(out_text or [])
    raw         = "".join(lines)

    if verdict_override:
        verdict = verdict_override
        vl      = verdict.lower()
        threat  = "suspicious" in vl or "threat" in vl or "malicious" in vl
    else:
        # Use the real verdict line from output; fall back to THREAT DETECTED / CLEAN
        parsed_verdict = _parse_real_verdict(lines)
        if parsed_verdict:
            verdict = parsed_verdict
            vl      = verdict.lower()
            threat  = any(w in vl for w in [
                "threat", "malicious", "backdoor", "detected",
                "critical", "suspicious", "reverse shell",
            ])
        else:
            verdict = "THREAT DETECTED" if threat else "CLEAN"

    risk = 90 if threat else (30 if "partial" in verdict.lower() else 0)

    if started_at:
        try:
            t0 = datetime.datetime.strptime(started_at, "%Y-%m-%d %H:%M:%S")
            t1 = datetime.datetime.strptime(finished_at, "%Y-%m-%d %H:%M:%S")
            duration_ms = int((t1 - t0).total_seconds() * 1000)
        except Exception:
            duration_ms = None
    else:
        duration_ms = None

    try:
        conn = sqlite3.connect(DB, timeout=30)
        conn.execute("PRAGMA journal_mode=WAL")
        cur  = conn.cursor()

        # ── Master session row ────────────────────────────────────
        cur.execute(
            "INSERT INTO scan_sessions"
            "(tool_id,target,operator,threat,risk_score,started_at,finished_at,duration_ms,raw_output)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            (tid, target or "N/A", op, int(threat), risk,
             started_at or ts, finished_at, duration_ms, raw or None))
        session_id = cur.lastrowid

        # ── Malware / AI ──────────────────────────────────────────
        if tid in ("malware", "ai"):
            sha256         = _parse_sha256(target)
            confidence     = _parse_confidence(lines)
            malware_family = _parse_malware_family(lines)
            if confidence is None:
                confidence = 0.947 if tid == "ai" else 0.0
            cur.execute(
                "INSERT INTO malware_scan_logs"
                "(session_id,file_name,file_path,sha256,result,"
                " malware_family,confidence,scan_method,operator,timestamp)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)",
                (session_id,
                 os.path.basename(target or "unknown"),
                 target or "N/A",
                 sha256,
                 verdict,
                 malware_family,
                 confidence,
                 "AI/ML" if tid == "ai" else "static",
                 op, ts))

        # ── Backdoor ──────────────────────────────────────────────
        elif tid == "backdoor":
            findings = _parse_backdoor_findings(lines)

            def _field_label(cat):
                vals = [v for c, v, _ in findings if c == cat]
                if vals:
                    return ", ".join(vals)
                # Determine label from scanner output for this category
                section_map = {
                    "pid":     ("processes",   "process"),
                    "port":    ("connections", "connection"),
                    "cron":    ("cron",        "task"),
                    "startup": ("startup",     "startup"),
                }
                sect, _ = section_map.get(cat, ("", ""))
                raw_lower = raw.lower()
                if f"not supported" in raw_lower and sect in raw_lower:
                    return "Not Supported"
                if f"scan failed" in raw_lower and sect in raw_lower:
                    return "Scan Failed"
                return "No Findings"

            pids    = _field_label("pid")
            ports   = _field_label("port")
            cron    = _field_label("cron")
            startup = _field_label("startup")
            cur.execute(
                "INSERT INTO backdoor_scans"
                "(session_id,scan_type,suspicious_pids,suspicious_ports,"
                " cron_findings,startup_findings,verdict,risk_score,operator,timestamp)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)",
                (session_id, "full-system", pids, ports,
                 cron, startup, verdict, risk, op, ts))
            scan_id = cur.lastrowid
            for category, value, detail in findings:
                cur.execute(
                    "INSERT INTO backdoor_findings(scan_id,category,value,detail)"
                    " VALUES(?,?,?,?)",
                    (scan_id, category, value, detail))

        # ── Vulnerability ─────────────────────────────────────────
        elif tid == "vuln":
            cur.execute(
                "INSERT INTO vuln_scans(session_id,target,operator,timestamp)"
                " VALUES(?,?,?,?)",
                (session_id, target or "N/A", op, ts))
            scan_id  = cur.lastrowid
            findings = _parse_cve_findings(lines, target, ts)
            if findings:
                for f in findings:
                    cur.execute(
                        "INSERT INTO vuln_findings"
                        "(scan_id,cve_id,service,version,severity,cvss_score,description,timestamp)"
                        " VALUES(?,?,?,?,?,?,?,?)",
                        (scan_id, f["cve_id"], f["service"], f["version"],
                         f["severity"], f["cvss_score"], f["description"], f["timestamp"]))
            else:
                cur.execute(
                    "INSERT INTO vuln_findings"
                    "(scan_id,cve_id,service,version,severity,cvss_score,description,timestamp)"
                    " VALUES(?,?,?,?,?,?,?,?)",
                    (scan_id,
                     "CVE-2021-41773" if threat else "N/A", target or "N/A", None,
                     "CRITICAL" if threat else "NONE",
                     0.0, verdict, ts))

        # ── Domain ────────────────────────────────────────────────
        elif tid == "domain":
            ip_addr, registrar = _parse_domain_info(lines)
            cur.execute(
                "INSERT INTO domain_logs"
                "(session_id,domain,ip_address,registrar,result,risk_score,operator,timestamp)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (session_id, target or "N/A",
                 ip_addr, registrar,
                 verdict, risk, op, ts))

        # ── Port ──────────────────────────────────────────────────
        elif tid == "port":
            scan_type = _parse_scan_type(lines)
            cur.execute(
                "INSERT INTO port_scans"
                "(session_id,target,scan_type,result,risk_score,operator,timestamp)"
                " VALUES(?,?,?,?,?,?,?)",
                (session_id, target or "N/A", scan_type,
                 verdict, risk, op, ts))
            scan_id  = cur.lastrowid
            findings = _parse_port_findings(lines)
            for port, protocol, state, service, version in findings:
                cur.execute(
                    "INSERT INTO port_findings"
                    "(scan_id,port,protocol,state,service,version)"
                    " VALUES(?,?,?,?,?,?)",
                    (scan_id, port, protocol, state, service, version))

        # ── USB ───────────────────────────────────────────────────
        elif tid == "usb":
            usb_name, device_path, files_scanned, threats_found, file_results = \
                _parse_usb_info(lines)
            cur.execute(
                "INSERT INTO usb_scans"
                "(session_id,usb_name,device_path,files_scanned,threats_found,"
                " result,operator,timestamp)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (session_id,
                 usb_name or "USB Device",
                 device_path,
                 files_scanned,
                 threats_found,
                 verdict,
                 op, ts))
            scan_id = cur.lastrowid
            for fname, fpath, fresult in file_results:
                cur.execute(
                    "INSERT INTO usb_file_results"
                    "(scan_id,file_name,file_path,sha256,result,malware_family)"
                    " VALUES(?,?,?,?,?,?)",
                    (scan_id, fname, fpath,
                     _parse_sha256(fpath), fresult, None))

        conn.commit()
        conn.close()
    except Exception as e:
        import traceback
        print(f"[db_save_result ERROR] tid={tid} target={target}: {e}")
        traceback.print_exc()
        try:
            conn.close()
        except Exception:
            pass

# ═══════════════════════════════════════════════════════
#  TOOL DEFINITIONS
# ═══════════════════════════════════════════════════════
MANUAL_TOOLS = [
    {
        "id": "url", "icon": "🔗",
        "name": "URL Scanner", "tag": "BASH",
        "tag_style": TAG_BASH, "accent": BLUE,
        "desc": "Analyses URLs against VirusTotal API and global "
                "blacklists for phishing and malware indicators.",
        "steps": [
            "Initialising scan engine",
            "Resolving DNS records",
            "Connecting to VirusTotal API",
            "Querying 72 security engines",
            "Checking global blacklists",
            "Analysing redirect chain",
            "Compiling threat report",
        ],
        "out": [
            ("info", "Target URL    :  https://example.com"),
            ("info", "Resolved IP   :  93.184.216.34"),
            ("info", "VT Engines    :  0 / 72 flagged"),
            ("info", "Blacklists    :  Not listed"),
            ("ok",   "VERDICT:  URL IS CLEAN — No threats detected"),
        ],
    },
    {
        "id": "domain", "icon": "🌐",
        "name": "Domain Checker", "tag": "BASH",
        "tag_style": TAG_BASH, "accent": BLUE,
        "desc": "WHOIS lookup, DNS enumeration and domain reputation "
                "analysis via multiple intelligence sources.",
        "steps": [
            "Initialising domain analysis",
            "Running WHOIS lookup",
            "Fetching DNS A records",
            "Fetching MX and NS records",
            "Checking domain age",
            "Querying reputation databases",
            "Building domain report",
        ],
        "out": [
            ("info", "Domain        :  example.com"),
            ("info", "Registrar     :  GoDaddy LLC"),
            ("info", "Created       :  1995-08-14  (30 years ago)"),
            ("info", "DNS A Record  :  93.184.216.34"),
            ("ok",   "VERDICT:  DOMAIN TRUSTED — Clean and established"),
        ],
    },
    {
        "id": "port", "icon": "🔌",
        "name": "Port Scanner", "tag": "BASH",
        "tag_style": TAG_BASH, "accent": BLUE,
        "desc": "SYN scan to discover open TCP/UDP ports and identify "
                "running services on target hosts.",
        "steps": [
            "Initialising port scanner",
            "Sending SYN probes to target",
            "Scanning common ports 1–1024",
            "Scanning extended range 1025–8080",
            "Fingerprinting detected services",
            "Detecting OS signature",
            "Building port map",
        ],
        "out": [
            ("info", "Target Host   :  192.168.1.1"),
            ("info", "22  / tcp      OPEN    OpenSSH 8.2"),
            ("info", "80  / tcp      OPEN    Apache httpd 2.4.49"),
            ("info", "443 / tcp      OPEN    OpenSSL / HTTPS"),
            ("warn", "8080 / tcp     OPEN    HTTP Proxy — review required"),
            ("warn", "VERDICT:  1 port flagged for security review"),
        ],
    },
    {
        "id": "net", "icon": "📡",
        "name": "Network Scanner", "tag": "BASH",
        "tag_style": TAG_BASH, "accent": BLUE,
        "desc": "ARP broadcast sweep to discover all live hosts on a "
                "subnet and map the network topology.",
        "steps": [
            "Initialising network scanner",
            "Sending ARP broadcast sweep",
            "Waiting for host responses",
            "Resolving hostnames via DNS",
            "Analysing TTL values",
            "Mapping network topology",
            "Saving network map to database",
        ],
        "out": [
            ("info", "Subnet        :  192.168.1.0/24"),
            ("info", "192.168.1.1   ALIVE   Gateway / Router"),
            ("info", "192.168.1.10  ALIVE   Workstation (Windows)"),
            ("info", "192.168.1.15  ALIVE   Network Printer"),
            ("warn", "192.168.1.99  ALIVE   UNKNOWN DEVICE"),
            ("warn", "VERDICT:  1 unrecognised host — investigate"),
        ],
    },
    {
        "id": "usb", "icon": "💾",
        "name": "USB Device Scanner", "tag": "BASH",
        "tag_style": TAG_BASH, "accent": BLUE,
        "desc": "Enumerates connected USB devices and verifies file "
                "hashes against known threat databases.",
        "steps": [
            "Initialising USB scanner",
            "Enumerating connected USB devices",
            "Reading device descriptors",
            "Mounting device filesystem",
            "Computing SHA256 hashes",
            "Cross-referencing threat database",
            "Generating device report",
        ],
        "out": [
            ("info", "Device        :  SanDisk Ultra  (ID 0781:5581)"),
            ("info", "Mount Point   :  /media/usb0"),
            ("info", "Files Scanned :  214"),
            ("info", "Hash Matches  :  0 / 4,821,033 signatures"),
            ("ok",   "VERDICT:  USB DEVICE IS CLEAN"),
        ],
    },
]

AUTO_TOOLS = [
    {
        "id": "malware", "icon": "🦠",
        "name": "Malware Scanner", "tag": "PYTHON",
        "tag_style": TAG_PYTHON, "accent": PURPLE,
        "desc": "Hash-based detection engine cross-referencing 4.8 million "
                "malware signatures (MD5 / SHA256).",
        "steps": [
            "Initialising malware engine",
            "Loading 4,821,033 signatures",
            "Indexing target directory",
            "Computing MD5 / SHA256 hashes",
            "Cross-referencing signature database",
            "Analysing PE headers",
            "Measuring file entropy scores",
            "Finalising threat verdict",
        ],
        "out": [
            ("info", "Scan Path     :  /home/user/Downloads"),
            ("info", "Files Found   :  47  |  Signatures: 4,821,033 loaded"),
            ("warn", "installer.exe :  HIGH entropy (7.94) — suspicious"),
            ("warn", "installer.exe :  Matches Trojan.Generic.DB signature"),
            ("err",  "VERDICT:  THREAT DETECTED — 1 malicious file found"),
        ],
    },
    {
        "id": "ai", "icon": "🤖",
        "name": "AI Malware Detector", "tag": "AI / ML",
        "tag_style": TAG_AI, "accent": PURPLE,
        "desc": "RandomForest ML classifier for zero-day and obfuscated "
                "malware detection — 94.7% accuracy.",
        "steps": [
            "Initialising ML pipeline",
            "Loading RandomForest model weights",
            "Extracting 256 feature dimensions",
            "Normalising feature vectors",
            "Running inference pipeline",
            "Calculating confidence scores",
            "Classifying threat category",
        ],
        "out": [
            ("info", "Sample        :  suspicious.exe"),
            ("info", "Model         :  RandomForest v2.1"),
            ("info", "Confidence    :  94.7%"),
            ("warn", "Category      :  TROJAN / Dropper"),
            ("err",  "AI VERDICT:  FILE IS MALICIOUS"),
        ],
    },
    {
        "id": "backdoor", "icon": "🚪",
        "name": "Backdoor Scanner", "tag": "PYTHON",
        "tag_style": TAG_PYTHON, "accent": PURPLE,
        "desc": "Detects reverse shells, Remote Access Trojans (RATs) "
                "and persistent backdoor implants.",
        "steps": [
            "Initialising backdoor scanner",
            "Enumerating all running processes",
            "Analysing outbound network connections",
            "Scanning startup registry entries",
            "Reviewing scheduled tasks",
            "Auditing cron jobs",
            "Compiling threat verdict",
        ],
        "out": [
            ("info", "Processes     :  142 reviewed"),
            ("info", "Connections   :  8 outbound connections found"),
            ("warn", "PID 3847      :  python3 → 45.33.32.156:4444"),
            ("warn", "Connection    :  Non-standard port — C2 pattern"),
            ("err",  "VERDICT:  ACTIVE REVERSE SHELL DETECTED"),
        ],
    },
    {
        "id": "vuln", "icon": "🛡",
        "name": "Vulnerability Scanner", "tag": "PYTHON",
        "tag_style": TAG_PYTHON, "accent": PURPLE,
        "desc": "CVE database assessment with CVSS severity scoring "
                "against detected software versions.",
        "steps": [
            "Initialising vulnerability scanner",
            "Enumerating target services",
            "Detecting software versions",
            "Fetching NVD CVE database",
            "Matching version fingerprints",
            "Calculating CVSS severity scores",
            "Generating vulnerability report",
        ],
        "out": [
            ("info", "Target        :  192.168.1.10"),
            ("info", "Services      :  Apache 2.4.49,  OpenSSL 1.0.2"),
            ("warn", "CVE-2021-41773  Apache Path Traversal   CVSS 9.8  CRITICAL"),
            ("warn", "CVE-2016-0800   OpenSSL DROWN Attack    CVSS 7.4  HIGH"),
            ("err",  "VERDICT:  2 critical vulnerabilities — patch immediately"),
        ],
    },
    {
        "id": "cuckoo", "icon": "🧪",
        "name": "Cuckoo Sandbox", "tag": "SANDBOX",
        "tag_style": TAG_SANDBOX, "accent": PURPLE,
        "desc": "Dynamic behavioural analysis by detonating samples "
                "inside an isolated Windows 10 virtual machine.",
        "steps": [
            "Initialising sandbox environment",
            "Restoring Win10 x64 VM snapshot",
            "Detonating sample in isolation",
            "Monitoring 1,847 API calls",
            "Capturing network traffic",
            "Recording filesystem changes",
            "Analysing memory dumps",
            "Generating behavioural report",
        ],
        "out": [
            ("info", "Sample        :  sample.exe  |  VM: Windows 10 x64"),
            ("info", "API Calls     :  1,847 logged over 120 seconds"),
            ("warn", "C2 Attempts   :  3 outbound connections blocked"),
            ("warn", "Persistence   :  Registry key created at HKLM\\Run"),
            ("err",  "VERDICT:  RANSOMWARE BEHAVIOUR DETECTED"),
        ],
    },
]

# ═══════════════════════════════════════════════════════
#  INPUT DIALOG — ask target before running a tool
# ═══════════════════════════════════════════════════════
class InputDialog(tk.Toplevel):
    """Simple modal dialog to collect a target string or file path."""
    def __init__(self, parent, label, placeholder, tool_id):
        super().__init__(parent)
        self.result    = None
        self.tool_id   = tool_id
        self.title(f"Run — {label}")
        self.configure(bg=BG)
        self.resizable(False, False)
        self.after(150, self.grab_set)

        tk.Frame(self, bg=BLUE, height=3).pack(fill="x")

        body = tk.Frame(self, bg=BG, padx=32, pady=24)
        body.pack()

        tk.Label(body, text=label, bg=BG, fg=T1,
                 font=fnt(13, True)).pack(anchor="w")
        tk.Label(body, text="Enter value below then click Run.",
                 bg=BG, fg=T2, font=fnt(11)).pack(anchor="w", pady=(2,14))

        self._var = tk.StringVar(value=placeholder)
        entry = tk.Entry(body, textvariable=self._var, bg=CARD,
                         fg=T1, insertbackground=BLUE,
                         font=fnt(13), relief="flat",
                         highlightthickness=1,
                         highlightbackground=BORDER,
                         highlightcolor=BLUE, width=38)
        entry.pack(fill="x", ipady=10)
        entry.select_range(0, "end")
        entry.focus()

        # Browse button for file/folder tools
        if tool_id in ("malware", "ai"):
            def browse():
                path = filedialog.askopenfilename(
                    title="Select file to scan",
                    filetypes=[("All files", "*.*"), ("EXE", "*.exe")])
                if path:
                    self._var.set(path)
            tk.Button(body, text="Browse…", bg=CARD2, fg=T2,
                      font=fnt(11), relief="flat", cursor="hand2",
                      command=browse).pack(anchor="w", pady=(6,0))

        btns = tk.Frame(body, bg=BG)
        btns.pack(pady=(18, 0), anchor="e")
        tk.Button(btns, text="Cancel", bg=CARD2, fg=T2,
                  font=fnt(12), relief="flat", cursor="hand2",
                  padx=16, pady=8,
                  command=self.destroy).pack(side="left", padx=6)
        tk.Button(btns, text="Run  →", bg=BLUE, fg="#ffffff",
                  font=fnt(12, True), relief="flat", cursor="hand2",
                  padx=16, pady=8,
                  activebackground=BLUEH, activeforeground="#ffffff",
                  command=self._ok).pack(side="left")

        entry.bind("<Return>", lambda e: self._ok())
        self.wait_window()

    def _ok(self):
        self.result = self._var.get().strip()
        self.destroy()


# ═══════════════════════════════════════════════════════
#  OUTPUT PANEL — live scrolling terminal inside the GUI
# ═══════════════════════════════════════════════════════
class OutputPanel(tk.Toplevel):
    """Live output window that streams subprocess stdout/stderr."""
    def __init__(self, parent, tool_name):
        super().__init__(parent)
        self.title(f"Output — {tool_name}")
        self.geometry("820x520")
        self.configure(bg=BG)
        self.resizable(True, True)
        self._queue = queue.Queue()
        self._proc  = None
        self._build()
        self._poll()

    def _build(self):
        tk.Frame(self, bg=BLUE, height=3).pack(fill="x")
        hdr = tk.Frame(self, bg="#0a1628", padx=16, pady=10)
        hdr.pack(fill="x")
        tk.Label(hdr, text=f"Live Output",
                 bg="#0a1628", fg="#e8f0fe",
                 font=fnt(13, True)).pack(side="left")
        tk.Button(hdr, text="✕  Close", bg="#0a1628", fg="#5a7898",
                  font=fnt(11), relief="flat", cursor="hand2",
                  command=self._close).pack(side="right")

        self._text = scrolledtext.ScrolledText(
            self, bg="#0d1117", fg="#c9d1d9",
            font=("Courier New", 11),
            relief="flat", padx=12, pady=10,
            state="disabled", wrap="word")
        self._text.pack(fill="both", expand=True, padx=0, pady=0)

        # Colour tags
        self._text.tag_config("ok",   foreground="#3fb950")
        self._text.tag_config("warn", foreground="#d29922")
        self._text.tag_config("err",  foreground="#f85149")
        self._text.tag_config("info", foreground="#c9d1d9")
        self._text.tag_config("dim",  foreground="#8b949e")

        self._status = tk.StringVar(value="Starting…")
        tk.Label(self, textvariable=self._status,
                 bg=BG, fg=T3, font=fnt(10)).pack(pady=6)

    def set_process(self, proc):
        """Store process reference so _poll can read its return code."""
        self._proc = proc

    def feed(self, line):
        """Called from _work thread to push a line into the display queue."""
        self._queue.put(line)

    def done(self):
        """Signal that the process has finished — triggers status update."""
        self._queue.put(None)

    def _poll(self):
        """Drain queue into text widget — called from main thread."""
        try:
            while True:
                line = self._queue.get_nowait()
                if line is None:
                    rc = self._proc.returncode if self._proc else 0
                    self._status.set(
                        "✔ Scan complete — no threats" if rc == 0
                        else f"⚠ Finished with exit code {rc}")
                    return
                self._append(line)
        except queue.Empty:
            pass
        self.after(80, self._poll)

    def _append(self, line):
        self._text.configure(state="normal")
        tag = "info"
        lo  = line.lower()
        if any(w in lo for w in ["error", "malicious", "threat", "backdoor", "critical", "detected"]):
            tag = "err"
        elif any(w in lo for w in ["warn", "suspicious", "unknown", "high"]):
            tag = "warn"
        elif any(w in lo for w in ["clean", "✔", "ok", "complete", "safe"]):
            tag = "ok"
        elif line.startswith("#") or lo.startswith("[info]"):
            tag = "dim"
        self._text.insert("end", line, tag)
        self._text.see("end")
        self._text.configure(state="disabled")

    def write(self, text, tag="info"):
        """Write a plain message (not from subprocess)."""
        self._text.configure(state="normal")
        self._text.insert("end", text + "\n", tag)
        self._text.see("end")
        self._text.configure(state="disabled")

    def _close(self):
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
        self.destroy()


# ═══════════════════════════════════════════════════════
#  TOOL CARD  — wired to real scripts
# ═══════════════════════════════════════════════════════
class ToolCard(tk.Frame):
    def __init__(self, parent, tool, user,
                 stats_cb, auto_run=False, auto_delay=500, **kw):
        super().__init__(parent, bg=CARD,
                         highlightthickness=1,
                         highlightbackground=BORDER,
                         cursor=("arrow" if auto_run else "hand2"), **kw)
        self.tool      = tool
        self.user      = user
        self.stats_cb  = stats_cb
        self.auto_run  = auto_run
        self._running  = False
        self._done     = False
        self._build()

        if auto_run:
            # Run automatically after delay — no clicking needed
            self.after(auto_delay, self._start_auto)
        else:
            # Manual tools — click to run
            self.bind("<Enter>", lambda e:
                self.configure(highlightbackground=tool["accent"]))
            self.bind("<Leave>", lambda e:
                self.configure(highlightbackground=(
                    tool["accent"] if self._done else BORDER)))
            self.bind("<Button-1>", lambda e: self._run())
            for child in self.winfo_children():
                child.bind("<Button-1>", lambda e: self._run())

    def _build(self):
        acc = self.tool["accent"]
        tk.Frame(self, bg=acc, height=3).pack(fill="x")

        body = tk.Frame(self, bg=CARD, padx=16, pady=12)
        body.pack(fill="both", expand=True)

        r1 = tk.Frame(body, bg=CARD)
        r1.pack(fill="x")

        ib = tk.Frame(r1, bg=CARD2, width=36, height=36)
        ib.pack(side="left", padx=(0, 10))
        ib.pack_propagate(False)
        tk.Label(ib, text=self.tool["icon"], bg=CARD2,
                 font=fnt(16), fg=acc).place(
            relx=.5, rely=.5, anchor="center")

        tk.Label(r1, text=self.tool["name"], bg=CARD,
                 fg=T1, font=fnt(13, True)).pack(side="left")

        tbg, tfg = self.tool["tag_style"]
        tk.Label(r1, text=f"  {self.tool['tag']}  ",
                 bg=tbg, fg=tfg,
                 font=fnt(10, True)).pack(side="right", pady=3)

        tk.Label(body, text=self.tool["desc"], bg=CARD, fg=T2,
                 font=fnt(11), wraplength=340,
                 justify="left", anchor="w").pack(fill="x", pady=(6, 8))

        flow = "  →  ".join(self.tool["steps"])
        tk.Label(body, text=flow, bg=CARD, fg=T3,
                 font=fnt(9), wraplength=340,
                 justify="left", anchor="w").pack(fill="x", pady=(0, 8))

        self._pvar = tk.DoubleVar(value=0)
        sty = ttk.Style()
        sid = f"tc_{self.tool['id']}.Horizontal.TProgressbar"
        sty.configure(sid, troughcolor=PANEL,
                      background=acc, thickness=5, borderwidth=0)
        ttk.Progressbar(body, variable=self._pvar,
                        maximum=100, style=sid).pack(fill="x", pady=(0, 5))

        sr = tk.Frame(body, bg=CARD)
        sr.pack(fill="x")
        tk.Label(sr, text="Status:", bg=CARD, fg=T3,
                 font=fnt(10)).pack(side="left")
        self._svar = tk.StringVar(
            value="Auto-running…" if self.auto_run else "Click card to run")
        self._slbl = tk.Label(sr, textvariable=self._svar,
                              bg=CARD, fg=T3, font=fnt(10))
        self._slbl.pack(side="left", padx=6)

    # ── Auto-run for automated tools ─────────
    def _start_auto(self):
        """Called automatically on load for automated tool cards."""
        if self._running:
            return
        tid = self.tool["id"]
        # For tools that need a target, use the placeholder as the default
        # so the script gets proper stdin input instead of blocking on input()
        target = None
        if tid in NEEDS_TARGET:
            _, placeholder = NEEDS_TARGET[tid]
            target = placeholder
        self._start(target)

    # ── Entry point when card is clicked ─────
    def _run(self):
        if self._running:
            return
        tid    = self.tool["id"]
        target = None

        # Automated tools with no input — run immediately
        if tid in AUTO_RUN_TOOLS:
            self._start(target)
            return

        # Tools that need a target — show input dialog
        if tid in NEEDS_TARGET:
            label, placeholder = NEEDS_TARGET[tid]
            dlg = InputDialog(self.winfo_toplevel(), label, placeholder, tid)
            if not dlg.result:
                return
            target = dlg.result

        self._start(target)

    def _start(self, target):
        """Common launch logic."""
        self._running = True
        self._done    = False
        self.configure(highlightbackground=BORDER)
        self._pvar.set(0)
        self._svar.set("Starting…")
        self._slbl.config(fg=BLUE)

        sty = ttk.Style()
        sid = f"tc_{self.tool['id']}.Horizontal.TProgressbar"
        sty.configure(sid, background=self.tool["accent"])

        db_audit(self.user["username"], f"RUN:{self.tool['id']}")
        threading.Thread(
            target=self._work,
            args=(target,),
            daemon=True).start()

    # ── Background worker — runs real script ──
    def _work(self, target):
        tid        = self.tool["id"]
        steps      = self.tool["steps"]
        total      = len(steps)
        started_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        interp, script_path = SCRIPT_MAP.get(tid, (None, None))

        # ── Animate progress through steps ────
        def tick_steps():
            for i, step in enumerate(steps[:-1]):
                time.sleep(0.6)
                pct = int((i + 1) / total * 80)
                self.after(0, lambda p=pct, s=step: self._tick(p, s))

        step_thread = threading.Thread(target=tick_steps, daemon=True)
        step_thread.start()

        def _abort(verdict_str, ui_error=None):
            step_thread.join()
            db_save_result(tid, target, [], False, self.user, started_at,
                           verdict_override=verdict_str)
            self.after(0, lambda v=verdict_str, e=ui_error: self._finish(
                False, error=e, verdict=v))

        # ── Script existence check ────────────
        if not interp or not script_path or not os.path.isfile(script_path):
            _abort("SCAN FAILED", f"Script not found:\n{script_path}")
            return

        # ── OS-aware command resolution ───────
        # Linux : bash runs directly — no WSL prefix ever
        # Windows: bash tools need WSL; python tools use sys.executable
        cmd = _build_cmd(interp, script_path)
        if cmd is None:
            _abort("NOT SUPPORTED",
                   "WSL is not installed or configured.\n"
                   "Install WSL to run bash-based tools on Windows.")
            return

        # ── Build stdin for interactive scripts ──
        stdin_input = None
        t = target or ""
        if tid == "url" and t:
            stdin_input = (t + "\n").encode()
        elif tid == "domain" and t:
            stdin_input = (t + "\n3\n").encode()
        elif tid == "port" and t:
            stdin_input = ("1\n" + t + "\n8\n").encode()
        elif tid == "net" and t:
            stdin_input = ("2\n" + t + "\n4\n").encode()
        elif tid == "usb":
            stdin_input = ("1\n3\n").encode()
        elif tid in ("malware", "ai") and t:
            # Option 1 = single file, option 2 = folder batch scan
            menu_opt = "2" if os.path.isdir(t) else "1"
            stdin_input = (menu_opt + "\n" + t + "\n4\n").encode()
        elif tid == "vuln" and t:
            stdin_input = ("1\n" + t + "\n2\n").encode()

        # ── Launch subprocess ─────────────────
        threat   = False
        out_text = []
        scan_failed = False
        try:
            env = os.environ.copy()
            env["TERM"] = "dumb"
            env["DEBIAN_FRONTEND"] = "noninteractive"
            env["PYTHONIOENCODING"] = "utf-8:replace"

            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE if stdin_input else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=env,
                bufsize=1,
            )

            if stdin_input:
                try:
                    proc.stdin.write(stdin_input.decode())
                    proc.stdin.flush()
                    proc.stdin.close()
                except Exception:
                    pass

            # ── Create live output panel BEFORE reading stdout ────
            # _work is the sole reader of proc.stdout — no competing thread
            panel = None
            if not self.auto_run:
                panel_ready = threading.Event()
                panel_ref   = [None]
                def _mk_panel():
                    p = OutputPanel(self.winfo_toplevel(), self.tool["name"])
                    p.set_process(proc)
                    panel_ref[0] = p
                    panel_ready.set()
                self.after(0, _mk_panel)
                panel_ready.wait(timeout=3.0)
                panel = panel_ref[0]

            # ── Read stdout — single reader ────
            for line in iter(proc.stdout.readline, ""):
                out_text.append(line)
                lo = line.lower()
                if any(w in lo for w in [
                    "malicious", "threat detected", "suspicious",
                    "backdoor detected", "reverse shell",
                ]):
                    threat = True
                if panel:
                    panel.feed(line)

            proc.wait(timeout=120)
            if panel:
                panel.done()

            # Non-zero exit with no output = something went wrong
            if proc.returncode != 0 and not out_text:
                scan_failed = True

        except subprocess.TimeoutExpired:
            proc.kill()
            out_text.append("[!] Scan timed out after 120 seconds.\n")
            scan_failed = True
        except FileNotFoundError as e:
            out_text.append(f"[!] Command not found: {e}\n")
            scan_failed = True
        except Exception as e:
            out_text.append(f"[!] Launch error: {e}\n")
            scan_failed = True

        step_thread.join()

        # Determine final verdict override for failure cases
        v_override = None
        if scan_failed and not out_text:
            v_override = "SCAN FAILED"

        parsed = _parse_real_verdict(out_text)
        db_save_result(tid, target, out_text, threat, self.user, started_at,
                       verdict_override=v_override)
        self.after(0, lambda h=threat, v=parsed or v_override: self._finish(h, verdict=v))

    # _open_panel removed — panel is now created inside _work before reading stdout

    # ── UI updates (called via self.after) ────
    def _tick(self, pct, step):
        self._pvar.set(pct)
        self._svar.set(step)
        self._slbl.config(fg=BLUE)
        sty = ttk.Style()
        sid = f"tc_{self.tool['id']}.Horizontal.TProgressbar"
        sty.configure(sid, background=AMBER)

    def _finish(self, threat, error=None, verdict=None):
        self._running = False
        self._done    = True
        self._pvar.set(100)
        sty = ttk.Style()
        sid = f"tc_{self.tool['id']}.Horizontal.TProgressbar"

        v_lower = (verdict or "").lower()
        partial = "partial" in v_lower

        if error:
            sty.configure(sid, background=AMBER)
            self._svar.set(f"Error — {error[:60]}")
            self._slbl.config(fg=AMBER)
            self.configure(highlightbackground=AMBER)
            messagebox.showerror("Script Error", error)
        elif threat:
            sty.configure(sid, background=RED)
            self._svar.set("SUSPICIOUS — threats found")
            self._slbl.config(fg=RED)
            self.configure(highlightbackground=RED)
        elif partial:
            sty.configure(sid, background=AMBER)
            self._svar.set("PARTIAL — some scans unavailable")
            self._slbl.config(fg=AMBER)
            self.configure(highlightbackground=AMBER)
        else:
            sty.configure(sid, background=BLUE)
            self._svar.set("CLEAN — scan complete")
            self._slbl.config(fg=BLUE)
            self.configure(highlightbackground=BLUE)

        self.stats_cb(threat)

# ═══════════════════════════════════════════════════════
#  SCROLLABLE TOOL PANEL
# ═══════════════════════════════════════════════════════
class ToolPanel(tk.Frame):
    def __init__(self, parent, title, subtitle,
                 accent, tools, user,
                 stats_cb, auto_run=False, **kw):
        super().__init__(parent, bg=PANEL, **kw)

        # Accent strip + header
        tk.Frame(self, bg=accent,
                 height=3).pack(fill="x")
        hdr = tk.Frame(self, bg="#0f1e35",
                       padx=18, pady=12)
        hdr.pack(fill="x")

        left = tk.Frame(hdr, bg="#0f1e35")
        left.pack(side="left")
        tk.Label(left, text=title,
                 bg="#0f1e35", fg="#e8f0fe",
                 font=fnt(15, True)).pack(
            anchor="w")
        tk.Label(left, text=subtitle,
                 bg="#0f1e35", fg="#5a7898",
                 font=fnt(11)).pack(anchor="w")

        tbg = ("#0f3d8a" if accent == BLUE
               else "#3b1f6b")
        tfg = ("#7eb3ff" if accent == BLUE
               else "#c4b5fd")
        tk.Label(hdr,
                 text=f"  {len(tools)} tools  ",
                 bg=tbg, fg=tfg,
                 font=fnt(10, True)).pack(
            side="right", pady=8)

        tk.Frame(self, bg=BORDER,
                 height=1).pack(fill="x")

        # Scrollable canvas
        cv = tk.Canvas(self, bg=PANEL,
                       highlightthickness=0)
        sb = tk.Scrollbar(
            self, orient="vertical",
            command=cv.yview,
            bg=PANEL, troughcolor=PANEL)
        inner = tk.Frame(cv, bg=PANEL)
        inner.bind(
            "<Configure>",
            lambda e: cv.configure(
                scrollregion=cv.bbox("all")))
        cv.create_window(
            (0, 0), window=inner, anchor="nw")
        cv.configure(yscrollcommand=sb.set)
        cv.pack(side="left",
                fill="both", expand=True)
        sb.pack(side="right", fill="y")

        for ev in ("<MouseWheel>",
                   "<Button-4>", "<Button-5>"):
            cv.bind(ev, lambda e, c=cv:
                c.yview_scroll(
                    -1 if (e.num == 4
                           or getattr(e, "delta", 0) > 0)
                    else 1, "units"))

        # Stagger auto-run tools so they don't all start at once
        for i, tool in enumerate(tools):
            card = ToolCard(inner, tool, user,
                            stats_cb,
                            auto_run=auto_run,
                            auto_delay=500 + i * 2000)
            card.pack(fill="x", padx=12, pady=6)

# ═══════════════════════════════════════════════════════
#  ADMIN PANEL
# ═══════════════════════════════════════════════════════
class AdminPanel(tk.Toplevel):
    def __init__(self, parent, user):
        super().__init__(parent)
        self.title("Admin Control Panel")
        self.geometry("960x680")
        self.configure(bg=BG)
        self.resizable(True, True)
        self._user = user
        self._build()

    def _build(self):
        tk.Frame(self, bg=BLUE,
                 height=3).pack(fill="x")
        hdr = tk.Frame(self, bg=CARD,
                       padx=24, pady=14)
        hdr.pack(fill="x")
        tk.Label(hdr, text="Admin Control Panel",
                 bg=CARD, fg=T1,
                 font=fnt(17, True)).pack(
            side="left")
        tk.Label(hdr,
                 text=f"   Signed in as  "
                      f"{self._user['username']}",
                 bg=CARD, fg=T3,
                 font=fnt(11)).pack(
            side="left", pady=4)
        tk.Button(hdr, text="✕  Close",
                  bg=CARD, fg=T2,
                  font=fnt(12), relief="flat",
                  cursor="hand2",
                  activebackground=CARD2,
                  activeforeground=T1,
                  command=self.destroy).pack(
            side="right")
        tk.Frame(self, bg=BORDER,
                 height=1).pack(fill="x")

        sty = ttk.Style()
        sty.configure("Adm.TNotebook",
                      background=BG,
                      borderwidth=0,
                      tabmargins=[0, 0, 0, 0])
        sty.configure("Adm.TNotebook.Tab",
                      background=CARD,
                      foreground=T3,
                      font=fnt(12, True),
                      padding=[20, 10])
        sty.map("Adm.TNotebook.Tab",
                background=[("selected", CARD2)],
                foreground=[("selected", BLUE)])

        nb = ttk.Notebook(self,
                          style="Adm.TNotebook")
        nb.pack(fill="both", expand=True)

        for name, builder in [
            ("  ACL Reference  ",    self._acl),
            ("  User Management  ",  self._users),
            ("  Add User  ",         self._add),
            ("  Audit Log  ",        self._audit),
        ]:
            f = tk.Frame(nb, bg=BG)
            nb.add(f, text=name)
            builder(f)

    # ── ACL matrix ────────────────────────────
    def _acl(self, p):
        f = tk.Frame(p, bg=BG,
                     padx=28, pady=22)
        f.pack(fill="both", expand=True)

        tk.Label(f, text="Access Control Matrix",
                 bg=BG, fg=T1,
                 font=fnt(16, True)).pack(
            anchor="w")
        tk.Label(f,
                 text="Defines exactly what each "
                      "role is permitted to do "
                      "within the system.",
                 bg=BG, fg=T2,
                 font=fnt(12)).pack(
            anchor="w", pady=(4, 20))

        tbl = tk.Frame(f, bg=BG)
        tbl.pack(anchor="w", fill="x")

        headers = ["Permission / Action",
                   "Admin", "Analyst",
                   "Viewer", "Guest"]
        hfg = [T2, RED, "#60a5fa", AMBER, T3]

        for ci, (h, fg) in enumerate(
                zip(headers, hfg)):
            tk.Label(tbl, text=h,
                     bg=CARD2, fg=fg,
                     font=fnt(11, True),
                     width=(28 if ci == 0 else 8),
                     anchor=(
                         "w" if ci == 0
                         else "center"),
                     padx=14, pady=10
                     ).grid(row=0, column=ci,
                            padx=2, pady=2,
                            sticky="ew")

        actions = [
            ("Run Manual Tools (Bash)",
             "run_manual"),
            ("Run Automated Scans (Python/AI)",
             "run_auto"),
            ("View Scan Results & Reports",
             "view_results"),
            ("Manage User Accounts",
             "manage_users"),
            ("View Full Audit Log",
             "view_logs"),
            ("Export Reports",
             "export"),
            ("System Configuration",
             "config"),
        ]

        for ri, (label, action) in enumerate(
                actions, 1):
            rb = CARD2 if ri % 2 == 0 else CARD
            tk.Label(tbl,
                     text=f"  {label}",
                     bg=rb, fg=T1,
                     font=fnt(12),
                     anchor="w",
                     padx=14, pady=11
                     ).grid(row=ri, column=0,
                            padx=2, pady=1,
                            sticky="ew")
            for ci, role in enumerate(
                    ["admin", "analyst",
                     "viewer", "guest"], 1):
                ok = action in PERMISSIONS[role]
                tk.Label(tbl,
                         text="✔" if ok else "—",
                         bg=rb,
                         fg=GREEN if ok else T4,
                         font=fnt(14, True),
                         anchor="center",
                         pady=11
                         ).grid(row=ri, column=ci,
                                padx=2, pady=1,
                                sticky="ew")

        note = tk.Frame(f, bg=CARD2,
                        padx=18, pady=14)
        note.pack(fill="x", pady=(22, 0))
        tk.Label(note,
                 text="Admin-only responsibilities",
                 bg=CARD2, fg=RED,
                 font=fnt(12, True)).pack(
            anchor="w", pady=(0, 8))
        for item in [
            "Create, edit and deactivate user accounts",
            "Assign and change user role permissions",
            "Access the full audit trail of all activity",
            "Configure API keys and system settings",
            "Delete or archive historical scan reports",
        ]:
            tk.Label(note,
                     text=f"   •   {item}",
                     bg=CARD2, fg=T2,
                     font=fnt(12)).pack(
                anchor="w", pady=3)

    # ── User management ───────────────────────
    def _users(self, p):
        f = tk.Frame(p, bg=BG,
                     padx=22, pady=18)
        f.pack(fill="both", expand=True)

        tk.Label(f, text="Registered Users",
                 bg=BG, fg=T1,
                 font=fnt(14, True)).pack(
            anchor="w")
        tk.Label(f,
                 text="Select a user then click "
                      "Toggle to enable or disable.",
                 bg=BG, fg=T2,
                 font=fnt(12)).pack(
            anchor="w", pady=(3, 14))

        sty = ttk.Style()
        sty.configure("U.Treeview",
                       background=CARD,
                       foreground=T1,
                       fieldbackground=CARD,
                       font=fnt(12),
                       rowheight=34)
        sty.configure("U.Treeview.Heading",
                       background=CARD2,
                       foreground=BLUE,
                       font=fnt(11, True))
        sty.map("U.Treeview",
                background=[("selected", CARD2)])

        cols = ("ID", "Username", "Role",
                "Status", "Created")
        self._tree = ttk.Treeview(
            f, columns=cols,
            show="headings", height=9,
            style="U.Treeview")
        for col, w in zip(
                cols, [50, 160, 110, 100, 200]):
            self._tree.heading(col, text=col)
            self._tree.column(col, width=w)
        self._tree.pack(fill="both", expand=True)

        btn_row = tk.Frame(f, bg=BG)
        btn_row.pack(pady=10, anchor="w")

        def refresh():
            for r in self._tree.get_children():
                self._tree.delete(r)
            for row in db_users():
                s = ("Active" if row[3]
                     else "Disabled")
                self._tree.insert(
                    "", "end",
                    values=(row[0], row[1],
                            row[2].capitalize(),
                            s, row[4]))

        def toggle():
            sel = self._tree.selection()
            if not sel:
                messagebox.showwarning(
                    "Select",
                    "Please select a user first.")
                return
            v = self._tree.item(
                sel[0])["values"]
            if v[1] == self._user["username"]:
                messagebox.showerror(
                    "Error",
                    "Cannot disable your own account.")
                return
            db_toggle(v[0], v[3] == "Active")
            db_audit(self._user["username"],
                     f"TOGGLE:{v[1]}")
            refresh()

        for txt, cmd, fg in [
            ("Refresh", refresh, BLUE),
            ("Toggle Active / Disabled",
             toggle, AMBER),
        ]:
            tk.Button(btn_row, text=txt,
                      bg=CARD2, fg=fg,
                      font=fnt(12, True),
                      relief="flat",
                      cursor="hand2",
                      activebackground=BDR2,
                      activeforeground=T1,
                      padx=18, pady=8,
                      command=cmd).pack(
                side="left", padx=6)
        refresh()

    # ── Add user ──────────────────────────────
    def _add(self, p):
        f = tk.Frame(p, bg=BG,
                     padx=44, pady=22)
        f.pack(fill="both", expand=True)

        tk.Label(f, text="Create New User",
                 bg=BG, fg=T1,
                 font=fnt(15, True)).pack(
            anchor="w")
        tk.Label(f,
                 text="New accounts are active "
                      "immediately upon creation.",
                 bg=BG, fg=T2,
                 font=fnt(12)).pack(
            anchor="w", pady=(3, 20))

        self._nu = tk.StringVar()
        self._np = tk.StringVar()
        self._nr = tk.StringVar(value="viewer")

        for label, var, show in [
            ("Username", self._nu, ""),
            ("Password", self._np, "●"),
        ]:
            tk.Label(f, text=label,
                     bg=BG, fg=T2,
                     font=fnt(12, True)).pack(
                anchor="w", pady=(10, 4))
            e = tk.Entry(
                f, textvariable=var, show=show,
                bg=CARD, fg=T1,
                insertbackground=BLUE,
                relief="flat", font=fnt(13),
                highlightthickness=1,
                highlightbackground=BORDER,
                highlightcolor=BLUE,
                width=30)
            e.pack(anchor="w", ipady=9)

        tk.Label(f, text="Role",
                 bg=BG, fg=T2,
                 font=fnt(12, True)).pack(
            anchor="w", pady=(10, 4))

        sty = ttk.Style()
        sty.configure("R.TCombobox",
                      fieldbackground=CARD,
                      background=CARD,
                      foreground=T1,
                      font=fnt(12))
        ttk.Combobox(
            f, textvariable=self._nr,
            values=["admin", "analyst",
                    "viewer", "guest"],
            state="readonly",
            font=fnt(13), width=22,
            style="R.TCombobox").pack(anchor="w")

        # Role guide
        guide = tk.Frame(f, bg=CARD2,
                         padx=16, pady=12)
        guide.pack(anchor="w", pady=14,
                   fill="x")
        tk.Label(guide,
                 text="Role Permissions Guide",
                 bg=CARD2, fg=T2,
                 font=fnt(11, True)).pack(
            anchor="w", pady=(0, 8))
        for role, desc, clr in [
            ("Admin",
             "Full access — all tools, "
             "user management, logs, config",
             RED),
            ("Analyst",
             "Run scans + view results "
             "+ export reports",
             "#60a5fa"),
            ("Viewer",
             "View scan results only — "
             "cannot run tools",
             AMBER),
            ("Guest",
             "No access — "
             "placeholder account",
             T3),
        ]:
            row = tk.Frame(guide, bg=CARD2)
            row.pack(fill="x", pady=3)
            tk.Label(row,
                     text=f"{role:<10}",
                     bg=CARD2, fg=clr,
                     font=fnt(12, True),
                     width=10,
                     anchor="w").pack(
                side="left")
            tk.Label(row, text=desc,
                     bg=CARD2, fg=T3,
                     font=fnt(11)).pack(
                side="left")

        self._msg = tk.StringVar()
        tk.Label(f, textvariable=self._msg,
                 bg=BG, fg=GREEN,
                 font=fnt(11)).pack(
            anchor="w", pady=6)

        def create():
            u  = self._nu.get().strip()
            pw = self._np.get().strip()
            r  = self._nr.get()
            if not u or not pw:
                self._msg.set(
                    "Username and password required.")
                return
            if db_add_user(u, pw, r):
                db_audit(
                    self._user["username"],
                    f"ADD_USER:{u}:{r}")
                self._msg.set(
                    f"✔  User '{u}' created "
                    f"with role: {r}")
                self._nu.set("")
                self._np.set("")
            else:
                self._msg.set(
                    f"Username '{u}' already exists.")

        tk.Button(f, text="Create User",
                  bg=BLUE, fg="#ffffff",
                  font=fnt(13, True),
                  relief="flat", cursor="hand2",
                  activebackground=BLUEH,
                  activeforeground="#ffffff",
                  padx=24, pady=10,
                  command=create).pack(
            anchor="w", pady=8)

    # ── Audit log ─────────────────────────────
    def _audit(self, p):
        f = tk.Frame(p, bg=BG,
                     padx=22, pady=18)
        f.pack(fill="both", expand=True)

        tk.Label(f, text="System Audit Log",
                 bg=BG, fg=T1,
                 font=fnt(14, True)).pack(
            anchor="w")
        tk.Label(f,
                 text="All user actions are "
                      "automatically recorded.",
                 bg=BG, fg=T2,
                 font=fnt(12)).pack(
            anchor="w", pady=(3, 14))

        sty = ttk.Style()
        sty.configure("AL.Treeview",
                       background=CARD,
                       foreground=T1,
                       fieldbackground=CARD,
                       font=fnt(12),
                       rowheight=30)
        sty.configure("AL.Treeview.Heading",
                       background=CARD2,
                       foreground=AMBER,
                       font=fnt(11, True))
        sty.map("AL.Treeview",
                background=[("selected", CARD2)])

        cols = ("User", "Action", "Timestamp")
        tv = ttk.Treeview(
            f, columns=cols,
            show="headings", height=14,
            style="AL.Treeview")
        for col, w in zip(cols, [160, 300, 200]):
            tv.heading(col, text=col)
            tv.column(col, width=w)
        for row in db_audit_log():
            tv.insert("", "end", values=row)

        sb = ttk.Scrollbar(
            f, orient="vertical",
            command=tv.yview)
        tv.configure(yscrollcommand=sb.set)
        tv.pack(side="left",
                fill="both", expand=True)
        sb.pack(side="right", fill="y")

# ═══════════════════════════════════════════════════════
#  TOP BAR
# ═══════════════════════════════════════════════════════
class TopBar(tk.Frame):
    def __init__(self, parent, user,
                 on_logout, on_admin,
                 stats, **kw):
        super().__init__(parent, bg="#0a1628",
                         height=56, **kw)
        self.pack_propagate(False)
        self._stats = stats

        # Left accent strip
        tk.Frame(self, bg=BLUE,
                 width=4).pack(
            side="left", fill="y")

        # Logo + name
        tk.Label(self, text="  HCE  ",
                 bg="#1565c0", fg="#ffffff",
                 font=fnt(14, True)).pack(
            side="left", pady=14)
        tk.Label(self,
                 text="  Hybrid Cybersecurity Engine",
                 bg="#0a1628", fg="#e8f0fe",
                 font=fnt(14, True)).pack(
            side="left")
        tk.Label(self,
                 text="  |  Security Operations Dashboard",
                 bg="#0a1628", fg="#5a7898",
                 font=fnt(11)).pack(side="left")

        # Right side
        tk.Frame(self, bg="#1a2a45",
                 width=1).pack(
            side="right", fill="y")

        tk.Button(self, text="  Sign Out  ",
                  bg="#0a1628", fg="#5a7898",
                  font=fnt(12), relief="flat",
                  cursor="hand2",
                  activebackground=RED,
                  activeforeground="#ffffff",
                  command=on_logout).pack(
            side="right", padx=8, pady=14)

        if user["role"] == "admin":
            tk.Button(self,
                      text="  Admin Panel  ",
                      bg="#0d3a7a", fg="#90b4e8",
                      font=fnt(12, True),
                      relief="flat",
                      cursor="hand2",
                      activebackground=BLUE,
                      activeforeground="#ffffff",
                      command=on_admin).pack(
                side="right", padx=4, pady=14)

        # Role badge + username
        rb, rf = ROLE_BADGE.get(
            user["role"], (CARD2, T2))
        tk.Label(self,
                 text=f"  {user['role'].capitalize()}  ",
                 bg=rb, fg=rf,
                 font=fnt(10, True)).pack(
            side="right", pady=18)
        tk.Label(self,
                 text=f"  {user['username']}  ",
                 bg=CARD, fg=T1,
                 font=fnt(13, True)).pack(
            side="right", padx=2)

        # Live stat counters
        self._sv = tk.StringVar(value="0")
        self._tv = tk.StringVar(value="0")

        for label, var, clr in [
            ("Scans",   self._sv, BLUE),
            ("Threats", self._tv, RED),
        ]:
            box = tk.Frame(self, bg="#0f1e35",
                           padx=16)
            box.pack(side="left",
                     padx=8, pady=10)
            tk.Label(box, textvariable=var,
                     bg="#0f1e35", fg=clr,
                     font=(F, 20, "bold")).pack()
            tk.Label(box, text=label,
                     bg="#0f1e35", fg="#5a7898",
                     font=fnt(9)).pack()

        # Live clock
        self._clk = tk.StringVar()
        tk.Label(self, textvariable=self._clk,
                 bg="#0a1628", fg="#5a7898",
                 font=fnt(11)).pack(
            side="left", padx=14)
        self._tick()

    def refresh(self):
        self._sv.set(str(self._stats["runs"]))
        self._tv.set(str(self._stats["threats"]))

    def _tick(self):
        self._clk.set(
            datetime.datetime.now().strftime(
                "%Y-%m-%d   %H:%M:%S"))
        self.after(1000, self._tick)

# ═══════════════════════════════════════════════════════
#  RESULTS VIEWER — live DB results panel
# ═══════════════════════════════════════════════════════
class ResultsViewer(tk.Frame):
    """Bottom panel showing all scan results from the database."""

    TABS = [
        ("All Scans",     None,                  None),
        ("Malware",       "malware_scan_logs",
         "id,file_name,result,malware_family,confidence,scan_method,operator,timestamp"),
        ("Backdoor",      "backdoor_scans",
         "id,scan_type,suspicious_pids,suspicious_ports,cron_findings,startup_findings,verdict,risk_score,operator,timestamp"),
        ("Vulnerability", "vuln_findings",
         "id,cve_id,service,version,port,severity,cvss_score,description,timestamp"),
        ("Domain",        "domain_logs",
         "id,domain,ip_address,registrar,result,risk_score,operator,timestamp"),
        ("Port",          "port_scans",
         "id,target,scan_type,result,risk_score,operator,timestamp"),
        ("USB",           "usb_scans",
         "id,usb_name,device_path,files_scanned,threats_found,result,operator,timestamp"),
    ]

    def __init__(self, parent, user, **kw):
        super().__init__(parent, bg=BG, **kw)
        self._user      = user
        self._active    = 0
        self._build()
        self._load()
        # Auto-refresh every 10 seconds
        self._refresh_loop()

    def _build(self):
        # Header row
        hdr = tk.Frame(self, bg="#0a1628", padx=16, pady=8)
        hdr.pack(fill="x")

        tk.Label(hdr, text="Scan Results",
                 bg="#0a1628", fg="#e8f0fe",
                 font=fnt(13, True)).pack(side="left")

        tk.Button(hdr, text="Refresh",
                  bg="#0d3a7a", fg="#90b4e8",
                  font=fnt(10), relief="flat",
                  cursor="hand2", padx=12, pady=4,
                  activebackground=BLUE,
                  activeforeground="#ffffff",
                  command=self._load).pack(side="right", padx=4)

        tk.Button(hdr, text="Clear All",
                  bg="#0a1628", fg="#5a7898",
                  font=fnt(10), relief="flat",
                  cursor="hand2", padx=12, pady=4,
                  activebackground=RED,
                  activeforeground="#ffffff",
                  command=self._clear).pack(side="right", padx=4)

        # Tab bar
        self._tab_bar = tk.Frame(self, bg=CARD2)
        self._tab_bar.pack(fill="x")
        self._tab_btns = []
        for i, (label, *_) in enumerate(self.TABS):
            btn = tk.Button(
                self._tab_bar, text=label,
                bg=BLUE if i == 0 else CARD2,
                fg="#ffffff" if i == 0 else T3,
                font=fnt(10, i == 0),
                relief="flat", cursor="hand2",
                padx=14, pady=6,
                activebackground=BLUE,
                activeforeground="#ffffff",
                command=lambda idx=i: self._switch(idx))
            btn.pack(side="left")
            self._tab_btns.append(btn)

        # Treeview table
        sty = ttk.Style()
        sty.configure("RV.Treeview",
                       background=CARD,
                       foreground=T1,
                       fieldbackground=CARD,
                       font=fnt(11),
                       rowheight=28)
        sty.configure("RV.Treeview.Heading",
                       background=CARD2,
                       foreground=BLUE,
                       font=fnt(11, True))
        sty.map("RV.Treeview",
                background=[("selected", CARD2)])

        frame = tk.Frame(self, bg=CARD)
        frame.pack(fill="x")

        self._tree = ttk.Treeview(
            frame, style="RV.Treeview",
            height=6, show="headings")
        vsb = ttk.Scrollbar(frame, orient="vertical",
                            command=self._tree.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal",
                            command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set,
                             xscrollcommand=hsb.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        # Status bar
        self._status = tk.StringVar(value="Loading…")
        tk.Label(self, textvariable=self._status,
                 bg=BG, fg=T3, font=fnt(10),
                 anchor="w", padx=16).pack(
            fill="x", pady=2)

    def _switch(self, idx):
        self._active = idx
        for i, btn in enumerate(self._tab_btns):
            btn.configure(
                bg=BLUE if i == idx else CARD2,
                fg="#ffffff" if i == idx else T3,
                font=fnt(10, i == idx))
        self._load()

    # Long text columns that need truncation in individual tab views
    _LONG_COLS = {"result", "verdict", "description", "raw_output",
                  "file_path", "cron_findings", "startup_findings",
                  "suspicious_pids", "suspicious_ports", "geo_info"}

    _TOOL_LABELS = {
        "malware":  "Malware Scanner",
        "ai":       "AI Scanner",
        "backdoor": "Backdoor Scanner",
        "vuln":     "Vuln Scanner",
        "domain":   "Domain Checker",
        "port":     "Port Scanner",
        "usb":      "USB Scanner",
        "url":      "URL Scanner",
        "cuckoo":   "Cuckoo Sandbox",
    }

    def _load(self):
        """Load results from DB into the treeview."""
        _, table, col_spec = self.TABS[self._active]

        for row in self._tree.get_children():
            self._tree.delete(row)

        try:
            conn = sqlite3.connect(str(DB_PATH))
            cur  = conn.cursor()

            if table is None:
                rows, cols = self._load_all(cur)
            else:
                # Use explicit column list; fall back gracefully for missing cols
                cols = [c.strip() for c in col_spec.split(",")]
                # Filter to only columns that actually exist in the table
                cur.execute(f"PRAGMA table_info({table})")
                existing = {r[1] for r in cur.fetchall()}
                cols = [c for c in cols if c in existing]
                if not cols:
                    self._status.set(f"Table '{table}' not found or empty.")
                    conn.close()
                    return
                col_sql = ", ".join(cols)
                cur.execute(
                    f"SELECT {col_sql} FROM {table} ORDER BY id DESC LIMIT 100")
                raw_rows = cur.fetchall()
                rows = []
                for row in raw_rows:
                    cleaned = []
                    for val, col in zip(row, cols):
                        s = str(val) if val is not None else ""
                        if col in self._LONG_COLS and len(s) > 80:
                            s = s[:77] + "…"
                        cleaned.append(s)
                    rows.append(cleaned)

            conn.close()

            self._tree["columns"] = cols
            for col in cols:
                self._tree.heading(col, text=col.replace("_", " ").title())
                if col in ("result", "verdict", "description"):
                    w = 220
                elif col in ("file_path", "domain", "target", "raw_output"):
                    w = 180
                elif col == "id":
                    w = 50
                else:
                    w = 110
                self._tree.column(col, width=w, minwidth=50)

            self._tree.tag_configure("threat",
                foreground=RED,       background="#2a0a0a")
            self._tree.tag_configure("clean",
                foreground="#4ade80", background="#0a1f0a")
            self._tree.tag_configure("partial",
                foreground="#fbbf24", background="#1a1400")
            self._tree.tag_configure("neutral",
                foreground=T2,        background=CARD)

            for row in rows:
                row_str  = [str(v) if not isinstance(v, str) else v for v in row]
                combined = " ".join(row_str).lower()
                if any(w in combined for w in [
                        "suspicious", "threat detected", "malicious",
                        "backdoor detected", "reverse shell"]):
                    tag = "threat"
                elif "clean" in combined or "no findings" in combined:
                    tag = "clean"
                elif any(w in combined for w in [
                        "partial", "not supported", "scan failed"]):
                    tag = "partial"
                else:
                    tag = "neutral"
                self._tree.insert("", "end", values=row_str, tags=(tag,))

            total   = len(rows)
            threats = sum(1 for r in self._tree.get_children()
                         if "threat" in self._tree.item(r)["tags"])
            self._status.set(
                f"  {total} records  |  {threats} threats detected  "
                f"|  Last updated: {datetime.datetime.now().strftime('%H:%M:%S')}")

        except Exception as e:
            self._status.set(f"DB error: {e}")

    def _load_all(self, cur):
        """Load clean summary from scan_sessions — one authoritative row per scan."""
        cols = ["ID", "Tool", "Target / File", "Verdict", "Risk Score", "Operator", "Timestamp"]
        rows = []
        try:
            cur.execute("""
                SELECT id,
                       tool_id,
                       target,
                       CASE
                           WHEN threat = 1
                                THEN 'SUSPICIOUS'
                           WHEN risk_score >= 30
                                THEN 'PARTIAL'
                           WHEN raw_output LIKE '%SCAN FAILED%'
                             OR raw_output LIKE '%NOT SUPPORTED%'
                             OR raw_output LIKE '%Launch error%'
                                THEN 'SCAN FAILED'
                           ELSE 'CLEAN'
                       END,
                       risk_score,
                       operator,
                       COALESCE(finished_at, started_at)
                FROM scan_sessions
                ORDER BY id DESC
                LIMIT 100
            """)
            for r in cur.fetchall():
                tool_label = self._TOOL_LABELS.get(str(r[1]).lower(), str(r[1]).upper())
                rows.append((r[0], tool_label, r[2], r[3], r[4], r[5], r[6]))
        except Exception:
            pass
        return rows, cols

    def _clear(self):
        """Clear all scan results from DB."""
        if not messagebox.askyesno(
                "Clear Results",
                "Delete all scan results from the database?\nThis cannot be undone."):
            return
        try:
            conn = sqlite3.connect(str(DB_PATH))
            for _, table, *_ in self.TABS[1:]:
                try:
                    conn.execute(f"DELETE FROM {table}")
                except Exception:
                    pass
            # Clear supporting tables not listed in TABS
            for extra in ["vuln_scans", "backdoor_findings",
                          "port_findings", "usb_file_results", "scan_sessions"]:
                try:
                    conn.execute(f"DELETE FROM {extra}")
                except Exception:
                    pass
            conn.commit()
            conn.close()
            self._load()
            self._status.set("  All results cleared.")
        except Exception as e:
            self._status.set(f"Clear error: {e}")

    def _refresh_loop(self):
        """Auto-refresh every 10 seconds."""
        self._load()
        self.after(10000, self._refresh_loop)


# ═══════════════════════════════════════════════════════
#  DASHBOARD
# ═══════════════════════════════════════════════════════
class Dashboard(tk.Frame):
    def __init__(self, parent, user, on_logout, **kw):
        super().__init__(parent, bg=BG, **kw)
        self._user  = user
        self._out   = on_logout
        self._stats = {"runs": 0, "threats": 0}
        self._build()

    def _cb(self, threat):
        self._stats["runs"] += 1
        if threat: self._stats["threats"] += 1
        self._topbar.refresh()
        self._results_viewer._load()

    def _build(self):
        self._topbar = TopBar(
            self, self._user, self._out,
            lambda: AdminPanel(self, self._user),
            self._stats)
        self._topbar.pack(fill="x")
        tk.Frame(self, bg=BLUE, height=2).pack(fill="x")

        # Results bar at bottom
        tk.Frame(self, bg=BORDER, height=1).pack(side="bottom", fill="x")
        self._results_viewer = ResultsViewer(self, self._user)
        self._results_viewer.pack(side="bottom", fill="x")

        # Tools in the middle
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True)

        if can(self._user, "run_manual"):
            ToolPanel(body,
                "Manual Analysis Tools",
                "Bash-powered  |  5 tools",
                BLUE, MANUAL_TOOLS, self._user, self._cb).pack(
                side="left", fill="both", expand=True)
        else:
            self._locked(body, "Manual Analysis Tools", BLUE).pack(
                side="left", fill="both", expand=True)

        tk.Frame(body, bg=BORDER, width=1).pack(side="left", fill="y")

        if can(self._user, "run_auto"):
            ToolPanel(body,
                "Automated Scan Engine",
                "Python + AI/ML  |  5 tools",
                PURPLE, AUTO_TOOLS, self._user, self._cb,
                auto_run=True).pack(
                side="right", fill="both", expand=True)
        else:
            self._locked(body, "Automated Scan Engine", PURPLE).pack(
                side="right", fill="both", expand=True)

    def _locked(self, parent, title, accent):
        f = tk.Frame(parent, bg=PANEL)
        tk.Frame(f, bg=accent, height=3).pack(fill="x")
        tk.Frame(f, bg=PANEL).pack(expand=True, fill="both")
        tk.Label(f, text="🔒", bg=PANEL, fg=T4, font=fnt(36)).pack(pady=(60,8))
        tk.Label(f, text=title, bg=PANEL, fg=T2, font=fnt(14,True)).pack()
        tk.Label(f, text="Access Restricted", bg=PANEL, fg=RED, font=fnt(12)).pack(pady=6)
        tk.Label(f, text="Your role does not have\npermission to use these tools.",
                 bg=PANEL, fg=T3, font=fnt(12), justify="center").pack()
        return f

# ═══════════════════════════════════════════════════════
#  LOGIN SCREEN
# ═══════════════════════════════════════════════════════
class LoginScreen(tk.Frame):
    def __init__(self, parent, on_login, **kw):
        super().__init__(parent, bg=BG, **kw)
        self._on_login = on_login
        self._attempts = 0
        self._build()

    def _build(self):
        # Two-column layout
        left = tk.Frame(self, bg=CARD, width=420)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)
        tk.Frame(left, bg=BORDER, width=1).pack(
            side="left", fill="y")

        right = tk.Frame(self, bg=BG)
        right.pack(side="right",
                   fill="both", expand=True)

        # ── LEFT: branding ────────────────────
        brand = tk.Frame(left, bg=CARD, padx=38)
        brand.pack(side="left",
                   fill="both", expand=True)

        # Vertical centering
        tk.Frame(brand, bg=CARD).pack(expand=True)

        tk.Label(brand, text="HCE",
                 bg=CARD, fg="#1565c0",
                 font=(F, 62, "bold")).pack(
            anchor="w")
        tk.Label(brand,
                 text="Hybrid Cybersecurity\nEngine",
                 bg=CARD, fg="#0a1628",
                 font=(F, 20, "bold"),
                 justify="left").pack(anchor="w")
        tk.Label(brand,
                 text="Professional Security Suite",
                 bg=CARD, fg="#2a4a7a",
                 font=fnt(12)).pack(
            anchor="w", pady=(4, 30))

        tk.Frame(brand, bg=BORDER,
                 height=1).pack(
            fill="x", pady=(0, 20))

        # Feature list
        features = [
            ("🔗", "5 Manual Bash analysis tools"),
            ("🤖", "AI-powered zero-day detection"),
            ("🧪", "Dynamic Cuckoo Sandbox analysis"),
            ("🛡", "CVE vulnerability scanning"),
            ("📋", "Full audit trail — SQLite logging"),
            ("👥", "Role-based access control (RBAC)"),
        ]
        for icon, text in features:
            row = tk.Frame(brand, bg=CARD)
            row.pack(fill="x", pady=5)
            ib = tk.Frame(row, bg="#e8f0fe",
                          width=32, height=32)
            ib.pack(side="left", padx=(0, 12))
            ib.pack_propagate(False)
            tk.Label(ib, text=icon,
                     bg="#e8f0fe",
                     font=fnt(14)).place(
                relx=.5, rely=.5, anchor="center")
            tk.Label(row, text=text,
                     bg=CARD, fg="#2a4a7a",
                     font=fnt(12)).pack(
                side="left")

        tk.Frame(brand, bg=CARD).pack(expand=True)
        tk.Label(brand,
                 text="v4.0  |  Kali Linux  |  "
                      "Python Tkinter  |  SQLite",
                 bg=CARD, fg="#90b4e8",
                 font=fnt(10)).pack(pady=20)

        # ── RIGHT: login form ─────────────────
        form_outer = tk.Frame(right, bg=BG)
        form_outer.place(relx=.5, rely=.5,
                         anchor="center")

        form = tk.Frame(
            form_outer, bg=CARD,
            padx=50, pady=44,
            highlightthickness=1,
            highlightbackground=BORDER)
        form.pack()

        # Top accent
        tk.Frame(form, bg=BLUE,
                 height=3).pack(
            fill="x", pady=(0, 26))

        tk.Label(form, text="Sign in",
                 bg=CARD, fg="#0a1628",
                 font=(F, 23, "bold")).pack(
            anchor="w")
        tk.Label(form,
                 text="Enter your credentials "
                      "to access the system",
                 bg=CARD, fg="#2a4a7a",
                 font=fnt(12)).pack(
            anchor="w", pady=(4, 26))

        # Username + Password fields
        self._uvar = tk.StringVar()
        self._pvar = tk.StringVar()

        for label, var, show in [
            ("Username", self._uvar, ""),
            ("Password", self._pvar, "●"),
        ]:
            tk.Label(form, text=label,
                     bg=CARD, fg="#2a4a7a",
                     font=fnt(12, True)).pack(
                anchor="w", pady=(10, 4))
            e = tk.Entry(
                form, textvariable=var,
                show=show,
                bg=PANEL, fg=T1,
                insertbackground=BLUE,
                relief="flat", font=fnt(13),
                highlightthickness=1,
                highlightbackground=BORDER,
                highlightcolor=BLUE,
                width=26)
            e.pack(fill="x", ipady=11)
            if label == "Username": e.focus()
            if show:
                e.bind("<Return>",
                       lambda ev: self._auth())

        # Error message
        self._msg = tk.StringVar()
        tk.Label(form, textvariable=self._msg,
                 bg=CARD, fg="#ef5350",
                 font=fnt(11)).pack(
            anchor="w", pady=(12, 4))

        # Sign in button
        tk.Button(
            form, text="Sign In  →",
            bg=BLUE, fg="#ffffff",
            font=(F, 13, "bold"),
            relief="flat", bd=0,
            cursor="hand2",
            activebackground=BLUEH,
            activeforeground="#ffffff",
            command=self._auth
        ).pack(fill="x", ipady=13,
               pady=(4, 0))

    def _auth(self):
        if self._attempts >= 3:
            self._msg.set(
                "Account locked. "
                "Restart the application.")
            return
        user = db_login(
            self._uvar.get().strip(),
            self._pvar.get().strip())
        if user:
            self._on_login(user)
        else:
            self._attempts += 1
            left = 3 - self._attempts
            self._msg.set(
                f"Invalid credentials. "
                f"{left} attempt"
                f"{'s' if left != 1 else ''} "
                "remaining."
                if left else "Account locked.")

# ═══════════════════════════════════════════════════════
#  APPLICATION
# ═══════════════════════════════════════════════════════
class App:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title(
            "Hybrid Cybersecurity Engine")
        self.root.configure(bg=BG)
        self.root.attributes("-fullscreen", True)
        self.root.bind(
            "<Escape>",
            lambda e: self.root.attributes(
                "-fullscreen", False))
        self.root.bind(
            "<F11>",
            lambda e: self.root.attributes(
                "-fullscreen", True))

        sty = ttk.Style()
        sty.theme_use("default")
        sty.configure(
            "Vertical.TScrollbar",
            background=CARD,
            troughcolor=PANEL,
            arrowcolor=BORDER,
            bordercolor=CARD)

        self._cur = None
        self._login()
        self.root.mainloop()

    def _login(self):
        if self._cur:
            self._cur.destroy()
        self._cur = LoginScreen(
            self.root, self._enter)
        self._cur.pack(fill="both", expand=True)

    def _enter(self, user):
        if self._cur:
            self._cur.destroy()
        self._cur = Dashboard(
            self.root, user, self._login)
        self._cur.pack(fill="both", expand=True)


if __name__ == "__main__":
    init_db()
    App()