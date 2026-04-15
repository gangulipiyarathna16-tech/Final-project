#!/usr/bin/env python3
"""
backdoor_scanner.py
Hybrid Cybersecurity Engine — Backdoor Scanner
Detects: reverse shells, RATs, suspicious outbound connections,
         malicious cron jobs, and persistence startup entries.
Logs results to hybrid_vas.db
"""

import os
import re
import sys
import sqlite3
import subprocess
import datetime
from pathlib import Path

try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
except ImportError:
    class _D:
        def __getattr__(self, k): return ""
    Fore = Style = _D()

DB_PATH  = Path.home() / "hybrid_vas" / "database" / "hybrid_vas.db"
LOG_DIR  = Path.home() / "hybrid_vas" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

# ── Known bad C2 ports ──────────────────────────────────────
C2_PORTS = {4444, 4445, 1337, 31337, 8888, 9999, 6666, 5555, 12345, 3333}
SUSPICIOUS_PROCESSES = {"netcat", "nc", "ncat", "socat", "msfconsole", "meterpreter"}

def banner():
    print(Fore.CYAN + "=" * 48)
    print("   Hybrid_VAS — Backdoor Scanner")
    print(f"   {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 48 + Style.RESET_ALL)

# ── 1. Suspicious running processes ────────────────────────
def scan_processes():
    print(Fore.YELLOW + "\n[*] Scanning running processes..." + Style.RESET_ALL)
    findings = []
    try:
        out = subprocess.check_output(
            ["ps", "aux"], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines()[1:]:
            lower = line.lower()
            for bad in SUSPICIOUS_PROCESSES:
                if re.search(rf"\b{re.escape(bad)}\b", lower):
                    pid = line.split()[1]
                    cmd = " ".join(line.split()[10:])[:80]
                    findings.append({"pid": pid, "cmd": cmd, "reason": f"suspicious process: {bad}"})
                    print(Fore.RED + f"  [!] PID {pid}: {cmd}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"  [ERROR] {e}" + Style.RESET_ALL)

    if not findings:
        print(Fore.GREEN + "  [✔] No suspicious processes found." + Style.RESET_ALL)
    return findings

# ── 2. Outbound network connections ────────────────────────
def scan_connections():
    print(Fore.YELLOW + "\n[*] Scanning outbound network connections..." + Style.RESET_ALL)
    findings = []
    try:
        out = subprocess.check_output(
            ["ss", "-tnp"], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            state   = parts[0]
            foreign = parts[4] if len(parts) > 4 else ""
            try:
                port = int(foreign.rsplit(":", 1)[-1])
            except ValueError:
                continue
            pid_info = parts[-1] if "pid=" in parts[-1] else ""
            if port in C2_PORTS or (state == "ESTAB" and port > 1024 and port not in {8080, 443, 80, 8443}):
                findings.append({"port": port, "state": state, "foreign": foreign, "pid": pid_info})
                color = Fore.RED if port in C2_PORTS else Fore.YELLOW
                print(color + f"  [!] {state} → {foreign}  {pid_info}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"  [ERROR] {e}" + Style.RESET_ALL)

    if not findings:
        print(Fore.GREEN + "  [✔] No suspicious connections found." + Style.RESET_ALL)
    return findings

# ── 3. Cron job audit ───────────────────────────────────────
def scan_cron():
    print(Fore.YELLOW + "\n[*] Auditing cron jobs..." + Style.RESET_ALL)
    findings = []
    cron_paths = [
        "/etc/crontab",
        "/etc/cron.d",
        "/var/spool/cron/crontabs",
    ]
    suspicious_keywords = ["wget", "curl", "bash -i", "/dev/tcp", "python3 -c", "nc -e", "chmod +x"]

    for path in cron_paths:
        p = Path(path)
        if not p.exists():
            continue
        files = list(p.rglob("*")) if p.is_dir() else [p]
        for f in files:
            if not f.is_file():
                continue
            try:
                content = f.read_text(errors="ignore")
            except PermissionError:
                continue
            for keyword in suspicious_keywords:
                if keyword in content:
                    findings.append({"file": str(f), "keyword": keyword})
                    print(Fore.RED + f"  [!] {f}: contains '{keyword}'" + Style.RESET_ALL)

    if not findings:
        print(Fore.GREEN + "  [✔] No suspicious cron entries found." + Style.RESET_ALL)
    return findings

# ── 4. Startup / persistence entries ───────────────────────
def scan_startup():
    print(Fore.YELLOW + "\n[*] Checking startup persistence entries..." + Style.RESET_ALL)
    findings = []
    startup_paths = [
        Path.home() / ".bashrc",
        Path.home() / ".bash_profile",
        Path.home() / ".profile",
        Path("/etc/rc.local"),
        Path("/etc/init.d"),
        Path("/etc/systemd/system"),
    ]
    suspicious_keywords = ["wget", "curl", "/dev/tcp", "bash -i", "python3 -c", "nohup", "nc -e"]

    for path in startup_paths:
        if not path.exists():
            continue
        files = list(path.rglob("*.service")) if path.is_dir() else [path]
        for f in files:
            if not f.is_file():
                continue
            try:
                content = f.read_text(errors="ignore")
            except PermissionError:
                continue
            for keyword in suspicious_keywords:
                if keyword in content:
                    findings.append({"file": str(f), "keyword": keyword})
                    print(Fore.RED + f"  [!] {f}: contains '{keyword}'" + Style.RESET_ALL)

    if not findings:
        print(Fore.GREEN + "  [✔] No suspicious startup entries found." + Style.RESET_ALL)
    return findings

# ── 5. Risk scoring ─────────────────────────────────────────
def compute_risk(procs, conns, cron, startup):
    score = 0
    score += len(procs)  * 30
    score += len([c for c in conns if c["port"] in C2_PORTS]) * 40
    score += len([c for c in conns if c["port"] not in C2_PORTS]) * 10
    score += len(cron)   * 20
    score += len(startup) * 15
    return min(score, 100)

# ── 6. DB logging ───────────────────────────────────────────
def log_to_db(procs, conns, cron, startup, verdict, risk):
    try:
        conn = sqlite3.connect(str(DB_PATH))
        conn.execute("""
            INSERT INTO backdoor_scans
            (scan_type, suspicious_pids, suspicious_ports, cron_findings,
             startup_findings, verdict, risk_score, operator, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            "full",
            str([p["pid"] for p in procs]),
            str([c["port"] for c in conns]),
            str([c["keyword"] for c in cron]),
            str([s["keyword"] for s in startup]),
            verdict,
            risk,
            os.environ.get("USER", "unknown"),
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ))
        conn.commit()
        conn.close()
        print(Fore.YELLOW + "\n[+] Results saved to database." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[!] DB log failed: {e}" + Style.RESET_ALL)

# ── 7. Verdict display ──────────────────────────────────────
def show_verdict(risk, procs, conns, cron, startup):
    print(Fore.CYAN + "\n" + "=" * 48 + Style.RESET_ALL)
    total = len(procs) + len(conns) + len(cron) + len(startup)

    if risk >= 70 or any(c["port"] in C2_PORTS for c in conns):
        verdict = "BACKDOOR DETECTED"
        color   = Fore.RED
    elif risk >= 30 or total > 0:
        verdict = "SUSPICIOUS — REVIEW REQUIRED"
        color   = Fore.YELLOW
    else:
        verdict = "CLEAN — NO BACKDOOR FOUND"
        color   = Fore.GREEN

    print(color + f"  VERDICT : {verdict}" + Style.RESET_ALL)

    filled = risk // 5
    bar    = "█" * filled + "░" * (20 - filled)
    bcolor = Fore.GREEN if risk < 30 else Fore.YELLOW if risk < 70 else Fore.RED
    print(bcolor + f"  Risk    : [{bar}] {risk}/100" + Style.RESET_ALL)
    print(f"  Processes flagged  : {len(procs)}")
    print(f"  Connections flagged: {len(conns)}")
    print(f"  Cron findings      : {len(cron)}")
    print(f"  Startup findings   : {len(startup)}")
    print(Fore.CYAN + "=" * 48 + Style.RESET_ALL)
    return verdict

# ── Main ────────────────────────────────────────────────────
def main():
    banner()
    procs   = scan_processes()
    conns   = scan_connections()
    cron    = scan_cron()
    startup = scan_startup()
    risk    = compute_risk(procs, conns, cron, startup)
    verdict = show_verdict(risk, procs, conns, cron, startup)
    log_to_db(procs, conns, cron, startup, verdict, risk)

if __name__ == "__main__":
    main()
