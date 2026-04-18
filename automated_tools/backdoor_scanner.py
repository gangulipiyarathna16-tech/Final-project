#!/usr/bin/env python3
"""
backdoor_scanner.py
Hybrid Cybersecurity Engine — Backdoor Scanner (Cross-Platform)
Detects: reverse shells, RATs, suspicious outbound connections,
         malicious cron/scheduled jobs, persistence startup entries.

Status labels per scan section:
  No Findings    — scan ran, nothing found
  Not Supported  — OS doesn't provide this scan type
  Scan Failed    — command error or access denied
"""

import os
import re
import sys
import sqlite3
import subprocess
import datetime
from pathlib import Path

IS_WINDOWS = sys.platform.startswith("win")
IS_LINUX   = sys.platform.startswith("linux")

try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
except ImportError:
    class _D:
        def __getattr__(self, k): return ""
    Fore = Style = _D()

DB_PATH = Path(__file__).resolve().parent.parent / "database" / "hybrid_vas.db"
LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

C2_PORTS           = {4444, 4445, 1337, 31337, 8888, 9999, 6666, 5555, 12345, 3333}
SUSPICIOUS_PROCS   = {"netcat", "nc", "ncat", "socat", "msfconsole", "meterpreter",
                      "mimikatz", "cobalt", "empire", "metasploit"}
SUSPICIOUS_KEYWORDS = ["wget ", "curl ", "bash -i", "/dev/tcp", "python3 -c",
                       "nc -e", "chmod +x", "powershell -enc", "cmd /c", "certutil"]

STATUS_OK      = "ok"
STATUS_SKIP    = "not_supported"
STATUS_FAILED  = "failed"

def banner():
    print(Fore.CYAN + "=" * 52)
    print("   Hybrid_VAS — Backdoor Scanner")
    print(f"   Platform : {'Windows' if IS_WINDOWS else 'Linux/Unix'}")
    print(f"   {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 52 + Style.RESET_ALL)

def _label(status, findings):
    """Return a display label based on scan status and findings list."""
    if status == STATUS_SKIP:
        return "Not Supported"
    if status == STATUS_FAILED:
        return "Scan Failed"
    return f"{len(findings)} finding(s)" if findings else "No Findings"

# ── 1. Running processes ────────────────────────────────────
def scan_processes():
    print(Fore.YELLOW + "\n[*] Scanning running processes..." + Style.RESET_ALL)
    findings = []
    status   = STATUS_OK
    try:
        if IS_WINDOWS:
            out = subprocess.check_output(
                ["tasklist", "/FO", "CSV", "/NH"],
                text=True, stderr=subprocess.DEVNULL, timeout=30)
            for line in out.splitlines():
                parts = [p.strip('"') for p in line.split('","')]
                if not parts:
                    continue
                name = parts[0].lower()
                pid  = parts[1] if len(parts) > 1 else "?"
                for bad in SUSPICIOUS_PROCS:
                    if bad in name:
                        findings.append({"pid": pid, "cmd": parts[0], "reason": f"suspicious process: {bad}"})
                        print(Fore.RED + f"  [!] PID {pid}: {parts[0]}" + Style.RESET_ALL)
        else:
            out = subprocess.check_output(
                ["ps", "aux"], text=True, stderr=subprocess.DEVNULL, timeout=30)
            for line in out.splitlines()[1:]:
                lower = line.lower()
                for bad in SUSPICIOUS_PROCS:
                    if re.search(rf"\b{re.escape(bad)}\b", lower):
                        parts = line.split()
                        pid   = parts[1]
                        cmd   = " ".join(parts[10:])[:80]
                        findings.append({"pid": pid, "cmd": cmd, "reason": f"suspicious process: {bad}"})
                        print(Fore.RED + f"  [!] PID {pid}: {cmd}" + Style.RESET_ALL)
    except FileNotFoundError:
        status = STATUS_FAILED
        print(Fore.RED + "  [!] Process lister not found." + Style.RESET_ALL)
    except subprocess.TimeoutExpired:
        status = STATUS_FAILED
        print(Fore.RED + "  [!] Process scan timed out." + Style.RESET_ALL)
    except Exception as e:
        status = STATUS_FAILED
        print(Fore.RED + f"  [ERROR] {e}" + Style.RESET_ALL)

    print(Fore.GREEN + f"  [✔] Processes: {_label(status, findings)}" + Style.RESET_ALL
          if not findings else "")
    return status, findings

# ── 2. Outbound network connections ────────────────────────
def scan_connections():
    print(Fore.YELLOW + "\n[*] Scanning outbound network connections..." + Style.RESET_ALL)
    findings = []
    status   = STATUS_OK
    try:
        if IS_WINDOWS:
            out = subprocess.check_output(
                ["netstat", "-ano"], text=True, stderr=subprocess.DEVNULL, timeout=30)
            for line in out.splitlines():
                parts = line.split()
                if len(parts) < 4 or parts[0] not in ("TCP", "UDP"):
                    continue
                foreign = parts[2]
                state   = parts[3] if len(parts) > 3 else ""
                pid     = parts[4] if len(parts) > 4 else "?"
                try:
                    port = int(foreign.rsplit(":", 1)[-1])
                except ValueError:
                    continue
                if port in C2_PORTS or (state == "ESTABLISHED" and port > 1024
                                         and port not in {8080, 443, 80, 8443, 3389}):
                    findings.append({"port": port, "state": state,
                                     "foreign": foreign, "pid": f"pid={pid}"})
                    color = Fore.RED if port in C2_PORTS else Fore.YELLOW
                    print(color + f"  [!] {state} → {foreign}  pid={pid}" + Style.RESET_ALL)
        else:
            out = subprocess.check_output(
                ["ss", "-tnp"], text=True, stderr=subprocess.DEVNULL, timeout=30)
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
                if port in C2_PORTS or (state == "ESTAB" and port > 1024
                                         and port not in {8080, 443, 80, 8443}):
                    findings.append({"port": port, "state": state,
                                     "foreign": foreign, "pid": pid_info})
                    color = Fore.RED if port in C2_PORTS else Fore.YELLOW
                    print(color + f"  [!] {state} → {foreign}  {pid_info}" + Style.RESET_ALL)
    except FileNotFoundError:
        status = STATUS_FAILED
        print(Fore.RED + "  [!] Network tool not found." + Style.RESET_ALL)
    except subprocess.TimeoutExpired:
        status = STATUS_FAILED
        print(Fore.RED + "  [!] Network scan timed out." + Style.RESET_ALL)
    except Exception as e:
        status = STATUS_FAILED
        print(Fore.RED + f"  [ERROR] {e}" + Style.RESET_ALL)

    if not findings and status == STATUS_OK:
        print(Fore.GREEN + "  [✔] Connections: No Findings" + Style.RESET_ALL)
    return status, findings

# ── 3. Cron / Scheduled tasks ───────────────────────────────
def scan_scheduled_tasks():
    print(Fore.YELLOW + "\n[*] Auditing scheduled tasks / cron jobs..." + Style.RESET_ALL)
    findings = []
    status   = STATUS_OK
    try:
        if IS_WINDOWS:
            out = subprocess.check_output(
                ["schtasks", "/query", "/FO", "CSV", "/NH"],
                text=True, stderr=subprocess.DEVNULL, timeout=30)
            for line in out.splitlines():
                lower = line.lower()
                for kw in SUSPICIOUS_KEYWORDS:
                    if kw.lower() in lower:
                        findings.append({"file": "Task Scheduler", "keyword": kw,
                                         "detail": line[:120]})
                        print(Fore.RED + f"  [!] Scheduled task contains '{kw}'" + Style.RESET_ALL)
        elif IS_LINUX:
            cron_paths = ["/etc/crontab", "/etc/cron.d", "/var/spool/cron/crontabs"]
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
                    for kw in SUSPICIOUS_KEYWORDS:
                        if kw in content:
                            findings.append({"file": str(f), "keyword": kw,
                                             "detail": kw})
                            print(Fore.RED + f"  [!] {f}: contains '{kw}'" + Style.RESET_ALL)
        else:
            status = STATUS_SKIP
    except FileNotFoundError:
        status = STATUS_FAILED
        print(Fore.RED + "  [!] Task scheduler tool not found." + Style.RESET_ALL)
    except subprocess.TimeoutExpired:
        status = STATUS_FAILED
    except Exception as e:
        status = STATUS_FAILED
        print(Fore.RED + f"  [ERROR] {e}" + Style.RESET_ALL)

    if not findings and status == STATUS_OK:
        print(Fore.GREEN + "  [✔] Scheduled tasks: No Findings" + Style.RESET_ALL)
    elif status == STATUS_SKIP:
        print(Fore.YELLOW + "  [~] Cron audit: Not Supported on this OS" + Style.RESET_ALL)
    return status, findings

# ── 4. Startup / persistence entries ────────────────────────
def scan_startup():
    print(Fore.YELLOW + "\n[*] Checking startup / persistence entries..." + Style.RESET_ALL)
    findings = []
    status   = STATUS_OK
    try:
        if IS_WINDOWS:
            reg_keys = [
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            ]
            for key in reg_keys:
                try:
                    out = subprocess.check_output(
                        ["reg", "query", key],
                        text=True, stderr=subprocess.DEVNULL, timeout=10)
                    for line in out.splitlines():
                        lower = line.lower()
                        for kw in SUSPICIOUS_KEYWORDS:
                            if kw.lower() in lower:
                                findings.append({"file": key, "keyword": kw,
                                                 "detail": line[:120]})
                                print(Fore.RED + f"  [!] Registry {key}: '{kw}'" + Style.RESET_ALL)
                except Exception:
                    continue
            # Also check Windows startup folder
            startup_folder = Path(os.environ.get("APPDATA", "")) / \
                             "Microsoft/Windows/Start Menu/Programs/Startup"
            if startup_folder.exists():
                for f in startup_folder.iterdir():
                    if f.is_file():
                        findings.append({"file": str(f), "keyword": "startup file",
                                         "detail": str(f)})
                        print(Fore.YELLOW + f"  [~] Startup folder: {f.name}" + Style.RESET_ALL)

        elif IS_LINUX:
            startup_paths = [
                Path.home() / ".bashrc",
                Path.home() / ".bash_profile",
                Path.home() / ".profile",
                Path("/etc/rc.local"),
                Path("/etc/init.d"),
                Path("/etc/systemd/system"),
            ]
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
                    for kw in SUSPICIOUS_KEYWORDS:
                        if kw in content:
                            findings.append({"file": str(f), "keyword": kw,
                                             "detail": kw})
                            print(Fore.RED + f"  [!] {f}: contains '{kw}'" + Style.RESET_ALL)
        else:
            status = STATUS_SKIP
    except Exception as e:
        status = STATUS_FAILED
        print(Fore.RED + f"  [ERROR] {e}" + Style.RESET_ALL)

    if not findings and status == STATUS_OK:
        print(Fore.GREEN + "  [✔] Startup entries: No Findings" + Style.RESET_ALL)
    elif status == STATUS_SKIP:
        print(Fore.YELLOW + "  [~] Startup audit: Not Supported on this OS" + Style.RESET_ALL)
    return status, findings

# ── 5. Risk scoring ──────────────────────────────────────────
def compute_risk(procs, conns, cron, startup):
    score = 0
    score += len(procs)  * 30
    score += len([c for c in conns if c["port"] in C2_PORTS]) * 40
    score += len([c for c in conns if c["port"] not in C2_PORTS]) * 10
    score += len(cron)   * 20
    score += len(startup) * 15
    return min(score, 100)

# ── 6. Verdict: CLEAN / PARTIAL / SUSPICIOUS ─────────────────
def compute_verdict(risk, results):
    """
    results: dict of {section: (status, findings)}
    SUSPICIOUS — threat indicators found
    PARTIAL    — no threats, but some scans were unavailable
    CLEAN      — all scans ran, nothing found
    """
    has_findings = risk > 0 or any(len(f) > 0 for _, f in results.values())
    has_skip     = any(s == STATUS_SKIP   for s, _ in results.values())
    has_failed   = any(s == STATUS_FAILED for s, _ in results.values())

    if has_findings:
        return "SUSPICIOUS"
    if has_skip or has_failed:
        return "PARTIAL"
    return "CLEAN"

# ── 7. DB logging ────────────────────────────────────────────
def log_to_db(results, verdict, risk):
    """results: dict of section → (status, findings)"""
    def _fmt(section):
        status, findings = results.get(section, (STATUS_SKIP, []))
        if status == STATUS_SKIP:   return "Not Supported"
        if status == STATUS_FAILED: return "Scan Failed"
        if not findings:            return "No Findings"
        return ", ".join(
            str(f.get("pid", f.get("port", f.get("keyword", "?"))))
            for f in findings
        )[:200]

    try:
        conn = sqlite3.connect(str(DB_PATH))
        conn.execute("""
            INSERT INTO backdoor_scans
            (scan_type, suspicious_pids, suspicious_ports, cron_findings,
             startup_findings, verdict, risk_score, operator, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            "full",
            _fmt("processes"),
            _fmt("connections"),
            _fmt("cron"),
            _fmt("startup"),
            verdict,
            risk,
            os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ))
        conn.commit()
        conn.close()
        print(Fore.YELLOW + "\n[+] Results saved to database." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[!] DB log failed: {e}" + Style.RESET_ALL)

# ── 8. Verdict display ───────────────────────────────────────
def show_verdict(verdict, risk, results):
    print(Fore.CYAN + "\n" + "=" * 52 + Style.RESET_ALL)

    if verdict == "SUSPICIOUS":
        color = Fore.RED
        label = "SUSPICIOUS — Potential backdoor indicators found"
    elif verdict == "PARTIAL":
        color = Fore.YELLOW
        label = "PARTIAL — Some scans unavailable on this OS"
    else:
        color = Fore.GREEN
        label = "CLEAN — No backdoor found (all scans completed)"

    print(color + f"  VERDICT : {label}" + Style.RESET_ALL)

    filled = risk // 5
    bar    = "█" * filled + "░" * (20 - filled)
    bcolor = Fore.GREEN if risk < 30 else Fore.YELLOW if risk < 70 else Fore.RED
    print(bcolor + f"  Risk    : [{bar}] {risk}/100" + Style.RESET_ALL)

    for section, (status, findings) in results.items():
        icon  = "✔" if status == STATUS_OK and not findings else \
                "!" if findings else \
                "~" if status == STATUS_SKIP else "✗"
        clr   = Fore.GREEN if icon == "✔" else \
                Fore.RED   if icon == "!" else \
                Fore.YELLOW
        label_str = _label(status, findings)
        print(clr + f"  [{icon}] {section:<22}: {label_str}" + Style.RESET_ALL)

    print(Fore.CYAN + "=" * 52 + Style.RESET_ALL)
    return verdict

# ── Main ──────────────────────────────────────────────────────
def main():
    banner()

    proc_status,  procs   = scan_processes()
    conn_status,  conns   = scan_connections()
    cron_status,  cron    = scan_scheduled_tasks()
    start_status, startup = scan_startup()

    results = {
        "Processes":         (proc_status,  procs),
        "Connections":       (conn_status,  conns),
        "Scheduled Tasks":   (cron_status,  cron),
        "Startup Entries":   (start_status, startup),
    }

    risk    = compute_risk(procs, conns, cron, startup)
    verdict = compute_verdict(risk, results)
    show_verdict(verdict, risk, results)
    log_to_db(results, verdict, risk)

if __name__ == "__main__":
    main()
