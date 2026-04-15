#!/usr/bin/env python3
"""
vuln_scanner.py
Hybrid Cybersecurity Engine — Vulnerability Scanner
Detects running service versions and looks them up against the NVD CVE API.
Logs results to hybrid_vas.db
"""

import os
import re
import sys
import json
import sqlite3
import subprocess
import datetime
import time
import urllib.request
import urllib.error
from pathlib import Path

try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
except ImportError:
    class _D:
        def __getattr__(self, k): return ""
    Fore = Style = _D()

DB_PATH = Path.home() / "hybrid_vas" / "database" / "hybrid_vas.db"

# NVD API — free, no key required for basic use
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

SEVERITY_COLOR = {
    "CRITICAL": Fore.RED,
    "HIGH":     Fore.RED,
    "MEDIUM":   Fore.YELLOW,
    "LOW":      Fore.GREEN,
    "NONE":     Fore.WHITE,
}

def banner():
    print(Fore.CYAN + "=" * 52)
    print("   Hybrid_VAS — Vulnerability Scanner")
    print(f"   {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 52 + Style.RESET_ALL)

# ── 1. Detect services via nmap ─────────────────────────────
def detect_services(target):
    print(Fore.YELLOW + f"\n[*] Scanning target: {target}" + Style.RESET_ALL)
    services = []
    try:
        out = subprocess.check_output(
            ["nmap", "-sV", "--open", "-T4", "-p", "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443,27017", target],
            text=True, stderr=subprocess.DEVNULL, timeout=120
        )
        # Parse nmap output: PORT STATE SERVICE VERSION
        for line in out.splitlines():
            m = re.match(r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)", line)
            if m:
                port    = int(m.group(1))
                service = m.group(2)
                version = m.group(3).strip()
                services.append({"port": port, "service": service, "version": version})
                print(Fore.CYAN + f"  [+] {port}/tcp  {service}  {version}" + Style.RESET_ALL)
    except FileNotFoundError:
        print(Fore.RED + "  [!] nmap not found. Install: sudo apt install nmap" + Style.RESET_ALL)
    except subprocess.TimeoutExpired:
        print(Fore.RED + "  [!] nmap timed out." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"  [!] nmap error: {e}" + Style.RESET_ALL)

    if not services:
        print(Fore.YELLOW + "  [!] No open services detected." + Style.RESET_ALL)
    return services

# ── 2. Query NVD CVE API ────────────────────────────────────
def query_nvd(keyword, max_results=5):
    cves = []
    params = f"?keywordSearch={urllib.request.quote(keyword)}&resultsPerPage={max_results}"
    url    = NVD_API + params
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "HybridVAS/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        for item in data.get("vulnerabilities", []):
            cve   = item.get("cve", {})
            cve_id = cve.get("id", "N/A")
            desc  = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")[:120]
                    break
            metrics = cve.get("metrics", {})
            cvss_score = 0.0
            severity   = "NONE"
            # Try CVSS v3 first, then v2
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if key in metrics and metrics[key]:
                    m_data = metrics[key][0]
                    cvss_score = m_data.get("cvssData", {}).get("baseScore", 0.0)
                    severity   = m_data.get("cvssData", {}).get("baseSeverity",
                                 m_data.get("baseSeverity", "NONE"))
                    break
            cves.append({
                "cve_id":     cve_id,
                "description": desc,
                "cvss_score":  cvss_score,
                "severity":    severity.upper(),
            })
        time.sleep(0.6)  # NVD rate limit — 5 req/30s without key
    except urllib.error.URLError:
        print(Fore.YELLOW + f"  [!] Could not reach NVD API for '{keyword}'" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.YELLOW + f"  [!] CVE lookup error: {e}" + Style.RESET_ALL)
    return cves

# ── 3. Match services to CVEs ───────────────────────────────
def find_cves(services):
    print(Fore.YELLOW + "\n[*] Looking up CVEs via NVD API..." + Style.RESET_ALL)
    all_findings = []
    for svc in services:
        keyword = svc["version"] if svc["version"] else svc["service"]
        if not keyword:
            continue
        print(Fore.CYAN + f"  [>] Querying: {keyword}" + Style.RESET_ALL)
        cves = query_nvd(keyword)
        for cve in cves:
            color = SEVERITY_COLOR.get(cve["severity"], Fore.WHITE)
            print(color + f"    {cve['cve_id']}  CVSS {cve['cvss_score']}  {cve['severity']}" + Style.RESET_ALL)
            print(Fore.WHITE + f"    {cve['description']}" + Style.RESET_ALL)
            all_findings.append({**svc, **cve})
    if not all_findings:
        print(Fore.GREEN + "  [✔] No CVEs found for detected services." + Style.RESET_ALL)
    return all_findings

# ── 4. Log to DB ─────────────────────────────────────────────
def log_to_db(target, findings):
    try:
        conn    = sqlite3.connect(str(DB_PATH))
        cur     = conn.cursor()
        ts      = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        operator = os.environ.get("USER", "unknown")

        cur.execute(
            "INSERT INTO vuln_scans (target, operator, timestamp) VALUES (?,?,?)",
            (target, operator, ts)
        )
        scan_id = cur.lastrowid

        for f in findings:
            cur.execute("""
                INSERT INTO vuln_findings
                (scan_id, cve_id, service, version, severity, cvss_score, description, timestamp)
                VALUES (?,?,?,?,?,?,?,?)
            """, (
                scan_id, f["cve_id"], f["service"], f["version"],
                f["severity"], f["cvss_score"], f.get("description", ""), ts
            ))

        conn.commit()
        conn.close()
        print(Fore.YELLOW + f"\n[+] {len(findings)} findings saved to database." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[!] DB log failed: {e}" + Style.RESET_ALL)

# ── 5. Verdict ──────────────────────────────────────────────
def show_verdict(findings):
    print(Fore.CYAN + "\n" + "=" * 52 + Style.RESET_ALL)
    critical = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")]
    if critical:
        print(Fore.RED + f"  VERDICT : {len(critical)} CRITICAL/HIGH CVEs — patch immediately" + Style.RESET_ALL)
    elif findings:
        print(Fore.YELLOW + f"  VERDICT : {len(findings)} vulnerabilities found — review needed" + Style.RESET_ALL)
    else:
        print(Fore.GREEN + "  VERDICT : CLEAN — no known CVEs detected" + Style.RESET_ALL)

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = sum(1 for f in findings if f["severity"] == sev)
        if count:
            color = SEVERITY_COLOR.get(sev, Fore.WHITE)
            print(color + f"  {sev:<10}: {count}" + Style.RESET_ALL)
    print(Fore.CYAN + "=" * 52 + Style.RESET_ALL)

# ── Main menu ───────────────────────────────────────────────
def main():
    banner()
    while True:
        print(Fore.CYAN + "\n[1] Scan a target\n[2] Exit" + Style.RESET_ALL)
        choice = input("Select: ").strip()
        if choice == "1":
            target = input("Enter target IP or hostname: ").strip()
            if not target:
                print(Fore.RED + "[!] Target cannot be empty." + Style.RESET_ALL)
                continue
            services = detect_services(target)
            if not services:
                continue
            findings = find_cves(services)
            show_verdict(findings)
            log_to_db(target, findings)
        elif choice == "2":
            break

if __name__ == "__main__":
    main()
