# Hybrid Cybersecurity Engine — Scanning Test Cases

> **Project:** HYBRID CYBERSECURITY ENGINE — PROFESSIONAL EDITION v5  
> **File under test:** `RUN9_wired.py`, `automated_tools/`, `manual_tools/`  
> **Test suite:** `tests/test_db_operations.py`  
> **Date:** 2026-04-18

---

## Table of Contents

1. [Database Initialisation Tests](#1-database-initialisation-tests)
2. [Authentication Tests](#2-authentication-tests)
3. [URL Scanner Tests](#3-url-scanner-tests)
4. [Domain Checker Tests](#4-domain-checker-tests)
5. [Port Scanner Tests](#5-port-scanner-tests)
6. [Network Scanner Tests](#6-network-scanner-tests)
7. [USB Device Scanner Tests](#7-usb-device-scanner-tests)
8. [Malware Scanner Tests](#8-malware-scanner-static-tests)
9. [AI Malware Detector Tests](#9-ai-malware-detector-tests)
10. [Backdoor Scanner Tests](#10-backdoor-scanner-tests)
11. [Vulnerability Scanner Tests](#11-vulnerability-scanner-tests)
12. [Results Viewer Query Tests](#12-results-viewer-query-tests)
13. [Clear / Data Retention Tests](#13-clear--data-retention-tests)

---

## 1. Database Initialisation Tests

**Module:** `RUN9_wired.init_db()`  
**Class:** `TestRun9InitDB`

| # | Test Case ID | Description | Input | Expected Result | Pass/Fail |
|---|---|---|---|---|---|
| 1 | TC-DB-001 | Create parent directory if missing | Nested path that does not exist | Directory and DB file created without error | |
| 2 | TC-DB-002 | Create all required tables | Fresh empty DB | Tables: `users`, `audit`, `malware_scan_logs`, `backdoor_scans`, `vuln_scans`, `vuln_findings`, `domain_logs`, `port_scans`, `usb_scans` all present | |
| 3 | TC-DB-003 | Seed default users on first run | Fresh DB | Users `admin`, `analyst1`, `viewer1` exist in `users` table | |
| 4 | TC-DB-004 | Idempotent double initialisation | Call `init_db()` twice | No crash, no duplicate user rows | |

---

## 2. Authentication Tests

**Module:** `RUN9_wired.db_login()`  
**Class:** `TestRun9Login`

| # | Test Case ID | Description | Input | Expected Result | Pass/Fail |
|---|---|---|---|---|---|
| 1 | TC-AUTH-001 | Valid admin credentials | `admin / admin123` | Returns dict `{username: "admin", role: "admin"}` | |
| 2 | TC-AUTH-002 | Valid analyst credentials | `analyst1 / analyst123` | Returns dict with `role: "analyst"` | |
| 3 | TC-AUTH-003 | Valid viewer credentials | `viewer1 / viewer123` | Returns dict with `role: "viewer"` | |
| 4 | TC-AUTH-004 | Wrong password | `admin / wrongpass` | Returns `None` | |
| 5 | TC-AUTH-005 | Non-existent user | `nobody / whatever` | Returns `None` | |
| 6 | TC-AUTH-006 | Empty credentials | `"" / ""` | Returns `None` | |

---

## 3. URL Scanner Tests

**Module:** `manual_tools/Domain-1.sh` (via `RUN9_wired` tool id `"url"`)  
**Script:** Bash — VirusTotal API + global blacklists

### 3.1 Functional Scan Steps

| Step # | Step Description |
|---|---|
| 1 | Initialising scan engine |
| 2 | Resolving DNS records |
| 3 | Connecting to VirusTotal API |
| 4 | Querying 72 security engines |
| 5 | Checking global blacklists |
| 6 | Analysing redirect chain |
| 7 | Compiling threat report |

### 3.2 Test Cases

| # | Test Case ID | Description | Input | Expected Result | Pass/Fail |
|---|---|---|---|---|---|
| 1 | TC-URL-001 | Scan a clean URL | `https://example.com` | `0 / 72 engines flagged`, verdict: **URL IS CLEAN** | |
| 2 | TC-URL-002 | Resolved IP returned | `https://example.com` | IP `93.184.216.34` shown in output | |
| 3 | TC-URL-003 | Blacklist status shown | Any URL | "Blacklists: Not listed" or specific match shown | |
| 4 | TC-URL-004 | Malicious URL detected | Known phishing URL | Positive flags from VT engines, verdict: **THREAT DETECTED** | |
| 5 | TC-URL-005 | Result saved to `scan_sessions` | Any URL scan | `scan_sessions` row created with `tool_id = "url"` | |
| 6 | TC-URL-006 | Target stored in session | `https://example.com` | `target` column = `"https://example.com"` | |

---

## 4. Domain Checker Tests

**Module:** `manual_tools/Domain_checker.sh` (tool id `"domain"`)  
**Script:** Bash — WHOIS, DNS enumeration, reputation databases

### 4.1 Functional Scan Steps

| Step # | Step Description |
|---|---|
| 1 | Initialising domain analysis |
| 2 | Running WHOIS lookup |
| 3 | Fetching DNS A records |
| 4 | Fetching MX and NS records |
| 5 | Checking domain age |
| 6 | Querying reputation databases |
| 7 | Building domain report |

### 4.2 Test Cases

| # | Test Case ID | Description | Input | Expected Result | Pass/Fail |
|---|---|---|---|---|---|
| 1 | TC-DOM-001 | Trusted domain verdict | `example.com` | Verdict: **DOMAIN TRUSTED — Clean and established** | |
| 2 | TC-DOM-002 | Domain row inserted in DB | `example.com` | `domain_logs` count = 1 | |
| 3 | TC-DOM-003 | Domain name stored | `evil.com` | `domain_logs.domain = "evil.com"` | |
| 4 | TC-DOM-004 | Clean domain risk score | Clean domain | `risk_score = 0` | |
| 5 | TC-DOM-005 | Threat domain risk score | Malicious domain | `risk_score = 90` | |
| 6 | TC-DOM-006 | IP address parsed from output | Domain with IP in output | `domain_logs.ip_address` populated | |
| 7 | TC-DOM-007 | Registrar parsed from output | WHOIS output with registrar field | `domain_logs.registrar` populated | |
| 8 | TC-DOM-008 | Multiple scans accumulate | Scan `a.com`, `b.com`, `c.com` | `domain_logs` count = 3 | |

---

## 5. Port Scanner Tests

**Module:** `manual_tools/port_scanner.sh` (tool id `"port"`)  
**Script:** Bash — SYN scan, TCP/UDP port discovery

### 5.1 Functional Scan Steps

| Step # | Step Description |
|---|---|
| 1 | Initialising port scanner |
| 2 | Sending SYN probes to target |
| 3 | Scanning common ports 1–1024 |
| 4 | Scanning extended range 1025–8080 |
| 5 | Fingerprinting detected services |
| 6 | Detecting OS signature |
| 7 | Building port map |

### 5.2 Test Cases

| # | Test Case ID | Description | Input | Expected Result | Pass/Fail |
|---|---|---|---|---|---|
| 1 | TC-PORT-001 | Port scan row inserted | `192.168.1.1` | `port_scans` count = 1 | |
| 2 | TC-PORT-002 | Target IP stored | `192.168.50.1` | `port_scans.target = "192.168.50.1"` | |
| 3 | TC-PORT-003 | Default scan type is SYN | No specific scan type in output | `port_scans.scan_type = "SYN"` | |
| 4 | TC-PORT-004 | Open ports listed | Target with open ports | Output shows `22/tcp OPEN OpenSSH`, `80/tcp OPEN Apache` etc. | |
| 5 | TC-PORT-005 | Flagged ports trigger warning | Port 8080 open | Verdict warns: **1 port flagged for security review** | |
| 6 | TC-PORT-006 | Port findings rows created | Scan with open ports in nmap format | `port_findings` rows inserted with port, protocol, state, service | |
| 7 | TC-PORT-007 | None target stored as N/A | `target=None` | `port_scans.target = "N/A"` | |
| 8 | TC-PORT-008 | UDP scan type detection | Output contains "udp scan" | `scan_type = "UDP"` | |

---

## 6. Network Scanner Tests

**Module:** `manual_tools/network_scanner.sh` (tool id `"net"`)  
**Script:** Bash — ARP broadcast sweep, host discovery

### 6.1 Functional Scan Steps

| Step # | Step Description |
|---|---|
| 1 | Initialising network scanner |
| 2 | Sending ARP broadcast sweep |
| 3 | Waiting for host responses |
| 4 | Resolving hostnames via DNS |
| 5 | Analysing TTL values |
| 6 | Mapping network topology |
| 7 | Saving network map to database |

### 6.2 Test Cases

| # | Test Case ID | Description | Input | Expected Result | Pass/Fail |
|---|---|---|---|---|---|
| 1 | TC-NET-001 | Discover live hosts on subnet | `192.168.1.0/24` | Lists all responding hosts with IP and label | |
| 2 | TC-NET-002 | Unknown device flagged | Unknown MAC/IP on subnet | Verdict warns: **1 unrecognised host — investigate** | |
| 3 | TC-NET-003 | Scan result saved to DB | Any subnet scan | `scan_sessions` row with `tool_id = "net"` created | |
| 4 | TC-NET-004 | Gateway identified | Standard network | Gateway/Router listed in output | |

---

## 7. USB Device Scanner Tests

**Module:** `manual_tools/usb_scanner.sh` (tool id `"usb"`)  
**Script:** Bash — USB enumeration, SHA256 hash verification

### 7.1 Functional Scan Steps

| Step # | Step Description |
|---|---|
| 1 | Initialising USB scanner |
| 2 | Enumerating connected USB devices |
| 3 | Reading device descriptors |
| 4 | Mounting device filesystem |
| 5 | Computing SHA256 hashes |
| 6 | Cross-referencing threat database |
| 7 | Generating device report |

### 7.2 Test Cases

| # | Test Case ID | Description | Input | Expected Result | Pass/Fail |
|---|---|---|---|---|---|
| 1 | TC-USB-001 | USB scan row inserted | No specific device | `usb_scans` count = 1 | |
| 2 | TC-USB-002 | Default device name stored | No device name in output | `usb_scans.usb_name = "USB Device"` | |
| 3 | TC-USB-003 | Device name parsed from output | Output with `Device: SanDisk Ultra` | `usb_name = "SanDisk Ultra"` | |
| 4 | TC-USB-004 | Files scanned count parsed | Output: `214 files scanned` | `files_scanned = 214` | |
| 5 | TC-USB-005 | Clean USB verdict | No hash matches | Verdict: **USB DEVICE IS CLEAN** | |
| 6 | TC-USB-006 | Threat detected on USB | File matches threat signature | Verdict: **THREAT DETECTED**, `threats_found > 0` | |
| 7 | TC-USB-007 | Per-file results stored | Mixed clean/infected files | `usb_file_results` rows with CLEAN or THREAT DETECTED per file | |
| 8 | TC-USB-008 | Hash matches reported | Signature database check | Output shows `Hash Matches: 0 / 4,821,033 signatures` | |

---

## 8. Malware Scanner (Static) Tests

**Module:** `automated_tools/malware_scan/scripts/malware_scan_engine.py` (tool id `"malware"`)  
**Engine:** Python — MD5/SHA256 hash-based, 4.8M signatures

### 8.1 Functional Scan Steps

| Step # | Step Description |
|---|---|
| 1 | Initialising malware engine |
| 2 | Loading 4,821,033 signatures |
| 3 | Indexing target directory |
| 4 | Computing MD5 / SHA256 hashes |
| 5 | Cross-referencing signature database |
| 6 | Analysing PE headers |
| 7 | Measuring file entropy scores |
| 8 | Finalising threat verdict |

### 8.2 DB Save Tests — `db_save_result(tid="malware")`

| # | Test Case ID | Description | Input | Expected Result | Pass/Fail |
|---|---|---|---|---|---|
| 1 | TC-MAL-001 | Scan row inserted | `target=/tmp/bad.exe`, threat=True | `malware_scan_logs` count = 1 | |
| 2 | TC-MAL-002 | File name extracted and stored | `target=/tmp/evil.exe` | `file_name = "evil.exe"` | |
| 3 | TC-MAL-003 | File path stored | `target=/tmp/evil.exe` | `file_path = "/tmp/evil.exe"` | |
| 4 | TC-MAL-004 | Scan method is static | Any static scan | `scan_method = "static"` | |
| 5 | TC-MAL-005 | Operator stored | User `test_op` | `operator = "test_op"` | |
| 6 | TC-MAL-006 | SHA256 computed for real file | Existing file path | `sha256` column populated with 64-char hex string | |
| 7 | TC-MAL-007 | Confidence parsed from output | Output with `confidence: 92%` | `confidence ≈ 0.92` | |
| 8 | TC-MAL-008 | Malware family parsed | Output containing `trojan` | `malware_family = "Trojan"` | |

### 8.3 `malware_scan_engine.log_to_main_db()` Tests

**Class:** `TestMalwareScanEngineDB`

| # | Test Case ID | Description | Input | Expected Result | Pass/Fail |
|---|---|---|---|---|---|
| 1 | TC-MSE-001 | Malicious file stored | `bad.exe`, result=`malicious`, confidence=92.5 | `malware_scan_logs` count = 1 | |
| 2 | TC-MSE-002 | File name stored | `evil.bin` | `file_name = "evil.bin"` | |
| 3 | TC-MSE-003 | File path stored | `/home/user/f.exe` | `file_path = "/home/user/f.exe"` | |
| 4 | TC-MSE-004 | Result field stored | `result = "malicious"` | `malware_scan_logs.result = "malicious"` | |
| 5 | TC-MSE-005 | Malware family stored | `Ransomware.WannaCry` | `malware_family = "Ransomware.WannaCry"` | |
| 6 | TC-MSE-006 | Confidence stored as float | `confidence = 87.3` | `confidence ≈ 87.3 (float type)` | |
| 7 | TC-MSE-007 | Benign file stored | `result = "benign"`, confidence=98.1 | `malware_scan_logs.result = "benign"` | |
| 8 | TC-MSE-008 | Multiple files accumulate | Scan 3 files | `malware_scan_logs` count = 3 | |
| 9 | TC-MSE-009 | Confidence stored as Python float | Integer input `75` | `confidence` column type is `float` | |

---

## 9. AI Malware Detector Tests

**Module:** `automated_tools/malware_scan/scripts/malware_scan_engine.py` (tool id `"ai"`)  
**Engine:** Python — RandomForest ML classifier, 94.7% accuracy, 256 features

### 9.1 Functional Scan Steps

| Step # | Step Description |
|---|---|
| 1 | Initialising ML pipeline |
| 2 | Loading RandomForest model weights |
| 3 | Extracting 256 feature dimensions |
| 4 | Normalising feature vectors |
| 5 | Running inference pipeline |
| 6 | Calculating confidence scores |
| 7 | Classifying threat category |

### 9.2 Test Cases

| # | Test Case ID | Description | Input | Expected Result | Pass/Fail |
|---|---|---|---|---|---|
| 1 | TC-AI-001 | AI scan row inserted | `target=/tmp/s.bin`, output with `AI VERDICT: MALICIOUS` | `malware_scan_logs` count = 1 | |
| 2 | TC-AI-002 | Scan method is AI/ML | AI tool run | `scan_method = "AI/ML"` | |
| 3 | TC-AI-003 | Default confidence is 0.947 | No confidence in output | `confidence ≈ 0.947` | |
| 4 | TC-AI-004 | Threat category classified | Malicious sample | Output shows `Category: TROJAN / Dropper` | |
| 5 | TC-AI-005 | Verdict: malicious | Malicious binary | `AI VERDICT: FILE IS MALICIOUS` | |
| 6 | TC-AI-006 | Confidence parsed from output | Output: `confidence: 88%` | `confidence ≈ 0.88` | |

---

## 10. Backdoor Scanner Tests

**Module:** `automated_tools/backdoor_scanner.py` (tool id `"backdoor"`)  
**Engine:** Python — process inspection, network connections, cron/startup persistence

### 10.1 Functional Scan Steps

| Step # | Step Description |
|---|---|
| 1 | Initialising backdoor scanner |
| 2 | Enumerating all running processes |
| 3 | Analysing outbound network connections |
| 4 | Scanning startup registry entries |
| 5 | Reviewing scheduled tasks |
| 6 | Auditing cron jobs |
| 7 | Compiling threat verdict |

### 10.2 `db_save_result(tid="backdoor")` Tests

| # | Test Case ID | Description | Input | Expected Result | Pass/Fail |
|---|---|---|---|---|---|
| 1 | TC-BD-001 | Backdoor scan row inserted | Output with reverse shell detected | `backdoor_scans` count = 1 | |
| 2 | TC-BD-002 | Scan type is full-system | Any backdoor scan | `scan_type = "full-system"` | |
| 3 | TC-BD-003 | Risk score 90 on threat | `threat = True` | `risk_score = 90` | |
| 4 | TC-BD-004 | Risk score 0 on clean | `threat = False` | `risk_score = 0` | |

### 10.3 `backdoor_scanner.log_to_db()` Tests

**Class:** `TestBackdoorScannerDB`

| # | Test Case ID | Description | Input | Expected Result | Pass/Fail |
|---|---|---|---|---|---|
| 1 | TC-BD-005 | Threat scan stored | PID 1234, `nc -lvp 4444`, port 4444 | `verdict = "BACKDOOR DETECTED"`, `risk_score = 70` | |
| 2 | TC-BD-006 | Clean scan stored | No processes/connections | `verdict = "CLEAN — NO BACKDOOR FOUND"`, `risk_score = 0` | |
| 3 | TC-BD-007 | Suspicious PID serialised | PID 999, `socat` command | `suspicious_pids` contains `"999"` | |
| 4 | TC-BD-008 | Cron findings serialised | Cron file with `wget` keyword | `cron_findings` contains `"wget"` | |
| 5 | TC-BD-009 | Multiple scans accumulate | 3 scans with different risk levels | `backdoor_scans` count = 3 | |
| 6 | TC-BD-010 | Active reverse shell detected | `python3 → 45.33.32.156:4444` | Verdict: **ACTIVE REVERSE SHELL DETECTED** | |
| 7 | TC-BD-011 | Non-standard port flagged | Connection on port 4444 | Output warns: **C2 pattern** | |

---

## 11. Vulnerability Scanner Tests

**Module:** `automated_tools/vuln_scanner.py` (tool id `"vuln"`)  
**Engine:** Python — CVE database, CVSS severity scoring

### 11.1 Functional Scan Steps

| Step # | Step Description |
|---|---|
| 1 | Initialising vulnerability scanner |
| 2 | Enumerating target services |
| 3 | Detecting software versions |
| 4 | Fetching NVD CVE database |
| 5 | Matching version fingerprints |
| 6 | Calculating CVSS severity scores |
| 7 | Generating vulnerability report |

### 11.2 `db_save_result(tid="vuln")` Tests

| # | Test Case ID | Description | Input | Expected Result | Pass/Fail |
|---|---|---|---|---|---|
| 1 | TC-VUL-001 | Vuln scan row inserted | `target=192.168.1.10`, threat=True | `vuln_scans` count = 1 | |
| 2 | TC-VUL-002 | Finding row inserted | Same | `vuln_findings` count = 1 | |
| 3 | TC-VUL-003 | Target stored in scan | `target=10.0.0.5` | `vuln_scans.target = "10.0.0.5"` | |
| 4 | TC-VUL-004 | CVE ID stored | `threat=True` (default CVE-2021-41773) | `vuln_findings.cve_id = "CVE-2021-41773"` | |
| 5 | TC-VUL-005 | Severity CRITICAL on threat | `threat=True` | `vuln_findings.severity = "CRITICAL"` | |
| 6 | TC-VUL-006 | Scan and finding linked by ID | One scan + one finding | `vuln_scans.id == vuln_findings.scan_id` | |

### 11.3 `vuln_scanner.log_to_db()` Tests

**Class:** `TestVulnScannerDB`

| # | Test Case ID | Description | Input | Expected Result | Pass/Fail |
|---|---|---|---|---|---|
| 1 | TC-VDB-001 | Scan row created | `target=192.168.1.10` + 1 finding | `vuln_scans` count = 1 | |
| 2 | TC-VDB-002 | Finding row created | 1 CVE finding | `vuln_findings` count = 1 | |
| 3 | TC-VDB-003 | Target stored | `target=10.0.0.55` | `vuln_scans.target = "10.0.0.55"` | |
| 4 | TC-VDB-004 | CVE ID stored | `cve_id="CVE-2016-0800"` | `vuln_findings.cve_id = "CVE-2016-0800"` | |
| 5 | TC-VDB-005 | Severity stored | `severity="HIGH"` | `vuln_findings.severity = "HIGH"` | |
| 6 | TC-VDB-006 | CVSS score stored | `cvss=7.5` | `cvss_score ≈ 7.5` | |
| 7 | TC-VDB-007 | Empty findings creates scan only | `findings=[]` | `vuln_scans=1`, `vuln_findings=0` | |
| 8 | TC-VDB-008 | Scan ID links finding to scan | 1 scan + 1 finding | `vuln_scans.id == vuln_findings.scan_id` | |
| 9 | TC-VDB-009 | Multiple findings all stored | 3 CVEs (CRITICAL, HIGH, MEDIUM) | `vuln_findings` count = 3 | |
| 10 | TC-VDB-010 | Critical CVE shown | Apache 2.4.49, OpenSSL 1.0.2 | `CVE-2021-41773 CVSS 9.8 CRITICAL` in output | |

---

## 12. Results Viewer Query Tests

**Class:** `TestLoadAllQueries`  
Verifies that all six `_load_all` SQL queries execute without error and return data.

| # | Test Case ID | Description | Expected Result | Pass/Fail |
|---|---|---|---|---|
| 1 | TC-VIEW-001 | No SQL errors in any query | All 6 queries succeed | Zero errors returned | |
| 2 | TC-VIEW-002 | Malware Scanner results appear | After seeding malware scan | "Malware Scanner" in result set | |
| 3 | TC-VIEW-003 | Backdoor Scanner results appear | After seeding backdoor scan | "Backdoor Scanner" in result set | |
| 4 | TC-VIEW-004 | Domain Checker results appear | After seeding domain scan | "Domain Checker" in result set | |
| 5 | TC-VIEW-005 | Port Scanner results appear | After seeding port scan | "Port Scanner" in result set | |
| 6 | TC-VIEW-006 | USB Scanner results appear | After seeding USB scan | "USB Scanner" in result set | |
| 7 | TC-VIEW-007 | Vulnerability Scanner appears in All Scans | After seeding vuln scan | "Vulnerability Scanner" in result set | |
| 8 | TC-VIEW-008 | All six tools represented | All tools seeded | Result set names == `{Malware, Backdoor, Domain, Port, USB, Vulnerability}` | |

### Queries Validated

```sql
-- Malware Scanner
SELECT id, file_name, result, confidence, timestamp
FROM malware_scan_logs ORDER BY id DESC LIMIT 20

-- Backdoor Scanner
SELECT id, scan_type, verdict, risk_score, timestamp
FROM backdoor_scans ORDER BY id DESC LIMIT 20

-- Domain Checker
SELECT id, domain, result, risk_score, timestamp
FROM domain_logs ORDER BY id DESC LIMIT 20

-- Port Scanner
SELECT id, target, result, risk_score, timestamp
FROM port_scans ORDER BY id DESC LIMIT 20

-- USB Scanner
SELECT id, usb_name, result, '0', timestamp
FROM usb_scans ORDER BY id DESC LIMIT 20

-- Vulnerability Scanner
SELECT id, cve_id, description, cvss_score, timestamp
FROM vuln_findings ORDER BY id DESC LIMIT 20
```

---

## 13. Clear / Data Retention Tests

**Class:** `TestClearLogic`  
Verifies that clearing results wipes scan data but preserves users and audit logs.

| # | Test Case ID | Description | Expected Result | Pass/Fail |
|---|---|---|---|---|
| 1 | TC-CLR-001 | All scan tables empty after clear | `malware_scan_logs`, `backdoor_scans`, `vuln_findings`, `vuln_scans`, `domain_logs`, `port_scans`, `usb_scans` all = 0 rows | |
| 2 | TC-CLR-002 | `vuln_scans` cleared (not just `vuln_findings`) | `vuln_scans` count = 0 | |
| 3 | TC-CLR-003 | `users` table preserved after clear | User count before == user count after | |
| 4 | TC-CLR-004 | `audit` log preserved after clear | Audit count before == audit count after | |

---

## Summary — Test Case Counts

| Module / Area | Test Cases |
|---|---|
| Database Initialisation | 4 |
| Authentication | 6 |
| URL Scanner | 6 |
| Domain Checker | 8 |
| Port Scanner | 8 |
| Network Scanner | 4 |
| USB Device Scanner | 8 |
| Malware Scanner (Static) | 8 + 9 = 17 |
| AI Malware Detector | 6 |
| Backdoor Scanner | 4 + 7 = 11 |
| Vulnerability Scanner | 6 + 10 = 16 |
| Results Viewer Queries | 8 |
| Clear / Data Retention | 4 |
| **TOTAL** | **106** |

---

## How to Run the Test Suite

```bash
# From the project root
python -m pytest tests/test_db_operations.py -v

# Or directly
python tests/test_db_operations.py
```

> **Note:** Tests run headless — `tkinter` is mocked automatically. No display required.
