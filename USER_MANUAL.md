# Hybrid Cybersecurity Engine — User Manual

**Version:** Professional Edition v5  
**Application:** `RUN9_wired.py`

---

## Table of Contents

1. [System Requirements](#1-system-requirements)
2. [Installation & Launch](#2-installation--launch)
3. [Login Screen](#3-login-screen)
4. [Main Dashboard](#4-main-dashboard)
5. [Manual Tools](#5-manual-tools)
6. [Automated Tools](#6-automated-tools)
7. [Live Output Panel](#7-live-output-panel)
8. [Scan Results Viewer](#8-scan-results-viewer)
9. [Admin Panel](#9-admin-panel)
10. [Role Permissions Reference](#10-role-permissions-reference)
11. [Status Indicators](#11-status-indicators)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. System Requirements

| Requirement | Details |
|---|---|
| Python | 3.10 or later |
| Tkinter | Included with Python on most systems |
| Linux | Bash tools run natively |
| Windows | WSL (Windows Subsystem for Linux) required for Bash tools; Python tools run natively |
| Tkinter on Debian/Ubuntu | `sudo apt install python3-tk -y` |

---

## 2. Installation & Launch

```bash
# Navigate to the project directory
cd Final-project

# Install Tkinter (Linux/Debian only — skip on Windows)
sudo apt install python3-tk -y

# Launch the application
python3 RUN9_wired.py
```

The SQLite database is created automatically at `database/hybrid_vas.db` on first run. Four default accounts are seeded (see [Section 3](#3-login-screen)).

---

## 3. Login Screen

The application opens with a login dialog.

### Default Accounts

| Username | Password | Role |
|---|---|---|
| `admin` | `admin123` | Admin |
| `analyst1` | `analyst123` | Analyst |
| `viewer1` | `viewer123` | Viewer |
| `guest` | `guest123` | Guest |

> **Security note:** Change all default passwords before using the system on a real network.

### Login Steps

1. Enter your **username** in the first field.
2. Enter your **password** in the second field.
3. Click **Sign In** or press `Enter`.

If credentials are incorrect or the account is disabled, an error message is shown. Every successful login is recorded in the audit log.

---

## 4. Main Dashboard

After login the main window opens with three regions:

```
┌─────────────────────────────────────────────────────────┐
│  TOP BAR  — logo | scan counter | clock | user | buttons │
├──────────────────────────┬──────────────────────────────┤
│   MANUAL TOOLS (left)    │   AUTOMATED TOOLS (right)    │
│   5 Bash-based scanners  │   5 Python/AI scanners       │
├──────────────────────────┴──────────────────────────────┤
│              SCAN RESULTS VIEWER (bottom)                │
└─────────────────────────────────────────────────────────┘
```

### Top Bar

| Element | Description |
|---|---|
| **HCE** badge | Application logo |
| **Scans** counter | Total scans run in this session |
| **Threats** counter | Scans that returned a threat verdict |
| **Live clock** | Current date and time (updates every second) |
| **Username + Role badge** | Currently signed-in user |
| **Admin Panel** button | Opens the admin panel (Admin role only) |
| **Sign Out** button | Returns to the login screen |

---

## 5. Manual Tools

The left panel contains five Bash-based tools. Each is displayed as a **tool card**.

**To run a manual tool:** Click the card. A target input dialog appears for tools that require a target.

### 5.1 URL Scanner

- **Purpose:** Checks a URL against VirusTotal (72 security engines) and global blacklists for phishing and malware indicators.
- **Input required:** Full URL (e.g. `https://example.com`)
- **Scan steps:** DNS resolution → VirusTotal API query → blacklist check → redirect chain analysis → report
- **Typical output fields:** Target URL, resolved IP, engine count flagged, blacklist status, verdict

### 5.2 Domain Checker

- **Purpose:** WHOIS lookup, DNS A/MX/NS record enumeration, and domain reputation analysis.
- **Input required:** Domain name (e.g. `example.com`)
- **Scan steps:** WHOIS lookup → DNS A records → MX/NS records → domain age → reputation databases → report
- **Typical output fields:** Domain, registrar, creation date, DNS A record, reputation verdict

### 5.3 Port Scanner

- **Purpose:** SYN scan to discover open TCP/UDP ports and fingerprint running services on a target host.
- **Input required:** Target IP address (e.g. `192.168.1.1`)
- **Scan steps:** SYN probes → ports 1–1024 → extended range 1025–8080 → service fingerprinting → OS detection → port map
- **Typical output fields:** Target host, open ports with protocol, service name, version, verdict

### 5.4 Network Scanner

- **Purpose:** ARP broadcast sweep to discover all live hosts on a subnet and map the network topology.
- **Input required:** Subnet in CIDR notation (e.g. `192.168.1.0/24`)
- **Scan steps:** ARP broadcast → host responses → hostname resolution → TTL analysis → topology map
- **Typical output fields:** Subnet, live host IPs, hostnames, device type, any unrecognised devices flagged

### 5.5 USB Device Scanner

- **Purpose:** Enumerates connected USB storage devices and verifies file hashes against known threat databases.
- **Input required:** None — runs automatically on connected devices
- **Scan steps:** USB enumeration → device descriptors → filesystem mount → SHA256 hash computation → threat database cross-reference → report
- **Typical output fields:** Device name, mount point, files scanned, hash matches, verdict

---

## 6. Automated Tools

The right panel contains five Python-based automated tools. These tools **start automatically** when the dashboard loads — no clicking required. Each tool runs in a background thread and updates its card when complete.

> Tools that need a target (Malware Scanner, AI Detector, Vulnerability Scanner) use a default placeholder path on auto-run. Click the card to run a fresh scan against a specific target.

### 6.1 Malware Scanner

- **Purpose:** Hash-based detection engine cross-referencing 4.8 million MD5/SHA256 malware signatures.
- **Input required:** File path or directory path to scan
- **Input dialog:** Includes a **Browse…** button to select a file via file picker
- **Single file vs. folder:** The scanner automatically detects whether the input is a file or directory and selects the appropriate scan mode
- **Scan steps:** Engine init → signature loading → directory indexing → MD5/SHA256 hashing → signature cross-reference → PE header analysis → entropy scoring → verdict
- **Typical output fields:** Scan path, files found, suspicious files (with entropy score), signature match, verdict

### 6.2 AI Malware Detector

- **Purpose:** RandomForest ML classifier (94.7% accuracy) for zero-day and obfuscated malware that evades signature detection.
- **Input required:** File path to analyse
- **Input dialog:** Includes a **Browse…** button
- **Scan steps:** ML pipeline init → model weight loading → 256-feature extraction → vector normalisation → inference → confidence scoring → threat classification
- **Typical output fields:** Sample name, model version, confidence percentage, threat category, verdict

### 6.3 Backdoor Scanner

- **Purpose:** Detects reverse shells, Remote Access Trojans (RATs), and persistent backdoor implants on the local system.
- **Input required:** None — scans the local system automatically
- **Scan steps:** Process enumeration → outbound connection analysis → startup registry entries → scheduled tasks → cron job audit → verdict
- **Typical output fields:** Processes reviewed, outbound connections, suspicious PIDs, suspicious ports, cron findings, startup findings, verdict

### 6.4 Vulnerability Scanner

- **Purpose:** CVE database assessment with CVSS severity scoring against detected software versions on a target host.
- **Input required:** Target IP address or hostname (e.g. `192.168.1.10`)
- **Scan steps:** Target service enumeration → version detection → NVD CVE database query → version fingerprint matching → CVSS scoring → report
- **Typical output fields:** Target, services detected, CVE IDs, severity (CRITICAL/HIGH/MEDIUM/LOW), CVSS score, description

### 6.5 Cuckoo Sandbox *(not yet installed)*

- **Purpose:** Dynamic behavioural analysis — detonates a sample inside an isolated Windows 10 VM and monitors API calls, network traffic, filesystem changes, and memory.
- **Status:** Placeholder — shows demo output until Cuckoo is installed and configured
- **Typical output fields:** Sample name, API call count, C2 connection attempts, persistence mechanisms, verdict

---

## 7. Live Output Panel

When you click and run a manual tool (or click an automated tool card), a **Live Output Panel** window opens showing the real-time subprocess output.

### Layout

```
┌─ Live Output ─────────────────────────────── ✕ Close ─┐
│ (dark terminal area — scrolling output)                │
│                                                        │
└────────────────────────────────────────────────────────┘
  ✔ Scan complete — no threats         ← status bar
```

### Output Colour Coding

| Colour | Meaning |
|---|---|
| **Red** | Error, threat detected, malicious, critical, backdoor, infected |
| **Yellow/Amber** | Warning, suspicious, unknown device, flagged, high risk |
| **Green** | Clean, scan complete, safe, trusted, OK |
| **Dim grey** | Info/progress lines, comment lines |
| **White/light** | Normal informational output |

### Controls

- **✕ Close** — closes the panel. If the scan is still running, the subprocess is terminated first.
- The panel is resizable. Output auto-scrolls as new lines arrive.
- The status bar at the bottom shows `✔ Scan complete — no threats` (exit code 0) or `⚠ Finished with exit code N` for non-zero exits.

---

## 8. Scan Results Viewer

The bottom panel shows all scan results persisted in the database. It refreshes automatically every 10 seconds.

### Tabs

| Tab | Data source | Columns shown |
|---|---|---|
| **All Scans** | `scan_sessions` | Tool, Target/File, Verdict, Risk Score, Operator, Time |
| **Malware** | `malware_scan_logs` | File, Verdict, Family, Confidence, Operator, Time |
| **Backdoor** | `backdoor_scans` | Susp. PIDs, Susp. Ports, Cron Jobs, Startup, Verdict, Risk, Operator, Time |
| **Vulnerability** | `vuln_findings` | CVE ID, Service, Version, Port, Severity, CVSS, Description, Time |
| **Domain** | `domain_logs` | Domain, IP Address, Registrar, Verdict, Risk Score, Operator, Time |
| **Port** | `port_scans` | Target, Scan Type, Verdict, Operator, Time |
| **USB** | `usb_scans` | Device, Mount Path, Files, Threats, Verdict, Operator, Time |

### Buttons

| Button | Action |
|---|---|
| **Refresh** | Reloads results from the database immediately |
| **Clear All** | Deletes all records from the scan results tables (prompts for confirmation) |

---

## 9. Admin Panel

Available to **Admin role only**. Click **Admin Panel** in the top bar to open it.

The panel has four tabs:

### 9.1 ACL Reference

Displays the **Access Control Matrix** — a table showing which permissions are granted to each role.

Permissions listed:

| Permission | Description |
|---|---|
| Run Manual Tools | Execute the Bash-based scanner tools |
| Run Automated Scans | Execute the Python/AI scanner tools |
| View Scan Results | Access the results viewer |
| Manage User Accounts | Create, enable, and disable accounts |
| View Full Audit Log | Read the system audit trail |
| Export Reports | Export scan data |
| System Configuration | Access API keys and system settings |

Also includes a summary of **Admin-only responsibilities**.

### 9.2 User Management

Displays a table of all registered users with columns: ID, Username, Role, Status, Created.

**To enable or disable a user:**

1. Click a user row to select it.
2. Click **Toggle Active / Disabled**.
3. The status updates immediately and the action is recorded in the audit log.

**Note:** You cannot disable your own account.

Click **Refresh** to reload the user list.

### 9.3 Add User

Creates a new user account. Fields required:

| Field | Notes |
|---|---|
| **Username** | Must be unique |
| **Password** | Stored as SHA-256 hash |
| **Role** | Select from: admin, analyst, viewer, guest |

Click **Create User**. The account is active immediately. A confirmation message appears on success; an error message appears if the username already exists. The creation is recorded in the audit log.

### 9.4 Audit Log

Displays the 100 most recent audit entries with columns: User, Action, Timestamp.

Recorded events include:

| Event | When |
|---|---|
| `LOGIN` | Successful authentication |
| `RUN:<tool_id>` | Each time a tool is launched |
| `ADD_USER:<username>:<role>` | New user created |
| `TOGGLE:<username>` | User account enabled or disabled |

---

## 10. Role Permissions Reference

| Action | Admin | Analyst | Viewer | Guest |
|---|:---:|:---:|:---:|:---:|
| Run Manual Tools (Bash) | ✔ | ✔ | — | — |
| Run Automated Scans (Python/AI) | ✔ | ✔ | — | — |
| View Scan Results & Reports | ✔ | ✔ | ✔ | — |
| Manage User Accounts | ✔ | — | — | — |
| View Full Audit Log | ✔ | — | — | — |
| Export Reports | ✔ | ✔ | — | — |
| System Configuration | ✔ | — | — | — |

---

## 11. Status Indicators

### Tool Card States

After a scan completes, the card border and status text change to indicate the result:

| Border colour | Status text | Meaning |
|---|---|---|
| **Blue** | `CLEAN — scan complete` | No threats detected |
| **Red** | `SUSPICIOUS — threats found` | Threat or malicious content detected |
| **Amber** | `PARTIAL — some scans unavailable` | Scan ran but some components could not complete |
| **Amber** | `Error — <message>` | Script could not be launched or returned an error |

### Progress Bar

The thin progress bar on each card animates through the scan steps (amber while running, then changes to the result colour on completion).

---

## 12. Troubleshooting

### "WSL is not installed or configured"

Bash-based tools (URL Scanner, Domain Checker, Port Scanner, Network Scanner, USB Scanner) require WSL on Windows.

**Fix:**
```powershell
# Install WSL (run in PowerShell as Administrator)
wsl --install
# Then restart the machine and try again
```

### "Script not found"

The scanner script file is missing from the expected path under `manual_tools/` or `automated_tools/`.

**Fix:** Verify the scripts exist:
- Manual tools: `manual_tools/Domain-1.sh`, `Domain_checker.sh`, `port_scanner.sh`, `network_scanner.sh`, `usb_scanner.sh`
- Automated tools: `automated_tools/backdoor_scanner.py`, `automated_tools/vuln_scanner.py`, `automated_tools/malware_scan/scripts/malware_scan_engine.py`

### Scan times out after 120 seconds

The subprocess is killed automatically after 120 seconds. This can happen if a network target is unreachable.

**Fix:** Verify the target IP/domain is reachable before scanning, or use a target on a faster network.

### Tool shows demo output instead of real scan

If the real script cannot be found or WSL is unavailable, the tool falls back to displaying the built-in demo output for that tool. The scan is still recorded in the database with the demo verdict.

### Database errors

If the database becomes locked or corrupted, delete `database/hybrid_vas.db` and restart the application. Default accounts will be re-seeded automatically.

### Tkinter not found (Linux)

```bash
sudo apt install python3-tk -y
```

### "Username already exists" when adding a user

Choose a different username. Usernames must be unique across the system.
