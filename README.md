# Hybrid Cybersecurity Engine — Professional Edition v5

A desktop cybersecurity assessment platform built with Python and Tkinter, combining manual network tools (Bash scripts) and automated Python-based scanners into a single unified interface with role-based access control and a persistent SQLite database.

---

## Features

### Manual Tools (Bash)
| Tool | Description |
|---|---|
| **URL Scanner** | Checks URLs against VirusTotal API (72 engines) and global blacklists for phishing and malware indicators |
| **Domain Checker** | WHOIS lookup, DNS A/MX/NS enumeration, and domain reputation analysis |
| **Port Scanner** | SYN scan to discover open TCP/UDP ports and fingerprint running services |
| **Network Scanner** | ARP broadcast sweep to discover all live hosts on a subnet |
| **USB Device Scanner** | Enumerates connected USB devices and verifies file hashes against known threat signatures |

### Automated Tools (Python)
| Tool | Description |
|---|---|
| **Malware Scanner** | Hash-based detection engine cross-referencing 4.8 million MD5/SHA256 malware signatures |
| **AI Malware Detector** | RandomForest ML classifier for zero-day and obfuscated malware detection — 94.7% accuracy |
| **Backdoor Scanner** | Detects reverse shells, Remote Access Trojans (RATs), suspicious processes, and persistence mechanisms |
| **Vulnerability Scanner** | CVE database assessment with CVSS severity scoring against detected software versions |

---

## Requirements

- Python 3.10+
- Tkinter (`sudo apt install python3-tk -y` on Linux/WSL)
- Windows users: WSL must be installed and configured to run Bash tools

---

## Installation & Setup

```bash
# Clone the repository
git clone <repo-url>
cd Final-project

# (Linux/WSL) Install Tkinter if not present
sudo apt install python3-tk -y

# Run the application
python3 RUN9_wired.py
```

The database is created automatically at `database/hybrid_vas.db` on first launch.

---

## Project Structure

```
Final-project/
├── RUN9_wired.py                        # Main application entry point
├── db_init.py                           # Database initialisation script
├── database/
│   └── hybrid_vas.db                    # SQLite database (auto-created)
├── manual_tools/                        # Bash-based scanner scripts
│   ├── Domain-1.sh                      # URL scanner
│   ├── Domain_checker.sh                # Domain checker
│   ├── port_scanner.sh                  # Port scanner
│   ├── network_scanner.sh               # Network scanner
│   └── usb_scanner.sh                   # USB device scanner
├── automated_tools/
│   ├── backdoor_scanner.py              # Backdoor/RAT detection
│   ├── vuln_scanner.py                  # CVE vulnerability scanner
│   └── malware_scan/
│       ├── scripts/
│       │   ├── malware_scan_engine.py   # Hash & AI malware scanner
│       │   ├── malware_train.py         # ML model training script
│       │   ├── detection.py             # Detection logic
│       │   └── extractor.py             # Feature extractor
│       ├── models/
│       │   └── model.pkl                # Trained RandomForest model
│       └── logs/                        # Scan output logs
├── models/
│   └── model.pkl                        # Root-level model copy
└── datasets/
    └── Malware-Benign.csv               # Training dataset
```

---

## User Roles & Default Credentials

| Username | Password | Role | Permissions |
|---|---|---|---|
| `admin` | `admin123` | Admin | Full access: run tools, manage users, view logs, export, config |
| `analyst1` | `analyst123` | Analyst | Run manual & automated tools, view results, export |
| `viewer1` | `viewer123` | Viewer | View results only |
| `guest` | `guest123` | Guest | No permissions |

> **Note:** Change default passwords before deployment.

---

## Database Schema

All scan results are persisted in SQLite with full structured detail:

| Table | Purpose |
|---|---|
| `users` | User accounts with hashed passwords and roles |
| `audit` | Login and action audit trail |
| `scan_sessions` | Master row for every scan run (tool, target, operator, verdict, duration) |
| `malware_scan_logs` | Per-file malware scan results (hash, family, confidence, method) |
| `backdoor_scans` | Backdoor scan results (PIDs, ports, cron, startup findings) |
| `backdoor_findings` | Structured per-finding rows from backdoor scans |
| `vuln_scans` | Vulnerability scan runs per target |
| `vuln_findings` | CVE findings with CVSS scores and severity |
| `domain_logs` | Domain scan results (IP, registrar, risk score) |
| `port_scans` | Port scan runs with scan type and verdict |
| `port_findings` | Per-port results (port, protocol, state, service, version) |
| `usb_scans` | USB scan results (device name, path, file counts, threat count) |
| `usb_file_results` | Per-file results from USB scans |

---

## OS Compatibility

| Platform | Bash Tools | Python Tools |
|---|---|---|
| Linux | Native (`bash`) | Native (`python3`) |
| Windows | Via WSL (`wsl bash`) | Native (`python.exe`) |

Bash tools require WSL on Windows. Python tools (malware, AI, backdoor, vuln) run natively on both platforms.

---

## Running

```bash
python3 RUN9_wired.py
```

The GUI launches with a login screen. After authentication, available tools are filtered by the user's role. Each tool displays a live output panel with real script execution and results saved automatically to the database.
