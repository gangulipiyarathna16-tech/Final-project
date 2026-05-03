#!/usr/bin/env python3

import os
import requests
import base64
from datetime import datetime
import getpass

# ---------- CONFIG ----------
API_KEY = "PUT-YOUR-API-KEY-HERE"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
WORDLIST_FILE = os.path.join(SCRIPT_DIR, "wordlist.txt")
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "output")
# ----------------------------

# Colors for terminal
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RED = "\033[31m"
RESET = "\033[0m"

# Get user and last login
user = getpass.getuser()
last_login = os.popen(f"last -n 1 {user} | head -n 1").read().strip()

# Banner
print(f"{CYAN}============================================={RESET}")
print(f"{GREEN}         Hybrid VAS - URL Fuzzer Tool       {RESET}")
print(f"{YELLOW}Author: Ganguli Piyarathna{RESET}")
print(f"{YELLOW}Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
print(f"{YELLOW}Last login: {last_login}{RESET}")
print(f"{CYAN}============================================={RESET}\n")

# Ask for target URL
target = input(f"{CYAN}Enter the target URL (or type 'exit' to quit): {RESET}").strip()
if target.lower() == "exit":
    print(f"{YELLOW}Exiting URL Fuzzer...{RESET}")
    exit(0)

if not target:
    print(f"{RED}Error: URL cannot be empty.{RESET}")
    exit(1)

# Create output directory
os.makedirs(OUTPUT_DIR, exist_ok=True)
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
output_file = os.path.join(OUTPUT_DIR, f"fuzz_report_{timestamp}.txt")

# VirusTotal URL check
def check_malicious(url):
    if not API_KEY or API_KEY == "YOUR_VIRUSTOTAL_API_KEY":
        return f"{YELLOW}VT API key not set{RESET}"
    try:
        encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": API_KEY}
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{encoded_url}", headers=headers)
        if response.status_code == 200:
            data = response.json()
            malicious_count = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
            if malicious_count > 0:
                return f"{RED}Malicious ({malicious_count} detections){RESET}"
            else:
                return f"{GREEN}Clean{RESET}"
        else:
            return f"{YELLOW}VT Error ({response.status_code}){RESET}"
    except Exception as e:
        return f"{YELLOW}Scan Error: {e}{RESET}"

# Start fuzzing
if not os.path.isfile(WORDLIST_FILE):
    print(f"{RED}[ERROR] Wordlist not found: {WORDLIST_FILE}{RESET}")
    exit(1)

with open(WORDLIST_FILE, "r") as f:
    paths = [line.strip() for line in f if line.strip()]

total_paths = len(paths)
print(f"{CYAN}[INFO] Loaded {total_paths} paths from wordlist{RESET}")
print(f"{YELLOW}Fuzzing {target} ...{RESET}")

found_count = 0
for idx, path in enumerate(paths, 1):
    if idx % 50 == 0 or idx == total_paths:
        print(f"{CYAN}[INFO] Progress : {idx}/{total_paths} paths tested{RESET}")
    full_url = f"{target}/{path}"
    try:
        r = requests.get(full_url, timeout=5)
        status = r.status_code
    except requests.RequestException:
        status = 0

    if status not in [0, 404]:
        found_count += 1
        malicious_info = check_malicious(full_url)
        print(f"{GREEN}[+] Found : {full_url}  (HTTP {status})  {malicious_info}{RESET}")
        with open(output_file, "a") as out:
            out.write(f"{full_url} (Status: {status})\n")

print(f"\n{CYAN}--- Fuzzing Summary ---{RESET}")
print(f"{YELLOW}Paths tested  : {total_paths}{RESET}")
print(f"{GREEN}Paths found   : {found_count}{RESET}")

if found_count == 0:
    print(f"{YELLOW}[INFO] No accessible paths discovered.{RESET}")
    print("VERDICT : URL IS CLEAN — no accessible paths found")
else:
    print(f"{CYAN}Results saved in {output_file}{RESET}")
    print("VERDICT : SCAN COMPLETE — review found paths above")
