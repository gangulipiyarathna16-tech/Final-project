#!/usr/bin/env python3

import os
import requests
import base64
from datetime import datetime
import getpass

# ---------- CONFIG ----------
API_KEY = "560861232bb94d85dd87897058d35f4a7da76a8fe7e14e806ea15dd280c2dfc7"
WORDLIST_FILE = "wordlist.txt"
OUTPUT_DIR = "output"
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
print(f"{YELLOW}Fuzzing directories on {target}...{RESET}")

with open(WORDLIST_FILE, "r") as f:
    for path in f:
        path = path.strip()
        if not path:
            continue
        full_url = f"{target}/{path}"
        try:
            r = requests.get(full_url, timeout=5)
            status = r.status_code
        except requests.RequestException:
            status = 0

        if status not in [0, 404]:
            malicious_info = check_malicious(full_url)
            print(f"{GREEN}[+] Found: {full_url} (Status: {status}) {malicious_info}{RESET}")
            with open(output_file, "a") as out:
                out.write(f"{full_url} (Status: {status}) {malicious_info}\n")

print(f"{CYAN}Fuzzing complete. Results saved in {output_file}{RESET}")
