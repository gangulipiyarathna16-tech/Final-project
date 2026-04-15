#!/bin/bash
# ===== URL Fuzzer + Malicious URL Checker =====

# Colors
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
RESET="\e[0m"

# Your VirusTotal API Key
API_KEY="PUT-YOUR-API-KEY-HERE"

# Ask for target
read -p "Enter the target URL: " target
if [ -z "$target" ]; then
    echo -e "${RED}Error: URL cannot be empty. ${RESET}"
    exit 1
fi

mkdir -p output

# If no scheme is given, add https
if [[ "$target" != http* ]]; then
    target="https://$target"
fi

# Output file
timestamp=$(date +"%Y%m%d_%H%M%S")
output_file="output/fuzz_report_$timestamp.txt"

echo -e "${YELLOW}Fuzzing directories on $target ..... ${RESET}"

# Fuzzing loop
while read path; do
    full_url="${target}/${path}"
    status=$(curl -m 10 -k -o /dev/null -s -w "%{http_code}" "$full_url")

    if [[ "$status" != "404" ]]; then
        echo -e "${GREEN}[+] Found: $full_url (Status: $status) ${RESET}"
        echo "$full_url (Status: $status)" >> "$output_file"

        # === Check maliciousness with VirusTotal ===
        vt_id=$(echo -n "$full_url" | base64 -w0 | tr -d '=')

        vt_response=$(curl -s --request GET \
            --url "https://www.virustotal.com/api/v3/urls/$vt_id" \
            --header "x-apikey: $API_KEY")

        # Extract malicious verdict safely (if JSON missing, mark error)
        malicious=$(echo "$vt_response" | jq -r '.data.attributes.last_analysis_stats.malicious // "error"')

        if [[ "$malicious" == "error" ]]; then
            echo -e "${YELLOW}[!] VirusTotal lookup failed for $full_url ${RESET}"
            echo "[VT-ERROR] $full_url" >> "$output_file"
        elif [[ "$malicious" -gt 0 ]]; then
            echo -e "${RED}[!] Malicious: $full_url ${RESET}"
            echo "[MALICIOUS] $full_url" >> "$output_file"
        else
            echo -e "${BLUE}[✓] Clean: $full_url ${RESET}"
            echo "[CLEAN] $full_url" >> "$output_file"
        fi
    fi
done < wordlist.txt

echo -e "${GREEN}Fuzzing complete. Results saved in $output_file ${RESET}"
