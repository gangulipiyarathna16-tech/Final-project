#!/bin/bash
# ===== URL Fuzzer + Malicious URL Checker =====
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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

echo -e "${YELLOW}Fuzzing directories on $target ...${RESET}"

# Warn if VirusTotal API key is not configured
if [[ "$API_KEY" == "PUT-YOUR-API-KEY-HERE" || -z "$API_KEY" ]]; then
    echo -e "${YELLOW}[!] VirusTotal API key not configured — threat analysis skipped${RESET}"
    vt_enabled=0
else
    vt_enabled=1
fi

total_tested=0
found_count=0

# Fuzzing loop
while IFS= read -r path || [[ -n "$path" ]]; do
    [[ -z "$path" ]] && continue
    full_url="${target}/${path}"
    ((total_tested++))
    status=$(curl -m 10 -k -o /dev/null -s -w "%{http_code}" "$full_url")

    # Skip connection errors (000) and not-found (404)
    if [[ "$status" == "000" || "$status" == "404" ]]; then
        continue
    fi

    ((found_count++))
    echo -e "${GREEN}[+] Found : $full_url  (HTTP $status)${RESET}"
    echo "$full_url (Status: $status)" >> "$output_file"

    # VirusTotal check (only if API key is configured)
    if [[ $vt_enabled -eq 1 ]]; then
        vt_id=$(echo -n "$full_url" | base64 -w0 | tr -d '=')
        vt_response=$(curl -s --max-time 10 --request GET \
            --url "https://www.virustotal.com/api/v3/urls/$vt_id" \
            --header "x-apikey: $API_KEY")
        malicious=$(echo "$vt_response" | jq -r '.data.attributes.last_analysis_stats.malicious // "error"')

        if [[ "$malicious" == "error" ]]; then
            echo -e "${YELLOW}    [!] VT lookup failed${RESET}"
            echo "[VT-ERROR] $full_url" >> "$output_file"
        elif [[ "$malicious" -gt 0 ]]; then
            echo -e "${RED}    [!] Malicious — $malicious engine(s) flagged${RESET}"
            echo "[MALICIOUS] $full_url" >> "$output_file"
        else
            echo -e "${BLUE}    [✓] Clean${RESET}"
            echo "[CLEAN] $full_url" >> "$output_file"
        fi
    fi
done < "$SCRIPT_DIR/wordlist.txt"

echo ""
echo -e "${BLUE}--- Fuzzing Summary ---${RESET}"
echo -e "${YELLOW}Paths tested  : $total_tested${RESET}"
echo -e "${GREEN}Paths found   : $found_count${RESET}"

if [[ $found_count -eq 0 ]]; then
    echo -e "${YELLOW}[INFO] No accessible paths discovered.${RESET}"
    echo "VERDICT : URL IS CLEAN — no accessible paths found"
else
    echo -e "${GREEN}Results saved in $output_file${RESET}"
    malicious_count=$(grep -c "\[MALICIOUS\]" "$output_file" 2>/dev/null || echo 0)
    if [[ "$malicious_count" -gt 0 ]]; then
        echo "VERDICT : THREAT DETECTED — $malicious_count malicious URL(s) found"
    else
        echo "VERDICT : URL IS CLEAN — no threats detected"
    fi
fi
