#!/bin/bash
# ============================================================
#   Hybrid Cybersecurity Engine — Network Scanner
#   Author  : GANGULI
#   Version : 1.0
#   Deps    : arp-scan, nmap, sqlite3, curl, jq
# ============================================================

RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
CYAN="\e[36m"
MAGENTA="\e[35m"
RESET="\e[0m"

DB_FILE="$HOME/hybrid_vas/database/hybrid_vas.db"
REPORT_DIR="$HOME/hybrid_vas/reports"
LOG_FILE="$HOME/hybrid_vas/logs/network_scanner.log"

mkdir -p "$REPORT_DIR" "$(dirname "$LOG_FILE")"

# ─────────────────────────────────────────────────
#  DEPENDENCY CHECK
# ─────────────────────────────────────────────────
check_deps() {
    for cmd in arp-scan nmap sqlite3 curl jq; do
        if ! command -v "$cmd" &>/dev/null; then
            echo -e "${YELLOW}[!] $cmd not found. Installing...${RESET}"
            sudo apt-get install -y "$cmd" &>/dev/null
        fi
    done
    echo -e "${GREEN}[✔] Dependencies ready.${RESET}"
}

# ─────────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────────
banner() {
    clear
    echo -e "${CYAN}============================================="
    echo "   Hybrid_VAS — Network Scanner v1.0"
    echo "   $(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "=============================================${RESET}"
}

# ─────────────────────────────────────────────────
#  DB — ensure table exists
# ─────────────────────────────────────────────────
init_db() {
    sqlite3 "$DB_FILE" <<SQL
CREATE TABLE IF NOT EXISTS network_scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    subnet        TEXT,
    hosts_found   INTEGER DEFAULT 0,
    unknown_hosts INTEGER DEFAULT 0,
    result        TEXT,
    operator      TEXT,
    timestamp     DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS network_hosts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER,
    ip_address  TEXT,
    mac_address TEXT,
    hostname    TEXT,
    vendor      TEXT,
    status      TEXT,
    timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP
);
SQL
}

# ─────────────────────────────────────────────────
#  ARP SWEEP — discover live hosts
# ─────────────────────────────────────────────────
arp_sweep() {
    local subnet="$1"
    echo -e "${YELLOW}[*] Running ARP sweep on $subnet ...${RESET}"
    sudo arp-scan --localnet 2>/dev/null | grep -E "^[0-9]" || \
    sudo arp-scan "$subnet" 2>/dev/null | grep -E "^[0-9]"
}

# ─────────────────────────────────────────────────
#  HOSTNAME RESOLUTION
# ─────────────────────────────────────────────────
resolve_hostname() {
    local ip="$1"
    host "$ip" 2>/dev/null | grep "domain name pointer" | awk '{print $NF}' | tr -d '.' || echo "unknown"
}

# ─────────────────────────────────────────────────
#  OS FINGERPRINT (lightweight via nmap)
# ─────────────────────────────────────────────────
os_fingerprint() {
    local ip="$1"
    sudo nmap -O --osscan-guess -T4 -p 22,80,443 "$ip" 2>/dev/null | \
        grep "OS guess\|OS details\|Running:" | head -2 | awk -F': ' '{print $2}' | tr '\n' ' '
}

# ─────────────────────────────────────────────────
#  SAVE TO DB
# ─────────────────────────────────────────────────
save_scan() {
    local subnet="$1" hosts="$2" unknown="$3" result="$4"
    local ts operator scan_id
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    operator="${USER:-unknown}"

    scan_id=$(sqlite3 "$DB_FILE" "
        INSERT INTO network_scans (subnet, hosts_found, unknown_hosts, result, operator, timestamp)
        VALUES ('$subnet', $hosts, $unknown, '$result', '$operator', '$ts');
        SELECT last_insert_rowid();
    ")
    echo "$scan_id"
}

save_host() {
    local scan_id="$1" ip="$2" mac="$3" hostname="$4" vendor="$5" status="$6"
    sqlite3 "$DB_FILE" "
        INSERT INTO network_hosts (scan_id, ip_address, mac_address, hostname, vendor, status)
        VALUES ('$scan_id', '$ip', '$mac', '$hostname', '$vendor', '$status');
    "
}

# ─────────────────────────────────────────────────
#  REPORT GENERATION
# ─────────────────────────────────────────────────
generate_report() {
    local subnet="$1"
    local report="$REPORT_DIR/network_scan_$(date +%Y%m%d_%H%M%S).txt"
    {
        echo "============================================================"
        echo "  HYBRID_VAS — Network Scanner Report"
        echo "  Generated : $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Subnet    : $subnet"
        echo "============================================================"
        echo ""
        sqlite3 -column -header "$DB_FILE" \
            "SELECT ip_address, mac_address, hostname, vendor, status FROM network_hosts
             WHERE scan_id = (SELECT MAX(id) FROM network_scans);"
    } > "$report"
    echo -e "${GREEN}[✔] Report saved: $report${RESET}"
}

# ─────────────────────────────────────────────────
#  MAIN SCAN
# ─────────────────────────────────────────────────
run_scan() {
    local subnet="$1"
    local total=0 unknown=0
    declare -a HOST_DATA

    # Detect subnet automatically if not given
    if [[ -z "$subnet" ]]; then
        subnet=$(ip route | grep "proto kernel" | head -1 | awk '{print $1}')
        echo -e "${CYAN}[INFO] Auto-detected subnet: $subnet${RESET}"
    fi

    echo -e "${CYAN}[INFO] Scanning subnet: $subnet${RESET}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') SCAN $subnet" >> "$LOG_FILE"

    while IFS=$'\t' read -r ip mac vendor; do
        [[ -z "$ip" ]] && continue
        total=$((total + 1))

        hostname=$(resolve_hostname "$ip")

        status="KNOWN"
        if [[ -z "$mac" || "$mac" == "(Unknown)" ]]; then
            status="UNKNOWN"
            unknown=$((unknown + 1))
            echo -e "${RED}  [!] UNKNOWN HOST: $ip  $mac  $vendor${RESET}"
        else
            echo -e "${GREEN}  [+] $ip  $mac  ${vendor:-?}  $hostname${RESET}"
        fi

        HOST_DATA+=("$ip|$mac|$hostname|${vendor:-Unknown}|$status")
    done < <(arp_sweep "$subnet" | awk '{print $1"\t"$2"\t"substr($0, index($0,$3))}')

    # Save to DB
    scan_id=$(save_scan "$subnet" "$total" "$unknown" \
        "$( [[ $unknown -gt 0 ]] && echo 'UNKNOWN_HOSTS_FOUND' || echo 'CLEAN' )")

    for entry in "${HOST_DATA[@]}"; do
        IFS='|' read -r ip mac hostname vendor status <<< "$entry"
        save_host "$scan_id" "$ip" "$mac" "$hostname" "$vendor" "$status"
    done

    # Verdict
    echo -e "\n${CYAN}=============================================${RESET}"
    echo -e "  Hosts found : $total"
    echo -e "  Unknown     : $unknown"
    if [[ $unknown -gt 0 ]]; then
        echo -e "${RED}  VERDICT : UNKNOWN HOSTS DETECTED — investigate${RESET}"
    else
        echo -e "${GREEN}  VERDICT : ALL HOSTS RECOGNISED${RESET}"
    fi
    echo -e "${CYAN}=============================================${RESET}"

    generate_report "$subnet"
}

# ─────────────────────────────────────────────────
#  VIEW HISTORY
# ─────────────────────────────────────────────────
view_history() {
    echo -e "${CYAN}Last 5 network scans:${RESET}"
    sqlite3 -column -header "$DB_FILE" \
        "SELECT id, subnet, hosts_found, unknown_hosts, result, timestamp
         FROM network_scans ORDER BY id DESC LIMIT 5;"
    echo ""
    read -p "Press ENTER to continue..."
}

# ─────────────────────────────────────────────────
#  MAIN MENU
# ─────────────────────────────────────────────────
check_deps
init_db
banner

while true; do
    echo -e "\n${CYAN}============================="
    echo "   Network Scanner Menu"
    echo -e "=============================${RESET}"
    echo -e "${YELLOW}1${RESET}. Auto-detect subnet and scan"
    echo -e "${YELLOW}2${RESET}. Enter subnet manually (e.g. 192.168.1.0/24)"
    echo -e "${YELLOW}3${RESET}. View scan history"
    echo -e "${YELLOW}4${RESET}. Exit"
    read -p "Choose: " choice

    case "$choice" in
        1) run_scan "" ;;
        2)
            read -p "Enter subnet (e.g. 192.168.1.0/24): " subnet
            run_scan "$subnet"
            ;;
        3) view_history ;;
        4) echo -e "${YELLOW}Exiting...${RESET}"; break ;;
        *) echo -e "${RED}Invalid choice.${RESET}" ;;
    esac
done
