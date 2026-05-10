#!/bin/bash
# ============================================================
#   Hybrid Cybersecurity Engine - Network Scanner
#   Author  : GANGULI
#   Version : 1.1
#   Deps    : arp-scan or nmap, sqlite3
# ============================================================

RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
CYAN="\e[36m"
RESET="\e[0m"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DB_FILE="$PROJECT_ROOT/database/hybrid_vas.db"
REPORT_DIR="$PROJECT_ROOT/reports"
LOG_FILE="$PROJECT_ROOT/logs/network_scanner.log"

mkdir -p "$REPORT_DIR" "$(dirname "$LOG_FILE")" "$(dirname "$DB_FILE")"

# ------------------------------------------------------------
# Dependency check
# ------------------------------------------------------------
check_deps() {
    local missing=()

    command -v sqlite3 >/dev/null 2>&1 || missing+=("sqlite3")
    if ! command -v arp-scan >/dev/null 2>&1 && ! command -v nmap >/dev/null 2>&1; then
        missing+=("arp-scan or nmap")
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${RED}[ERROR] Missing dependencies: ${missing[*]}${RESET}"
        echo -e "${YELLOW}[INFO] Install on Debian/Kali/Ubuntu with:${RESET}"
        echo "sudo apt-get install -y arp-scan nmap sqlite3 dnsutils"
        exit 1
    fi

    echo -e "${GREEN}[OK] Dependencies ready.${RESET}"
}

# ------------------------------------------------------------
# Banner
# ------------------------------------------------------------
banner() {
    [[ -t 1 ]] && clear
    echo -e "${CYAN}============================================="
    echo "   Hybrid_VAS - Network Scanner v1.1"
    echo "   $(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "=============================================${RESET}"
}

# ------------------------------------------------------------
# DB - direct CLI logging tables
# ------------------------------------------------------------
init_db() {
    sqlite3 "$DB_FILE" <<SQL
CREATE TABLE IF NOT EXISTS network_scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    INTEGER,
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

sql_escape() {
    printf "%s" "${1//\'/\'\'}"
}

# ------------------------------------------------------------
# Discovery helpers
# ------------------------------------------------------------
auto_subnet() {
    ip route 2>/dev/null | awk '/proto kernel/ {print $1; exit}'
}

arp_sweep() {
    local subnet="$1"

    echo -e "${YELLOW}[INFO] Running host discovery on $subnet ...${RESET}" >&2

    if command -v arp-scan >/dev/null 2>&1; then
        if sudo -n true 2>/dev/null; then
            sudo -n arp-scan "$subnet" 2>/dev/null | awk '/^[0-9]/ {print $1 "\t" $2 "\t" substr($0, index($0,$3))}'
            return
        fi
        echo -e "${YELLOW}[WARN] sudo password required for arp-scan; falling back to nmap if available.${RESET}" >&2
    fi

    if command -v nmap >/dev/null 2>&1; then
        nmap -sn "$subnet" 2>/dev/null | awk '
            function flush_host() {
                if (ip != "" && up == 1) {
                    print ip "\t" (mac ? mac : "Unknown") "\t" (vendor ? vendor : "Unknown");
                }
            }
            /Nmap scan report for/ {
                flush_host();
                ip=$NF;
                gsub(/[()]/, "", ip);
                mac="";
                vendor="Unknown";
                up=0;
            }
            /Host is up/ {
                up=1;
            }
            /MAC Address:/ {
                mac=$3;
                vendor=substr($0, index($0,$4));
                gsub(/[()]/, "", vendor);
            }
            END {
                flush_host();
            }'
    fi
}

resolve_hostname() {
    local ip="$1"

    if command -v host >/dev/null 2>&1; then
        host "$ip" 2>/dev/null | awk '/domain name pointer/ {print $NF; found=1} END {if (!found) print "unknown"}' | tr -d '.'
    else
        echo "unknown"
    fi
}

save_scan() {
    [[ "${HCE_GUI_CAPTURE:-0}" == "1" ]] && return 0

    local subnet="$1" hosts="$2" unknown="$3" result="$4"
    local ts operator scan_id
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    operator="${USER:-unknown}"

    subnet=$(sql_escape "$subnet")
    result=$(sql_escape "$result")
    operator=$(sql_escape "$operator")

    scan_id=$(sqlite3 "$DB_FILE" "
        INSERT INTO network_scans (subnet, hosts_found, unknown_hosts, result, operator, timestamp)
        VALUES ('$subnet', $hosts, $unknown, '$result', '$operator', '$ts');
        SELECT last_insert_rowid();
    ")
    echo "$scan_id"
}

save_host() {
    [[ "${HCE_GUI_CAPTURE:-0}" == "1" ]] && return 0

    local scan_id="$1" ip="$2" mac="$3" hostname="$4" vendor="$5" status="$6"
    ip=$(sql_escape "$ip")
    mac=$(sql_escape "$mac")
    hostname=$(sql_escape "$hostname")
    vendor=$(sql_escape "$vendor")
    status=$(sql_escape "$status")

    sqlite3 "$DB_FILE" "
        INSERT INTO network_hosts (scan_id, ip_address, mac_address, hostname, vendor, status)
        VALUES ('$scan_id', '$ip', '$mac', '$hostname', '$vendor', '$status');
    "
}

generate_report() {
    [[ "${HCE_GUI_CAPTURE:-0}" == "1" ]] && return 0

    local subnet="$1"
    local report="$REPORT_DIR/network_scan_$(date +%Y%m%d_%H%M%S).txt"
    {
        echo "============================================================"
        echo "  HYBRID_VAS - Network Scanner Report"
        echo "  Generated : $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Subnet    : $subnet"
        echo "============================================================"
        echo ""
        sqlite3 -column -header "$DB_FILE" \
            "SELECT ip_address, mac_address, hostname, vendor, status FROM network_hosts
             WHERE scan_id = (SELECT MAX(id) FROM network_scans);"
    } > "$report"
    echo -e "${GREEN}[OK] Report saved: $report${RESET}"
}

# ------------------------------------------------------------
# Main scan
# ------------------------------------------------------------
run_scan() {
    local subnet="$1"
    local total=0
    local unknown=0
    local scan_id=""
    declare -a HOST_DATA

    if [[ -z "$subnet" ]]; then
        subnet=$(auto_subnet)
        echo -e "${CYAN}[INFO] Auto-detected subnet: ${subnet:-unknown}${RESET}"
    fi

    if [[ -z "$subnet" ]]; then
        echo -e "${RED}[ERROR] Could not determine subnet.${RESET}"
        echo "VERDICT : SCAN FAILED - subnet unavailable"
        return 1
    fi

    echo "Subnet: $subnet"
    echo -e "${CYAN}[INFO] Scanning subnet: $subnet${RESET}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') SCAN $subnet" >> "$LOG_FILE"

    while IFS=$'\t' read -r ip mac vendor; do
        [[ -z "$ip" ]] && continue
        total=$((total + 1))

        hostname=$(resolve_hostname "$ip")
        status="KNOWN"

        if [[ -z "$mac" || "$mac" == "Unknown" || "$mac" == "(Unknown)" ]]; then
            status="UNKNOWN"
            unknown=$((unknown + 1))
            echo -e "${RED}Host: $ip  MAC: ${mac:-Unknown}  Hostname: ${hostname:-unknown}  Vendor: ${vendor:-Unknown}  Status: UNKNOWN${RESET}"
        else
            echo -e "${GREEN}Host: $ip  MAC: $mac  Hostname: ${hostname:-unknown}  Vendor: ${vendor:-Unknown}  Status: KNOWN${RESET}"
        fi

        HOST_DATA+=("$ip|${mac:-Unknown}|${hostname:-unknown}|${vendor:-Unknown}|$status")
    done < <(arp_sweep "$subnet")

    result="$( [[ $unknown -gt 0 ]] && echo 'UNKNOWN_HOSTS_FOUND' || echo 'CLEAN' )"
    scan_id=$(save_scan "$subnet" "$total" "$unknown" "$result")

    if [[ -n "$scan_id" ]]; then
        for entry in "${HOST_DATA[@]}"; do
            IFS='|' read -r ip mac hostname vendor status <<< "$entry"
            save_host "$scan_id" "$ip" "$mac" "$hostname" "$vendor" "$status"
        done
    fi

    echo ""
    echo -e "${CYAN}=============================================${RESET}"
    echo "Hosts found : $total"
    echo "Unknown     : $unknown"
    echo "$total hosts found"
    echo "$unknown unknown hosts"

    if [[ $unknown -gt 0 ]]; then
        echo -e "${RED}VERDICT : UNKNOWN HOSTS DETECTED - investigate${RESET}"
    else
        echo -e "${GREEN}VERDICT : ALL HOSTS RECOGNISED${RESET}"
    fi
    echo -e "${CYAN}=============================================${RESET}"

    generate_report "$subnet"
}

view_history() {
    echo -e "${CYAN}Last 5 network scans:${RESET}"
    sqlite3 -column -header "$DB_FILE" \
        "SELECT id, subnet, hosts_found, unknown_hosts, result, timestamp
         FROM network_scans ORDER BY id DESC LIMIT 5;"
    echo ""
    read -p "Press ENTER to continue..."
}

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
