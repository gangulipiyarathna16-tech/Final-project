#!/bin/bash

# =========================
# Hybrid_VAS Port Scanner
# Version 1.3 - SABINAS
# =========================

# ----- Colors -----
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
CYAN="\e[36m"
MAGENTA="\e[35m"
RESET="\e[0m"

# ----- Paths -----
DB_PATH="hybrid_vas/database/hybrid_vas.db"
REPORT_DIR="hybrid_vas/manual_tools/port_scanner/reports"
LOG_DIR="hybrid_vas/logs"
CONFIG_DIR="hybrid_vas/config"

mkdir -p "$REPORT_DIR" "$LOG_DIR" "$CONFIG_DIR"

# ----- Display Last Login -----
echo -e "${CYAN}[INFO] Last login: $(date '+%Y-%m-%d %H:%M:%S')${RESET}"

# ----- Dependency Check -----
check_dependencies() {
    packages=("sqlite3" "nc" "enscript" "ghostscript" "curl" "jq" "firefox")
    echo -e "${YELLOW}[INFO] Checking dependencies...${RESET}"
    for pkg in "${packages[@]}"; do
        if ! command -v $pkg &>/dev/null; then
            echo -e "${RED}[WARN] $pkg not found. Installing...${RESET}"
            sudo apt-get update -y && sudo apt-get install -y $pkg
        fi
    done
    echo -e "${GREEN}[INFO] All dependencies are installed.${RESET}"
}
check_dependencies

# ----- Utility Functions -----
log_action() {
    echo "$(date '+%F %T') - $1" >> "$LOG_DIR/port_scanner.log"
}

validate_ip() {
    local ip=$1
    if ! [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo -e "${RED}[ERROR] Invalid IP: $ip${RESET}"
        return 1
    fi
    return 0
}

get_geolocation() {
    local target=$1
    local info=$(curl -s ipinfo.io/$target)
    city=$(echo "$info" | jq -r '.city')
    country=$(echo "$info" | jq -r '.country')
    org=$(echo "$info" | jq -r '.org')
    echo "$city, $country ($org)"
}

# ----- DB Functions -----
save_to_db() {
    local target=$1
    local scan_type=$2
    local result=$3
    local risk_score=$4
    local geo=$5
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")

    sqlite3 "$DB_PATH" <<EOF
    CREATE TABLE IF NOT EXISTS port_scans(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT,
        scan_type TEXT,
        result TEXT,
        risk_score INTEGER,
        geo_info TEXT,
        timestamp TEXT
    );
    INSERT INTO port_scans (target, scan_type, result, risk_score, geo_info, timestamp)
    VALUES ("$target", "$scan_type", "$result", $risk_score, "$geo", "$timestamp");
EOF
}

show_scan_history() {
    echo -e "${CYAN}Last 5 scans:${RESET}"
    sqlite3 "$DB_PATH" "SELECT id,target,scan_type,risk_score,geo_info,timestamp FROM port_scans ORDER BY id DESC LIMIT 5;" | \
    while IFS='|' read -r id target scan_type score geo ts; do
        echo -e "${YELLOW}ID:$id${RESET} Target:$target | Type:$scan_type | Risk:$score | Geo:$geo | $ts"
    done
}

# ----- Banner Grab -----
banner_grab() {
    local ip=$1
    local port=$2
    timeout 2 bash -c "</dev/tcp/$ip/$port" &>/dev/null
    if [ $? -eq 0 ]; then
        banner=$(echo "" | nc -nv -w 2 $ip $port 2>/dev/null | head -n 1)
        echo -e "${GREEN}[OPEN]${RESET} Port ${CYAN}$port${RESET} - $banner"
        echo "$port - $banner"
    fi
}

# ----- Risk Scoring -----
compute_risk() {
    local ports_open="$1"
    score=0
    high_risk_ports=(21 23 3389 445 3306)
    for port in ${ports_open//,/ }; do
        if [[ " ${high_risk_ports[@]} " =~ " $port " ]]; then
            score=$((score + 20))
        else
            score=$((score + 5))
        fi
    done
    [ $score -gt 100 ] && score=100
    echo $score
}

# ----- PDF Generation -----
generate_pdf() {
    local txt_file=$1
    local pdf_file="${txt_file%.txt}.pdf"
    enscript "$txt_file" -o - | ps2pdf - "$pdf_file"
    echo -e "${YELLOW}[INFO] PDF report generated:${RESET} ${CYAN}$pdf_file${RESET}"
    echo "Open in Firefox? (y/n)"
    read choice
    [ "$choice" = "y" ] && firefox "$pdf_file" &
}

# ----- Progress Bar -----
show_progress() {
    local progress=$1
    local total=$2
    local percent=$((progress*100/total))
    printf "\rProgress: [%-50s] %d%%" $(printf "%0.s#" $(seq 1 $((percent/2)))) $percent
}

# ----- Scan Header -----
scan_header() {
    local target=$1
    local scan_type=$2
    echo -e "\n${MAGENTA}========================================${RESET}"
    echo -e "${CYAN}Starting $scan_type scan on target: $target${RESET}"
    echo -e "${MAGENTA}========================================${RESET}\n"
}

# ----- Scan Function -----
run_scan() {
    local target=$1
    local ports=$2
    local scan_type=$3
    local max_threads=$4
    local report_file="$REPORT_DIR/portscan_${target}_${scan_type}_$(date +%F_%H-%M-%S).txt"

    scan_header "$target" "$scan_type"

    geo=$(get_geolocation $target)
    echo -e "Target: $target\nGeo: $geo\nScan Type: $scan_type\n====================" > "$report_file"

    total_ports=$(echo $ports | wc -w)
    echo -e "${CYAN}[INFO] Total ports: $total_ports | Threads: $max_threads${RESET}"

    # Parallel scanning with progress bar
    count=0
    ports_open=""
    for port in $ports; do
        (
            res=$(banner_grab $target $port)
            [ ! -z "$res" ] && echo "$port" >> "${report_file}.tmp"
            ((count++))
            show_progress $count $total_ports
        ) &
        while (( $(jobs -r | wc -l) >= max_threads )); do sleep 0.05; done
    done
    wait
    echo ""  # Newline after progress bar

    if [ -f "${report_file}.tmp" ]; then
        ports_open=$(cat "${report_file}.tmp" | awk '{print $1}' | paste -sd "," -)
        cat "${report_file}.tmp" >> "$report_file"
        rm "${report_file}.tmp"
    fi

    risk=$(compute_risk "$ports_open")
    echo -e "\nRisk Score: $risk/100" >> "$report_file"

    save_to_db "$target" "$scan_type" "$(cat $report_file)" "$risk" "$geo"
    cat "$report_file"

    if [[ $risk -ge 70 ]]; then
        echo "VERDICT : HIGH RISK — $risk/100 risk score, critical ports exposed"
    elif [[ $risk -ge 30 ]]; then
        echo "VERDICT : SUSPICIOUS — $risk/100 risk score, review open ports"
    else
        echo "VERDICT : ALL PORTS CLEAN — risk score $risk/100"
    fi

    generate_pdf "$report_file"
}

# ----- Predefined Scan Types -----
quick_ports=$(seq 1 1024)
deep_ports=$(seq 1 65535)

# ----- Scan Menus -----
scan_quick() {
    echo "Enter target IP (or comma separated for multi-targets): "
    read target_input
    for tgt in $(echo $target_input | tr ',' ' '); do
        validate_ip $tgt && run_scan $tgt "$quick_ports" "Quick" 50
    done
}

scan_deep() {
    echo "Enter target IP (or comma separated for multi-targets): "
    read target_input
    for tgt in $(echo $target_input | tr ',' ' '); do
        validate_ip $tgt && run_scan $tgt "$deep_ports" "Deep" 50
    done
}

scan_manual() {
    echo "Enter target IP: "
    read target
    validate_ip $target || return
    echo "Enter ports separated by space (or ranges like 20-25): "
    read ports
    expanded_ports=""
    for p in $ports; do
        if [[ $p =~ - ]]; then
            start=${p%-*}
            end=${p#*-}
            expanded_ports="$expanded_ports $(seq $start $end)"
        else
            expanded_ports="$expanded_ports $p"
        fi
    done
    run_scan $target "$expanded_ports" "Manual" 50
}

scan_multi() {
    echo "Enter multiple targets (comma separated): "
    read targets
    echo "Enter ports separated by space (or ranges like 20-25): "
    read ports
    expanded_ports=""
    for p in $ports; do
        if [[ $p =~ - ]]; then
            start=${p%-*}
            end=${p#*-}
            expanded_ports="$expanded_ports $(seq $start $end)"
        else
            expanded_ports="$expanded_ports $p"
        fi
    done
    for tgt in $(echo $targets | tr ',' ' '); do
        validate_ip $tgt && run_scan $tgt "$expanded_ports" "Multi" 50
    done
}

reports_menu() {
    echo -e "${CYAN}Reports Menu:${RESET}"
    echo "1. View last 5 scans in DB"
    echo "2. Open latest report in Firefox"
    echo "3. Back to main menu"
    read choice
    case $choice in
        1) show_scan_history ;;
        2) firefox $(ls -t $REPORT_DIR/*.pdf | head -1) & ;;
        3) return ;;
        *) echo -e "${RED}Invalid choice${RESET}" ;;
    esac
}

show_help() {
    echo -e "${CYAN}Scan Types:${RESET}"
    echo -e "1. Quick Scan (ports 1-1024)"
    echo -e "2. Deep Scan (ports 1-65535)"
    echo -e "3. Manual Scan (user defined ports)"
    echo -e "4. Multi-Target Scan"
    echo -e "Select a scan type to perform directly, or press enter to return."
    read choice
    case $choice in
        1) scan_quick ;;
        2) scan_deep ;;
        3) scan_manual ;;
        4) scan_multi ;;
        *) return ;;
    esac
}

# ----- Main Menu -----
while true; do
    echo -e "\n${CYAN}============================"
    echo "   Hybrid_VAS Port Scanner"
    echo "        v1.3 - SABINAS"
    echo -e "============================${RESET}\n"
    echo -e "${YELLOW}1${RESET}. Quick Scan"
    echo -e "${YELLOW}2${RESET}. Deep Scan"
    echo -e "${YELLOW}3${RESET}. Manual Scan"
    echo -e "${YELLOW}4${RESET}. Multi-Target Scan"
    echo -e "${YELLOW}5${RESET}. Scan History"
    echo -e "${YELLOW}6${RESET}. Reports Menu"
    echo -e "${YELLOW}7${RESET}. Help / Scan Types"
    echo -e "${YELLOW}8${RESET}. Exit"
    read -p "Choose an option: " menu_choice

    case $menu_choice in
        1) scan_quick ;;
        2) scan_deep ;;
        3) scan_manual ;;
        4) scan_multi ;;
        5) show_scan_history ;;
        6) reports_menu ;;
        7) show_help ;;
        8) echo -e "${YELLOW}Exiting...${RESET}"; break ;;
        *) echo -e "${RED}Invalid choice, try again.${RESET}" ;;
    esac
done
