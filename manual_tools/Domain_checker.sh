#!/bin/bash
# ============================================================
#   HYBRID CYBERSECURITY ENGINE
#   Tool    : Domain Checker
#   Author  : GANGULI
#   Version : 2.0  —  Matrix War Room Edition
#   Deps    : whois, curl, jq, sqlite3, dig
# ============================================================

# ─────────────────────────────────────────
#  CONFIGURATION
# ─────────────────────────────────────────
DB_DIR="$HOME/hybrid_vas/database"
DB_FILE="$DB_DIR/hybrid_vas.db"
LOG_FILE="$HOME/hybrid_vas/logs/domain_checker.log"
REPORT_DIR="$HOME/hybrid_vas/reports"
API_KEY="PUT-YOUR-API-KEY-HERE"
TOOL_NAME="Domain Checker"
AUTHOR="GANGULI"
VERSION="2.0"

# ─────────────────────────────────────────
#  MATRIX COLOUR PALETTE
# ─────────────────────────────────────────
MATRIX="\e[1;32m"
G2="\e[0;32m"
G3="\e[2;32m"
CYAN="\e[1;36m"
RED="\e[1;31m"
AMBER="\e[1;33m"
WHITE="\e[1;37m"
DIM="\e[2;37m"
GREEN="\e[0;32m"        # BUG FIX #1: GREEN was used on line 532 but never defined
BOLD="\e[1m"
BLINK="\e[5m"
RESET="\e[0m"

# ─────────────────────────────────────────
#  DEPENDENCY CHECK
# ─────────────────────────────────────────
check_deps() {
    local missing=()
    for cmd in whois curl jq sqlite3 dig; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${RED}[✘] Missing dependencies: ${missing[*]}${RESET}"
        echo -e "${AMBER}[!] Install with: sudo apt install ${missing[*]} -y${RESET}"
        exit 1
    fi
}

# ─────────────────────────────────────────
#  DIRECTORY + DB INIT
# ─────────────────────────────────────────
init_env() {
    mkdir -p "$DB_DIR" "$REPORT_DIR" "$(dirname "$LOG_FILE")"

    sqlite3 "$DB_FILE" <<SQL
CREATE TABLE IF NOT EXISTS domain_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    domain      TEXT    NOT NULL,
    ip_address  TEXT,
    registrar   TEXT,
    created     TEXT,
    expires     TEXT,
    vt_malicious  INTEGER DEFAULT 0,
    vt_suspicious INTEGER DEFAULT 0,
    vt_clean      INTEGER DEFAULT 0,
    result      TEXT    NOT NULL,
    risk_score  INTEGER DEFAULT 0,
    operator    TEXT,
    timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS tool_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tool_name   TEXT,
    operator    TEXT,
    run_time    DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS dns_records (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    domain      TEXT,
    record_type TEXT,
    record_value TEXT,
    timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP
);
SQL
}

# ─────────────────────────────────────────
#  LOGGING
# ─────────────────────────────────────────
log_tool_run() {
    sqlite3 "$DB_FILE" \
        "INSERT INTO tool_logs (tool_name, operator, run_time)
         VALUES ('$TOOL_NAME', '${OPERATOR:-unknown}', datetime('now'));"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] RUN  operator=${OPERATOR:-unknown}" >> "$LOG_FILE"
}

get_last_run() {
    local last
    last=$(sqlite3 "$DB_FILE" \
        "SELECT run_time FROM tool_logs
         WHERE tool_name='$TOOL_NAME'
         ORDER BY id DESC LIMIT 1 OFFSET 1;" 2>/dev/null)
    echo "${last:-First run — no previous session}"
}

get_total_scans() {
    sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM domain_logs;" 2>/dev/null || echo "0"
}

get_total_threats() {
    sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM domain_logs WHERE result='MALICIOUS';" 2>/dev/null || echo "0"
}

# ─────────────────────────────────────────
#  SAVE RESULTS
# ─────────────────────────────────────────
save_to_db() {
    local domain="$1" ip="$2" registrar="$3" created="$4" expires="$5"
    local vt_mal="$6" vt_sus="$7" vt_clean="$8" result="$9"
    local risk="${10}" operator="${11:-unknown}"

    # sanitise inputs to prevent SQL injection
    domain="${domain//\'/\'\'}"
    registrar="${registrar//\'/\'\'}"

    sqlite3 "$DB_FILE" \
        "INSERT INTO domain_logs
         (domain, ip_address, registrar, created, expires,
          vt_malicious, vt_suspicious, vt_clean, result, risk_score, operator)
         VALUES
         ('$domain','$ip','$registrar','$created','$expires',
          $vt_mal,$vt_sus,$vt_clean,'$result',$risk,'$operator');"

    echo "[$(date '+%Y-%m-%d %H:%M:%S')] SCAN domain=$domain result=$result risk=$risk" \
        >> "$LOG_FILE"
}

save_dns() {
    local domain="$1" type="$2" value="$3"
    sqlite3 "$DB_FILE" \
        "INSERT INTO dns_records (domain, record_type, record_value)
         VALUES ('${domain//\'/\'\'}','$type','${value//\'/\'\'}');"
}

# ─────────────────────────────────────────
#  MATRIX BANNER
# ─────────────────────────────────────────
show_banner() {
    clear
    local last_run total_scans total_threats
    last_run=$(get_last_run)
    total_scans=$(get_total_scans)
    total_threats=$(get_total_threats)

    echo -e "${MATRIX}"
    echo -e " ╔══════════════════════════════════════════════════════════╗"
    echo -e " ║   ██╗  ██╗ ██████╗███████╗                              ║"
    echo -e " ║   ██║  ██║██╔════╝██╔════╝                              ║"
    echo -e " ║   ███████║██║     █████╗                                ║"
    echo -e " ║   ██╔══██║██║     ██╔══╝   DOMAIN CHECKER  v${VERSION}        ║"
    echo -e " ║   ██║  ██║╚██████╗███████╗                              ║"
    echo -e " ║   ╚═╝  ╚═╝ ╚═════╝╚══════╝ WHOIS + DNS + VIRUSTOTAL    ║"
    echo -e " ╠══════════════════════════════════════════════════════════╣"
    printf  " ║  ${WHITE}%-56s${MATRIX}║\n" "Author   : $AUTHOR"
    printf  " ║  ${G2}%-56s${MATRIX}║\n"   "Last Run : $last_run"
    printf  " ║  ${CYAN}%-56s${MATRIX}║\n" "Scans    : $total_scans total  |  Threats: $total_threats detected"
    echo -e " ╚══════════════════════════════════════════════════════════╝${RESET}"
    echo
}

# ─────────────────────────────────────────
#  SECTION DIVIDER
# ─────────────────────────────────────────
divider() {
    echo -e "${G3} ──────────────────────────────────────────────────────────${RESET}"
}

section() {
    echo -e "\n${MATRIX}[▸]${AMBER} $1 ${RESET}"
    divider
}

# ─────────────────────────────────────────
#  VALIDATE DOMAIN FORMAT
# ─────────────────────────────────────────
validate_domain() {
    local domain="$1"
    if [[ ! "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$ ]]; then
        return 1
    fi
    return 0
}

# ─────────────────────────────────────────
#  WHOIS LOOKUP
# ─────────────────────────────────────────
run_whois() {
    local domain="$1"
    section "WHOIS INFORMATION"

    local raw
    raw=$(whois "$domain" 2>/dev/null)

    if [[ -z "$raw" ]]; then
        echo -e "${RED}  [✘] WHOIS lookup failed — no response${RESET}"
        REGISTRAR="N/A"; CREATED="N/A"; EXPIRES="N/A"; return
    fi

    REGISTRAR=$(echo "$raw" | grep -iE "^Registrar:" | head -1 | awk -F: '{print $2}' | xargs)
    CREATED=$(echo   "$raw" | grep -iE "Creation Date|Created" | head -1 | awk -F: '{print $2}' | xargs | cut -c1-20)
    EXPIRES=$(echo   "$raw" | grep -iE "Expiry Date|Expiration" | head -1 | awk -F: '{print $2}' | xargs | cut -c1-20)
    STATUS=$(echo    "$raw" | grep -iE "^Domain Status" | head -3 | awk -F: '{print $2}' | xargs | tr '\n' ' ')
    NAMESERVERS=$(echo "$raw" | grep -iE "^Name Server" | head -4 | awk '{print $NF}' | tr '\n' ' ')

    [[ -z "$REGISTRAR"   ]] && REGISTRAR="N/A"
    [[ -z "$CREATED"     ]] && CREATED="N/A"
    [[ -z "$EXPIRES"     ]] && EXPIRES="N/A"
    [[ -z "$STATUS"      ]] && STATUS="N/A"
    [[ -z "$NAMESERVERS" ]] && NAMESERVERS="N/A"

    printf "  ${G2}%-20s${WHITE}%s${RESET}\n" "Registrar:"   "$REGISTRAR"
    printf "  ${G2}%-20s${WHITE}%s${RESET}\n" "Created:"     "$CREATED"
    printf "  ${G2}%-20s${WHITE}%s${RESET}\n" "Expires:"     "$EXPIRES"
    printf "  ${G2}%-20s${WHITE}%s${RESET}\n" "Status:"      "$STATUS"
    printf "  ${G2}%-20s${WHITE}%s${RESET}\n" "Nameservers:" "$NAMESERVERS"
}

# ─────────────────────────────────────────
#  DNS ENUMERATION
# ─────────────────────────────────────────
run_dns() {
    local domain="$1"
    section "DNS ENUMERATION"

    local a_record mx_record txt_record ns_record
    a_record=$(dig  +short A     "$domain"  2>/dev/null | head -5)
    mx_record=$(dig +short MX    "$domain"  2>/dev/null | head -5)
    txt_record=$(dig +short TXT  "$domain"  2>/dev/null | head -3)
    ns_record=$(dig  +short NS   "$domain"  2>/dev/null | head -4)

    IP_ADDRESS=$(echo "$a_record" | head -1)
    [[ -z "$IP_ADDRESS" ]] && IP_ADDRESS="Unresolved"

    printf "  ${G2}%-20s${WHITE}%s${RESET}\n" "A  (IPv4):"   "${a_record:-N/A}"
    printf "  ${G2}%-20s${WHITE}%s${RESET}\n" "MX (Mail):"   "${mx_record:-N/A}"
    printf "  ${G2}%-20s${WHITE}%s${RESET}\n" "NS (Server):" "${ns_record:-N/A}"

    if [[ -n "$txt_record" ]]; then
        printf "  ${G2}%-20s${RESET}\n" "TXT Records:"
        echo "$txt_record" | while read -r line; do
            echo -e "    ${DIM}$line${RESET}"
        done
    fi

    local spf dmarc
    spf=$(dig +short TXT "$domain" 2>/dev/null | grep -i "v=spf")
    dmarc=$(dig +short TXT "_dmarc.$domain" 2>/dev/null | grep -i "v=DMARC")

    echo
    if [[ -n "$spf" ]];   then echo -e "  ${MATRIX}[✔]${RESET} SPF record found";      else echo -e "  ${AMBER}[!]${RESET} No SPF record — spoofing risk";  fi
    if [[ -n "$dmarc" ]]; then echo -e "  ${MATRIX}[✔]${RESET} DMARC policy found";    else echo -e "  ${AMBER}[!]${RESET} No DMARC record — phishing risk"; fi

    [[ -n "$a_record"  ]] && save_dns "$domain" "A"  "$a_record"
    [[ -n "$mx_record" ]] && save_dns "$domain" "MX" "$mx_record"
    [[ -n "$ns_record" ]] && save_dns "$domain" "NS" "$ns_record"
}

# ─────────────────────────────────────────
#  VIRUSTOTAL ANALYSIS
# ─────────────────────────────────────────
run_virustotal() {
    local domain="$1"
    section "VIRUSTOTAL ANALYSIS"

    if [[ "$API_KEY" == "PUT-YOUR-API-KEY-HERE" ]]; then
        echo -e "  ${AMBER}[!] VirusTotal API key not set.${RESET}"
        echo -e "  ${DIM}    Get a free key at: https://www.virustotal.com/gui/my-apikey${RESET}"
        VT_MALICIOUS=0; VT_SUSPICIOUS=0; VT_CLEAN=0
        return
    fi

    echo -e "  ${G3}[◌] Querying VirusTotal API...${RESET}"

    local response http_code body
    response=$(curl -s -w "\n%{http_code}" --max-time 15 \
        --request GET \
        --url "https://www.virustotal.com/api/v3/domains/$domain" \
        --header "x-apikey: $API_KEY" 2>/dev/null)

    http_code=$(echo "$response" | tail -1)
    # BUG FIX #2: head -n -1 is not portable (fails on macOS/BSD); use sed instead
    body=$(echo "$response" | sed '$d')

    if [[ "$http_code" != "200" ]]; then
        echo -e "  ${RED}[✘] API error — HTTP $http_code${RESET}"
        [[ "$http_code" == "401" ]] && echo -e "  ${AMBER}[!] Invalid API key${RESET}"
        [[ "$http_code" == "429" ]] && echo -e "  ${AMBER}[!] Rate limit exceeded — wait 60s${RESET}"
        VT_MALICIOUS=0; VT_SUSPICIOUS=0; VT_CLEAN=0
        return
    fi

    VT_MALICIOUS=$(echo  "$body" | jq -r '.data.attributes.last_analysis_stats.malicious'  2>/dev/null)
    VT_SUSPICIOUS=$(echo "$body" | jq -r '.data.attributes.last_analysis_stats.suspicious' 2>/dev/null)
    VT_CLEAN=$(echo      "$body" | jq -r '.data.attributes.last_analysis_stats.harmless'   2>/dev/null)
    VT_UNDETECTED=$(echo "$body" | jq -r '.data.attributes.last_analysis_stats.undetected' 2>/dev/null)
    VT_CATEGORIES=$(echo "$body" | jq -r '.data.attributes.categories | to_entries[] | .value' 2>/dev/null | sort -u | head -5 | tr '\n' ',')
    VT_REPUTATION=$(echo "$body" | jq -r '.data.attributes.reputation' 2>/dev/null)

    # BUG FIX #3: jq failures fall through as empty string, not "0"; guard all null/empty values
    [[ -z "$VT_MALICIOUS"  || "$VT_MALICIOUS"  == "null" ]] && VT_MALICIOUS=0
    [[ -z "$VT_SUSPICIOUS" || "$VT_SUSPICIOUS" == "null" ]] && VT_SUSPICIOUS=0
    [[ -z "$VT_CLEAN"      || "$VT_CLEAN"      == "null" ]] && VT_CLEAN=0
    [[ -z "$VT_UNDETECTED" || "$VT_UNDETECTED" == "null" ]] && VT_UNDETECTED=0
    [[ -z "$VT_REPUTATION" || "$VT_REPUTATION" == "null" ]] && VT_REPUTATION="N/A"

    printf "  ${G2}%-20s${RED}%s${RESET}\n"    "Malicious:"   "$VT_MALICIOUS engines"
    printf "  ${G2}%-20s${AMBER}%s${RESET}\n"  "Suspicious:"  "$VT_SUSPICIOUS engines"
    printf "  ${G2}%-20s${MATRIX}%s${RESET}\n" "Clean:"       "$VT_CLEAN engines"
    printf "  ${G2}%-20s${DIM}%s${RESET}\n"    "Undetected:"  "$VT_UNDETECTED engines"
    printf "  ${G2}%-20s${WHITE}%s${RESET}\n"  "Reputation:"  "$VT_REPUTATION"
    [[ -n "$VT_CATEGORIES" ]] && \
    printf "  ${G2}%-20s${DIM}%s${RESET}\n"    "Categories:"  "${VT_CATEGORIES%,}"
}

# ─────────────────────────────────────────
#  RISK SCORING ENGINE
# ─────────────────────────────────────────
calculate_risk() {
    local domain="$1"
    local score=0

    score=$((score + VT_MALICIOUS  * 15))
    score=$((score + VT_SUSPICIOUS * 5))

    if [[ "$CREATED" != "N/A" && -n "$CREATED" ]]; then
        local created_year current_year age
        # BUG FIX #4: grep -oP is not portable; use grep -oE which works on GNU+BSD
        created_year=$(echo "$CREATED" | grep -oE '^[0-9]{4}')
        current_year=$(date +%Y)
        # BUG FIX #5: arithmetic comparison requires numeric values; guard against empty
        if [[ -n "$created_year" ]]; then
            age=$((current_year - created_year))
            [[ $age -lt 1 ]] && score=$((score + 20))
            [[ $age -lt 2 ]] && score=$((score + 10))
        fi
    fi

    dig +short TXT "$domain"        2>/dev/null | grep -q "v=spf"   || score=$((score + 8))
    dig +short TXT "_dmarc.$domain" 2>/dev/null | grep -q "v=DMARC" || score=$((score + 8))

    [[ $score -gt 100 ]] && score=100
    RISK_SCORE=$score
}

# ─────────────────────────────────────────
#  VERDICT
# ─────────────────────────────────────────
show_verdict() {
    local domain="$1"
    section "THREAT VERDICT"

    calculate_risk "$domain"

    if   [[ $VT_MALICIOUS -gt 5   || $RISK_SCORE -ge 70 ]]; then
        RESULT="MALICIOUS"
        echo -e "  ${BLINK}${RED}╔══════════════════════════════════════╗${RESET}"
        echo -e "  ${RED}║  ⚠  VERDICT : MALICIOUS DOMAIN  ⚠   ║${RESET}"
        echo -e "  ${BLINK}${RED}╚══════════════════════════════════════╝${RESET}"
    elif [[ $VT_MALICIOUS -gt 0   || $VT_SUSPICIOUS -gt 3 || $RISK_SCORE -ge 40 ]]; then
        RESULT="SUSPICIOUS"
        echo -e "  ${AMBER}╔══════════════════════════════════════╗${RESET}"
        echo -e "  ${AMBER}║  ⚡  VERDICT : SUSPICIOUS DOMAIN  ⚡  ║${RESET}"
        echo -e "  ${AMBER}╚══════════════════════════════════════╝${RESET}"
    else
        RESULT="CLEAN"
        echo -e "  ${MATRIX}╔══════════════════════════════════════╗${RESET}"
        echo -e "  ${MATRIX}║  ✔   VERDICT : DOMAIN IS CLEAN   ✔   ║${RESET}"
        echo -e "  ${MATRIX}╚══════════════════════════════════════╝${RESET}"
    fi

    echo
    local filled=$(( RISK_SCORE / 5 ))
    local empty=$(( 20 - filled ))
    local bar_color="${MATRIX}"
    [[ $RISK_SCORE -ge 40 ]] && bar_color="${AMBER}"
    [[ $RISK_SCORE -ge 70 ]] && bar_color="${RED}"

    printf "  ${G2}Risk Score  : ${bar_color}["
    printf '%0.s█' $(seq 1 $filled)
    printf '%0.s░' $(seq 1 $empty)
    printf "] %d/100${RESET}\n" "$RISK_SCORE"

    printf "  ${G2}%-20s${WHITE}%s${RESET}\n" "Domain:"     "$domain"
    printf "  ${G2}%-20s${WHITE}%s${RESET}\n" "IP Address:" "${IP_ADDRESS:-N/A}"
    printf "  ${G2}%-20s${WHITE}%s${RESET}\n" "Result:"     "$RESULT"
}

# ─────────────────────────────────────────
#  EXPORT REPORT
# ─────────────────────────────────────────
export_report() {
    local domain="$1"
    local fname
    fname="$REPORT_DIR/domain_${domain//\./_}_$(date +%Y%m%d_%H%M%S).txt"

    {
        echo "============================================================"
        echo "  HYBRID CYBERSECURITY ENGINE — DOMAIN CHECKER REPORT"
        echo "  Generated : $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Operator  : ${OPERATOR:-unknown}"
        echo "  Domain    : $domain"
        echo "============================================================"
        echo ""
        echo "WHOIS"
        echo "  Registrar   : $REGISTRAR"
        echo "  Created     : $CREATED"
        echo "  Expires     : $EXPIRES"
        echo ""
        echo "DNS"
        echo "  IP Address  : ${IP_ADDRESS:-N/A}"
        echo ""
        echo "VIRUSTOTAL"
        echo "  Malicious   : $VT_MALICIOUS engines"
        echo "  Suspicious  : $VT_SUSPICIOUS engines"
        echo "  Clean       : $VT_CLEAN engines"
        echo ""
        echo "VERDICT"
        echo "  Result      : $RESULT"
        echo "  Risk Score  : $RISK_SCORE / 100"
        echo "============================================================"
    } > "$fname"

    echo -e "\n  ${MATRIX}[✔]${RESET} Report saved: ${WHITE}$fname${RESET}"
}

# ─────────────────────────────────────────
#  VIEW HISTORY
# ─────────────────────────────────────────
view_history() {
    section "RECENT SCAN HISTORY (last 10)"
    sqlite3 -column -header "$DB_FILE" \
        "SELECT id, domain, result, risk_score, timestamp
         FROM domain_logs ORDER BY id DESC LIMIT 10;" 2>/dev/null \
    | while IFS= read -r line; do
        if echo "$line" | grep -q "MALICIOUS"; then
            echo -e "  ${RED}$line${RESET}"
        elif echo "$line" | grep -q "SUSPICIOUS"; then
            echo -e "  ${AMBER}$line${RESET}"
        else
            echo -e "  ${G2}$line${RESET}"
        fi
    done
    echo
    echo -ne "${AMBER}  Press ENTER to continue...${RESET}"; read -r
}

# ─────────────────────────────────────────
#  MAIN SCAN FLOW
# ─────────────────────────────────────────
run_scan() {
    local domain="$1"

    if ! validate_domain "$domain"; then
        echo -e "${RED}  [✘] Invalid domain format: $domain${RESET}"
        echo -e "${DIM}      Example: example.com / sub.example.co.uk${RESET}"
        return 1
    fi

    echo -e "\n${MATRIX}[▸]${RESET} Target: ${WHITE}$domain${RESET}\n"

    VT_MALICIOUS=0; VT_SUSPICIOUS=0; VT_CLEAN=0
    VT_UNDETECTED=0; VT_CATEGORIES=""; VT_REPUTATION="N/A"
    IP_ADDRESS="N/A"; REGISTRAR="N/A"; CREATED="N/A"
    EXPIRES="N/A"; RESULT="CLEAN"; RISK_SCORE=0

    run_whois      "$domain"
    run_dns        "$domain"
    run_virustotal "$domain"
    show_verdict   "$domain"

    save_to_db "$domain" "$IP_ADDRESS" "$REGISTRAR" "$CREATED" "$EXPIRES" \
               "$VT_MALICIOUS" "$VT_SUSPICIOUS" "$VT_CLEAN" \
               "$RESULT" "$RISK_SCORE" "${OPERATOR:-unknown}"

    divider
    echo -e "  ${MATRIX}[✔]${RESET} Result saved to database."

    # BUG FIX #6: \c is not portable in echo -e for suppressing newline; use printf or echo -n
    echo -ne "\n  ${CYAN}[?]${RESET} Export report to file? ${AMBER}(y/n)${RESET}: "
    read -r export_choice
    [[ "$export_choice" =~ ^[Yy]$ ]] && export_report "$domain"
}

# ─────────────────────────────────────────
#  POST-SCAN MENU
# ─────────────────────────────────────────
post_scan_menu() {
    echo
    echo -e "${MATRIX}╔═══════════════════════════════╗${RESET}"
    echo -e "${MATRIX}║   WHAT DO YOU WANT TO DO?     ║${RESET}"
    echo -e "${MATRIX}╠═══════════════════════════════╣${RESET}"
    echo -e "${MATRIX}║ ${WHITE}[1]${MATRIX} Scan another domain        ║${RESET}"
    echo -e "${MATRIX}║ ${WHITE}[2]${MATRIX} View scan history           ║${RESET}"
    echo -e "${MATRIX}║ ${WHITE}[3]${MATRIX} Return to main menu         ║${RESET}"
    echo -e "${MATRIX}║ ${WHITE}[4]${MATRIX} Exit                        ║${RESET}"
    echo -e "${MATRIX}╚═══════════════════════════════╝${RESET}"
    echo -ne "${AMBER}  Choose [1-4]: ${RESET}"
}

# ─────────────────────────────────────────
#  MAIN LOOP
# ─────────────────────────────────────────
domain_checker() {
    show_banner
    log_tool_run

    while true; do
        echo -e "${MATRIX}[▸]${AMBER} Enter domain to scan ${DIM}(or 'history' / 'exit')${RESET}"
        # BUG FIX #1 (usage): $GREEN was referenced here but not defined — now defined above
        echo -ne "${MATRIX}  ➜ ${GREEN}"
        read -r domain
        echo -ne "${RESET}"

        case "$domain" in
            exit|quit|q)
                echo -e "\n${CYAN}[▸] Returning to main menu...${RESET}\n"
                [[ -f "./menu.sh" ]] && ./menu.sh
                exit 0
                ;;
            history)
                view_history
                continue
                ;;
            "")
                echo -e "${RED}  [✘] No domain entered.${RESET}"
                continue
                ;;
        esac

        run_scan "$domain"

        post_scan_menu
        read -r choice
        case "$choice" in
            1)  show_banner ;;
            2)  view_history ;;
            3)
                echo -e "\n${CYAN}[▸] Returning to main menu...${RESET}\n"
                [[ -f "./menu.sh" ]] && ./menu.sh
                exit 0
                ;;
            4)
                echo -e "\n${MATRIX}[▸] Session terminated. Goodbye, ${OPERATOR:-operator}.${RESET}\n"
                exit 0
                ;;
            *)
                echo -e "${RED}  [✘] Invalid choice.${RESET}"
                show_banner
                ;;
        esac
    done
}

# ─────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────
OPERATOR="${1:-unknown}"

check_deps
init_env
domain_checker