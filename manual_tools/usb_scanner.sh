#!/bin/bash
# ====================================
# Hybrid USB Scanner Tool - Main DB Version
# Author: GANGULI
# ====================================

# -------------------
# Configurations
# -------------------
TOOL_NAME="Hybrid USB Scanner"
AUTHOR="SABINAS"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BASE_DIR="$PROJECT_ROOT/reports/usb_scanner"
AUTO_REPORT_DIR="$BASE_DIR/autoreport"
MANUAL_REPORT_DIR="$BASE_DIR/manualreport"
DB_FILE="$PROJECT_ROOT/database/hybrid_vas.db"

# Colors
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
CYAN="\e[36m"
RESET="\e[0m"

# -------------------
# Dependency Check
# -------------------
install_dependencies() {
    echo -e "${CYAN}[INFO] Checking dependencies...${RESET}"
    local missing=()

    command -v lsblk >/dev/null 2>&1 || missing+=("util-linux")
    command -v findmnt >/dev/null 2>&1 || missing+=("util-linux")
    command -v clamscan >/dev/null 2>&1 || missing+=("clamav")
    command -v python3 >/dev/null 2>&1 || missing+=("python3")
    command -v sqlite3 >/dev/null 2>&1 || missing+=("sqlite3")
    python3 - <<'EOF' >/dev/null 2>&1 || missing+=("python3-reportlab")
import reportlab
EOF

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${RED}[ERROR] Missing dependencies: ${missing[*]}${RESET}"
        echo -e "${YELLOW}[INFO] Install on Debian/Kali/Ubuntu with:${RESET}"
        echo "sudo apt-get install -y util-linux clamav python3 python3-reportlab sqlite3"
        exit 1
    fi

    echo -e "${GREEN}[INFO] Dependencies ready.${RESET}"
}
install_dependencies

# -------------------
# Create directories and DB tables
# -------------------
mkdir -p "$AUTO_REPORT_DIR" "$MANUAL_REPORT_DIR" "$(dirname "$DB_FILE")"

sqlite3 "$DB_FILE" <<EOF
CREATE TABLE IF NOT EXISTS usb_scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    INTEGER,
    usb_name      TEXT,
    device_path   TEXT,
    files_scanned INTEGER DEFAULT 0,
    threats_found INTEGER DEFAULT 0,
    result        TEXT,
    operator      TEXT,
    timestamp     TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS usb_file_results (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id        INTEGER REFERENCES usb_scans(id),
    file_name      TEXT,
    file_path      TEXT,
    sha256         TEXT,
    result         TEXT,
    malware_family TEXT
);
EOF

for column_def in \
    "session_id INTEGER" \
    "device_path TEXT" \
    "files_scanned INTEGER DEFAULT 0" \
    "threats_found INTEGER DEFAULT 0" \
    "operator TEXT"; do
    column_name="${column_def%% *}"
    if ! sqlite3 "$DB_FILE" "PRAGMA table_info(usb_scans);" | awk -F'|' '{print $2}' | grep -qx "$column_name"; then
        sqlite3 "$DB_FILE" "ALTER TABLE usb_scans ADD COLUMN $column_def;"
    fi
done

# -------------------
# Banner
# -------------------
banner() {
    echo -e "${CYAN}"
    echo "====================================="
    echo "        $TOOL_NAME"
    echo "        Author: $AUTHOR"
    echo "        $(date)"
    echo "====================================="
    echo -e "${RESET}"
}

# -------------------
# Helpers
# -------------------
sql_escape() {
    printf "%s" "${1//\'/\'\'}"
}

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1 && [[ -f "$1" ]]; then
        sha256sum "$1" | awk '{print $1}'
    else
        printf ""
    fi
}

print_scan_header() {
    local usb_name="$1"
    local mountpoint="$2"
    local device_path="$3"

    echo "Device: $usb_name"
    echo "Path: $mountpoint"
    echo "Drive: $device_path"
}

summarize_results() {
    clean_count=0
    threat_count=0
    error_count=0
    overall="Clean"

    for r in "${SCAN_RESULTS[@]}"; do
        if [[ "$r" == *"|Malicious"* ]]; then
            ((threat_count++))
            overall="Issues Found"
        elif [[ "$r" == *"|Error"* ]]; then
            ((error_count++))
        else
            ((clean_count++))
        fi
    done

    files_scanned=$((clean_count + threat_count + error_count))
    echo -e "${YELLOW}[INFO] Results : ${GREEN}${clean_count} clean${RESET}  ${RED}${threat_count} threat(s)${RESET}  ${YELLOW}${error_count} error(s)${RESET}"
    echo "$files_scanned files scanned"
    echo "$threat_count threat(s) found"
}

print_verdict() {
    if [[ "$overall" == "Issues Found" ]]; then
        echo "VERDICT : THREAT DETECTED - malicious files found on USB device"
    else
        echo "VERDICT : USB DEVICE IS CLEAN - no threats detected"
    fi
}

# -------------------
# Detect mounted USB drives
# -------------------
detect_usb() {
    USB_LIST=()
    USB_DEVICES=()
    USB_LABELS=()

    while IFS='|' read -r name tran type mountpoint label; do
        [[ "$type" == "part" || "$type" == "disk" ]] || continue
        [[ "$tran" == "usb" ]] || continue
        [[ -n "$mountpoint" ]] || continue

        USB_LIST+=("$mountpoint")
        USB_DEVICES+=("$name")
        USB_LABELS+=("${label:-USB Device}")
    done < <(lsblk -lnp -o NAME,TRAN,TYPE,MOUNTPOINT,LABEL -P | awk '
        {
            name=tran=type=mount=label="";
            for (i=1; i<=NF; i++) {
                split($i, kv, "=");
                gsub(/^"|"$/, "", kv[2]);
                if (kv[1] == "NAME") name=kv[2];
                if (kv[1] == "TRAN") tran=kv[2];
                if (kv[1] == "TYPE") type=kv[2];
                if (kv[1] == "MOUNTPOINT") mount=kv[2];
                if (kv[1] == "LABEL") label=kv[2];
            }
            print name "|" tran "|" type "|" mount "|" label;
        }')
}

# -------------------
# Quick Scan
# -------------------
quick_scan() {
    local usb_path="$1"
    SCAN_RESULTS=()

    mapfile -t files < <(find "$usb_path" -type f 2>/dev/null)
    local total=${#files[@]}
    local idx=0

    echo -e "${CYAN}[INFO] Files to scan : $total${RESET}"

    for f in "${files[@]}"; do
        ((idx++))
        echo -ne "${CYAN}[SCAN] ($idx/$total) ${f##*/} ...${RESET}   \r"
        clamscan --no-summary "$f" >/dev/null 2>&1
        status=$?

        if [[ $status -eq 0 ]]; then
            SCAN_RESULTS+=("$f|Clean")
            echo "File: $f CLEAN"
        elif [[ $status -eq 1 ]]; then
            echo -e "${RED}[THREAT] ${f##*/} - INFECTED                              ${RESET}"
            SCAN_RESULTS+=("$f|Malicious")
            echo "File: $f INFECTED"
        else
            echo -e "${YELLOW}[WARN] ${f##*/} - scan error                              ${RESET}"
            SCAN_RESULTS+=("$f|Error")
            echo "File: $f ERROR"
        fi
    done

    echo -e "${GREEN}[INFO] $idx files scanned.                    ${RESET}"
}

# -------------------
# Deep Scan
# -------------------
deep_scan() {
    local usb_path="$1"
    local device
    local fs_type
    local temp_dir

    SCAN_RESULTS=()

    mapfile -t files < <(find "$usb_path" -type f 2>/dev/null)
    local total=${#files[@]}
    local idx=0

    echo -e "${CYAN}[INFO] Files to scan : $total${RESET}"

    for f in "${files[@]}"; do
        ((idx++))
        echo -ne "${CYAN}[SCAN] ($idx/$total) ${f##*/} ...${RESET}   \r"
        clamscan --no-summary "$f" >/dev/null 2>&1
        status=$?

        if [[ $status -eq 0 ]]; then
            SCAN_RESULTS+=("$f|Clean|No|-")
            echo "File: $f CLEAN"
        elif [[ $status -eq 1 ]]; then
            echo -e "${RED}[THREAT] ${f##*/} - INFECTED                              ${RESET}"
            SCAN_RESULTS+=("$f|Malicious|No|-")
            echo "File: $f INFECTED"
        else
            echo -e "${YELLOW}[WARN] ${f##*/} - scan error                              ${RESET}"
            SCAN_RESULTS+=("$f|Error|No|-")
            echo "File: $f ERROR"
        fi
    done

    echo -e "${GREEN}[INFO] $idx files scanned.               ${RESET}"

    device=$(findmnt -n -o SOURCE "$usb_path")
    fs_type=$(findmnt -n -o FSTYPE "$usb_path")

    if [[ -n "$device" && "$fs_type" =~ ^ext[234]$ && -x "$(command -v extundelete)" ]]; then
        temp_dir=$(mktemp -d)
        sudo extundelete "$device" --restore-all --output-dir "$temp_dir" >/dev/null 2>&1
        while IFS= read -r -d '' del_file; do
            SCAN_RESULTS+=("$del_file|Recovered|Yes|$(date '+%Y-%m-%d %H:%M:%S')")
        done < <(find "$temp_dir" -type f -print0 2>/dev/null)
        rm -rf "$temp_dir"
    elif [[ -n "$device" ]]; then
        echo -e "${YELLOW}[INFO] Deleted-file recovery skipped for filesystem: ${fs_type:-unknown}${RESET}"
    fi
}

# -------------------
# Generate PDF
# -------------------
generate_pdf_report() {
    local usb_name="$1"
    local scan_type="$2"
    local report_dir="$3"
    local timestamp
    local report_file
    local tmp_results

    timestamp=$(date '+%Y-%m-%d_%H-%M-%S')
    report_file="$report_dir/${usb_name##*/}_${timestamp}_scan_report.pdf"
    tmp_results=$(mktemp)

    for r in "${SCAN_RESULTS[@]}"; do
        echo "$r" >> "$tmp_results"
    done

    python3 <<EOF
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

c = canvas.Canvas("$report_file", pagesize=letter)
width, height = letter
c.setFont("Helvetica-Bold", 16)
c.drawString(30, height - 40, "USB Scan Report")
c.setFont("Helvetica", 12)
c.drawString(30, height - 60, "USB: $usb_name")
c.drawString(30, height - 80, "Scan Mode: $scan_type")
c.drawString(30, height - 100, "Timestamp: $(date)")

y = height - 140
with open("$tmp_results", encoding="utf-8", errors="replace") as f:
    for line in f:
        parts = line.strip().split("|")
        if "$scan_type" == "Manual Deep":
            while len(parts) < 4:
                parts.append("-")
            text_line = f"{parts[0]:40} {parts[1]:10} {parts[2]:10} {parts[3]}"
        else:
            while len(parts) < 2:
                parts.append("-")
            text_line = f"{parts[0]:40} {parts[1]}"
        c.drawString(30, y, text_line[:120])
        y -= 12
        if y < 40:
            c.showPage()
            c.setFont("Helvetica", 12)
            y = height - 40

c.save()
EOF

    rm -f "$tmp_results"
    echo -e "${GREEN}PDF report generated: $report_file${RESET}"
}

# -------------------
# Log to Main DB
# -------------------
log_to_db() {
    [[ "${HCE_GUI_CAPTURE:-0}" == "1" ]] && return 0

    local usb_name="$1"
    local device_path="$2"
    local scanned="$3"
    local threats="$4"
    local result="$5"
    local escaped_usb
    local escaped_device
    local escaped_result
    local scan_id

    escaped_usb=$(sql_escape "$usb_name")
    escaped_device=$(sql_escape "$device_path")
    escaped_result=$(sql_escape "$result")

    scan_id=$(sqlite3 "$DB_FILE" <<EOF
INSERT INTO usb_scans (usb_name, device_path, files_scanned, threats_found, result, operator)
VALUES ('$escaped_usb', '$escaped_device', $scanned, $threats, '$escaped_result', '${USER:-}');
SELECT last_insert_rowid();
EOF
)

    for r in "${SCAN_RESULTS[@]}"; do
        IFS='|' read -r file_path file_result _ <<< "$r"
        [[ -n "$file_path" ]] || continue

        local file_name
        local hash
        local escaped_file_name
        local escaped_file_path
        local escaped_file_result

        file_name="${file_path##*/}"
        hash=$(sha256_file "$file_path")
        escaped_file_name=$(sql_escape "$file_name")
        escaped_file_path=$(sql_escape "$file_path")
        escaped_file_result=$(sql_escape "$file_result")

        sqlite3 "$DB_FILE" <<EOF
INSERT INTO usb_file_results (scan_id, file_name, file_path, sha256, result, malware_family)
VALUES ($scan_id, '$escaped_file_name', '$escaped_file_path', '$hash', '$escaped_file_result', NULL);
EOF
    done
}

# -------------------
# Automatic Scan
# -------------------
automatic_scan() {
    banner
    echo -e "${YELLOW}Detecting USB drives for automatic scan...${RESET}"
    detect_usb
    [[ ${#USB_LIST[@]} -eq 0 ]] && { echo -e "${RED}No mounted USB drives detected.${RESET}"; return; }

    overall="Clean"

    for idx in "${!USB_LIST[@]}"; do
        usb="${USB_LIST[$idx]}"
        device="${USB_DEVICES[$idx]}"
        usb_name="${USB_LABELS[$idx]}"

        print_scan_header "$usb_name" "$usb" "$device"
        echo -e "${CYAN}[INFO] Scanning $usb (Quick Scan)${RESET}"
        quick_scan "$usb"
        summarize_results
        generate_pdf_report "$usb_name" "Automatic Quick" "$AUTO_REPORT_DIR"
        log_to_db "$usb_name" "$device" "$files_scanned" "$threat_count" "$overall"
    done

    echo ""
    print_verdict
}

# -------------------
# Manual Scan
# -------------------
manual_scan() {
    while true; do
        banner
        echo -e "${YELLOW}Detecting USB drives for manual scan...${RESET}"
        detect_usb
        [[ ${#USB_LIST[@]} -eq 0 ]] && { echo -e "${RED}No mounted USB drives detected.${RESET}"; return; }

        echo "Detected USB drives:"
        i=1
        for idx in "${!USB_LIST[@]}"; do
            echo "$i) ${USB_LABELS[$idx]} - ${USB_LIST[$idx]} (${USB_DEVICES[$idx]})"
            ((i++))
        done
        echo "0) Exit to tools menu"

        read -p "Select a USB to scan (0-${#USB_LIST[@]}): " choice
        [[ "$choice" =~ ^[0-9]+$ ]] || { echo -e "${RED}Invalid choice.${RESET}"; continue; }
        [[ "$choice" -eq 0 ]] && return
        [[ "$choice" -ge 1 && "$choice" -le ${#USB_LIST[@]} ]] || { echo -e "${RED}Invalid choice.${RESET}"; continue; }

        selected=$((choice - 1))
        usb="${USB_LIST[$selected]}"
        device="${USB_DEVICES[$selected]}"
        usb_name="${USB_LABELS[$selected]}"

        print_scan_header "$usb_name" "$usb" "$device"

        read -p "Choose scan type (quick/deep): " scan_mode
        scan_mode=$(echo "$scan_mode" | tr '[:upper:]' '[:lower:]')

        if [[ "$scan_mode" == "quick" ]]; then
            quick_scan "$usb"
            summarize_results
            generate_pdf_report "$usb_name" "Manual Quick" "$MANUAL_REPORT_DIR"
            log_to_db "$usb_name" "$device" "$files_scanned" "$threat_count" "$overall"
            print_verdict
        elif [[ "$scan_mode" == "deep" ]]; then
            deep_scan "$usb"
            summarize_results
            generate_pdf_report "$usb_name" "Manual Deep" "$MANUAL_REPORT_DIR"
            log_to_db "$usb_name" "$device" "$files_scanned" "$threat_count" "$overall"
            print_verdict
        else
            echo -e "${RED}Invalid scan type. Try again.${RESET}"
        fi
    done
}

# -------------------
# Main Menu
# -------------------
while true; do
    banner
    echo -e "${YELLOW}Select an option:${RESET}"
    echo "1) Automatic USB Scan"
    echo "2) Manual USB Scan"
    echo "3) Exit (Tools Menu)"
    read -p "Enter choice: " main_choice

    case $main_choice in
        1) automatic_scan ;;
        2) manual_scan ;;
        3) echo -e "${GREEN}Exiting to tools menu...${RESET}"; exit 0 ;;
        *) echo -e "${RED}Invalid choice. Try again.${RESET}" ;;
    esac
done
