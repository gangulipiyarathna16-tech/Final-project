#!/bin/bash
# ====================================
# Hybrid USB Scanner Tool - Main DB Version
# Author: SABINAS
# ====================================

# -------------------
# Configurations
# -------------------
TOOL_NAME="Hybrid USB Scanner"
AUTHOR="SABINAS"
BASE_DIR="$HOME/hybrid_vas/manual_tools/usb_scanner"
AUTO_REPORT_DIR="$BASE_DIR/autoreport"
MANUAL_REPORT_DIR="$BASE_DIR/manualreport"
DB_FILE="$HOME/hybrid_vas/database/hybrid_vas.db"  # Main database

# Colors
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
CYAN="\e[36m"
RESET="\e[0m"

# -------------------
# Dependency Check & Install
# -------------------
install_dependencies() {
    echo -e "${CYAN}Checking and installing dependencies...${RESET}"
    sudo apt-get update -y
    dpkg -l | grep clamav >/dev/null 2>&1 || sudo apt-get install -y clamav clamav-daemon
    dpkg -l | grep extundelete >/dev/null 2>&1 || sudo apt-get install -y extundelete
    dpkg -l | grep python3 >/dev/null 2>&1 || sudo apt-get install -y python3
    dpkg -l | grep python3-reportlab >/dev/null 2>&1 || sudo apt-get install -y python3-reportlab
    dpkg -l | grep jq >/dev/null 2>&1 || sudo apt-get install -y jq
}
install_dependencies

# -------------------
# Create directories
# -------------------
mkdir -p "$AUTO_REPORT_DIR" "$MANUAL_REPORT_DIR"

# -------------------
# Create table in main DB if missing
# -------------------
sqlite3 "$DB_FILE" <<EOF
CREATE TABLE IF NOT EXISTS usb_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usb_name TEXT,
    scan_mode TEXT,
    quick_or_deep TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    result TEXT
);
EOF

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
# Detect USB drives
# -------------------
detect_usb() {
    USB_LIST=($(lsblk -lnp -o NAME,TYPE | awk '$2=="part"{print $1}' | head -n3))
}

# -------------------
# Quick Scan
# -------------------
quick_scan() {
    local usb_path="$1"
    SCAN_RESULTS=()
    mapfile -t files < <(find "$usb_path" -type f 2>/dev/null)
    for f in "${files[@]}"; do
        clamscan --no-summary "$f" >/dev/null
        status=$?
        [[ $status -eq 0 ]] && SCAN_RESULTS+=("$f|Clean") || SCAN_RESULTS+=("$f|Malicious")
    done
}

# -------------------
# Deep Scan
# -------------------
deep_scan() {
    local usb_path="$1"
    SCAN_RESULTS=()
    # Quick scan first
    mapfile -t files < <(find "$usb_path" -type f 2>/dev/null)
    for f in "${files[@]}"; do
        clamscan --no-summary "$f" >/dev/null
        status=$?
        [[ $status -eq 0 ]] && SCAN_RESULTS+=("$f|Clean|No|-") || SCAN_RESULTS+=("$f|Malicious|No|-")
    done
    # Deleted files detection
    device=$(findmnt -n -o SOURCE "$usb_path")
    if [[ -n "$device" ]]; then
        temp_dir=$(mktemp -d)
        sudo extundelete "$device" --restore-directory "$usb_path" --output-dir "$temp_dir" >/dev/null 2>&1
        if [[ -d "$temp_dir" ]]; then
            deleted_files=$(find "$temp_dir" -type f)
            for del_file in $deleted_files; do
                SCAN_RESULTS+=("$del_file|Recovered|Yes|$(date '+%Y-%m-%d %H:%M:%S')")
            done
        fi
        rm -rf "$temp_dir"
    fi
}

# -------------------
# Generate PDF
# -------------------
generate_pdf_report() {
    local usb_name="$1"
    local scan_type="$2"
    local report_dir="$3"
    local timestamp=$(date '+%Y-%m-%d_%H-%M-%S')
    local report_file="$report_dir/${usb_name##*/}_${timestamp}_scan_report.pdf"

    tmp_results=$(mktemp)
    for r in "${SCAN_RESULTS[@]}"; do echo "$r" >> "$tmp_results"; done

    python3 <<EOF
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

c = canvas.Canvas("$report_file", pagesize=letter)
width, height = letter
c.setFont("Helvetica-Bold", 16)
c.drawString(30, height-40, "USB Scan Report")
c.setFont("Helvetica", 12)
c.drawString(30, height-60, "USB: $usb_name")
c.drawString(30, height-80, "Scan Mode: $scan_type")
c.drawString(30, height-100, "Timestamp: $(date)")

y = height-140
with open("$tmp_results") as f:
    for line in f:
        parts = line.strip().split("|")
        if "$scan_type" == "Manual Deep":
            text_line = f"{parts[0]:40} {parts[1]:10} {parts[2]:10} {parts[3]}"
        else:
            text_line = f"{parts[0]:40} {parts[1]}"
        c.drawString(30, y, text_line)
        y -= 12

c.save()
EOF

    rm "$tmp_results"
    echo -e "${GREEN}PDF report generated: $report_file${RESET}"
}

# -------------------
# Log to Main DB (fixed)
# -------------------
log_to_db() {
    local usb_name="$1"
    local scan_mode="$2"
    local quick_or_deep="$3"
    local result="$4"

    # Escape single quotes
    usb_name="${usb_name//\'/\'\'}"
    scan_mode="${scan_mode//\'/\'\'}"
    quick_or_deep="${quick_or_deep//\'/\'\'}"
    result="${result//\'/\'\'}"

    sqlite3 "$DB_FILE" <<EOF
INSERT INTO usb_scans (usb_name, scan_mode, quick_or_deep, result)
VALUES ('$usb_name', '$scan_mode', '$quick_or_deep', '$result');
EOF
}

# -------------------
# Automatic Scan
# -------------------
automatic_scan() {
    banner
    echo -e "${YELLOW}Detecting USB drives for automatic scan...${RESET}"
    detect_usb
    [[ ${#USB_LIST[@]} -eq 0 ]] && { echo -e "${RED}No USB drives detected.${RESET}"; return; }
    for usb in "${USB_LIST[@]}"; do
        echo -e "${CYAN}Scanning $usb (Quick Scan)${RESET}"
        quick_scan "$usb"
        generate_pdf_report "$usb" "Automatic Quick" "$AUTO_REPORT_DIR"
        overall="Clean"
        for r in "${SCAN_RESULTS[@]}"; do [[ "$r" == *Malicious* ]] && overall="Issues Found"; done
        log_to_db "$usb" "Automatic" "Quick" "$overall"
    done
    echo -e "${GREEN}Automatic scan complete. Returning to main menu.${RESET}"
}

# -------------------
# Manual Scan
# -------------------
manual_scan() {
    while true; do
        banner
        echo -e "${YELLOW}Detecting USB drives for manual scan...${RESET}"
        detect_usb
        [[ ${#USB_LIST[@]} -eq 0 ]] && { echo -e "${RED}No USB drives detected.${RESET}"; return; }
        echo "Detected USB drives:"
        i=1
        for usb in "${USB_LIST[@]}"; do echo "$i) $usb"; ((i++)); done
        echo "0) Exit to tools menu"
        read -p "Select a USB to scan (0-${#USB_LIST[@]}): " choice
        [[ "$choice" -eq 0 ]] && return
        [[ "$choice" -ge 1 && "$choice" -le ${#USB_LIST[@]} ]] || { echo -e "${RED}Invalid choice.${RESET}"; continue; }
        usb="${USB_LIST[$((choice-1))]}"
        read -p "Choose scan type (quick/deep): " scan_mode
        scan_mode=$(echo "$scan_mode" | tr '[:upper:]' '[:lower:]')
        if [[ "$scan_mode" == "quick" ]]; then
            quick_scan "$usb"
            generate_pdf_report "$usb" "Manual Quick" "$MANUAL_REPORT_DIR"
            overall="Clean"
            for r in "${SCAN_RESULTS[@]}"; do [[ "$r" == *Malicious* ]] && overall="Issues Found"; done
            log_to_db "$usb" "Manual" "Quick" "$overall"
        elif [[ "$scan_mode" == "deep" ]]; then
            deep_scan "$usb"
            generate_pdf_report "$usb" "Manual Deep" "$MANUAL_REPORT_DIR"
            overall="Clean"
            for r in "${SCAN_RESULTS[@]}"; do [[ "$r" == *Malicious* ]] && overall="Issues Found"; done
            log_to_db "$usb" "Manual" "Deep" "$overall"
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
