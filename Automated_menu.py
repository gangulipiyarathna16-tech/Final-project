#!/usr/bin/env python3
"""
Hybrid Cybersecurity Engine — CLI Entry Point
Launch: python3 Automated_menu.py
"""
import importlib
import subprocess
import sys
from pathlib import Path

DEPENDENCIES = ["InquirerPy", "rich"]

def in_virtualenv():
    return (
        hasattr(sys, "real_prefix")
        or (hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix)
    )

def ensure_dependencies():
    missing = []
    for dep in DEPENDENCIES:
        try:
            importlib.import_module(dep)
        except ImportError:
            missing.append(dep)
    if missing:
        print(f"[setup] Installing missing packages: {', '.join(missing)}")
        flag = [] if in_virtualenv() else ["--user"]
        subprocess.check_call([sys.executable, "-m", "pip", "install", *flag, *missing])

ensure_dependencies()

from InquirerPy import inquirer
from InquirerPy.base.control import Choice
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()

# ── Paths ────────────────────────────────────────────────────
ROOT        = Path(__file__).resolve().parent
SCRIPTS_DIR = ROOT / "automated_tools" / "malware_scan" / "scripts"
MANUAL_DIR  = ROOT / "manual_tools"

SCRIPT_MAP = {
    "url"     : ("bash",         MANUAL_DIR  / "Domain-1.sh"),
    "domain"  : ("bash",         MANUAL_DIR  / "Domain_checker.sh"),
    "port"    : ("bash",         MANUAL_DIR  / "port_scanner.sh"),
    "net"     : ("bash",         MANUAL_DIR  / "network_scanner.sh"),
    "usb"     : ("bash",         MANUAL_DIR  / "usb_scanner.sh"),
    "fuzz"    : (sys.executable, MANUAL_DIR  / "Fuzzing_tool.py"),
    "malware" : (sys.executable, SCRIPTS_DIR / "malware_scan_engine.py"),
    "backdoor": (sys.executable, ROOT / "automated_tools" / "backdoor_scanner.py"),
    "vuln"    : (sys.executable, ROOT / "automated_tools" / "vuln_scanner.py"),
}

# ── Runner ───────────────────────────────────────────────────
def run_tool(tool_id):
    if tool_id not in SCRIPT_MAP:
        console.print(f"[red][!] Unknown tool: {tool_id}[/red]")
        return

    interpreter, script = SCRIPT_MAP[tool_id]
    script = Path(script)

    if not script.exists():
        console.print(f"[red][!] Script not found: {script}[/red]")
        return

    console.rule(f"[bold cyan]{tool_id.upper()}[/bold cyan]")
    try:
        subprocess.run([interpreter, str(script)], check=False)
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Interrupted.[/yellow]")
    except FileNotFoundError:
        console.print(f"[red][!] Interpreter '{interpreter}' not found.[/red]")

def run_full_scan():
    console.print(Panel(
        "[bold cyan]Full Automated Scan[/bold cyan] — Backdoor → Vuln → Malware",
        expand=False,
    ))
    run_tool("backdoor")

    target = inquirer.text(
        message="Vuln scan — target IP/Host:",
        default="192.168.1.1",
    ).execute().strip()
    if target:
        _, script = SCRIPT_MAP["vuln"]
        console.rule("[bold cyan]VULN[/bold cyan]")
        subprocess.run([sys.executable, str(script), target], check=False)

    file_path = inquirer.text(
        message="Malware scan — file or directory path:",
        default=str(Path.home() / "Downloads"),
    ).execute().strip()
    if file_path:
        _, script = SCRIPT_MAP["malware"]
        console.rule("[bold cyan]MALWARE[/bold cyan]")
        subprocess.run([sys.executable, str(script), file_path], check=False)

def customize_scans():
    selected = inquirer.checkbox(
        message="Select tools to run (Space to toggle, Enter to confirm):",
        choices=[
            Choice("url",      name="URL Scanner           (Domain-1.sh)"),
            Choice("domain",   name="Domain Checker        (Domain_checker.sh)"),
            Choice("port",     name="Port Scanner          (port_scanner.sh)"),
            Choice("net",      name="Network Scanner       (network_scanner.sh)"),
            Choice("usb",      name="USB Scanner           (usb_scanner.sh)"),
            Choice("fuzz",     name="Fuzzing Tool          (Fuzzing_tool.py)"),
            Choice("malware",  name="Malware Detector      (malware_scan_engine.py)"),
            Choice("backdoor", name="Backdoor Scanner      (backdoor_scanner.py)"),
            Choice("vuln",     name="Vulnerability Scanner (vuln_scanner.py)"),
        ],
    ).execute()

    if not selected:
        console.print("[yellow]No tools selected.[/yellow]")
        return

    for tool_id in selected:
        run_tool(tool_id)

def manual_tools_menu():
    while True:
        choice = inquirer.select(
            message="Manual Tools — select a tool:",
            choices=[
                Choice("url",    "URL Scanner           (Domain-1.sh)"),
                Choice("domain", "Domain Checker        (Domain_checker.sh)"),
                Choice("port",   "Port Scanner          (port_scanner.sh)"),
                Choice("net",    "Network Scanner       (network_scanner.sh)"),
                Choice("usb",    "USB Scanner           (usb_scanner.sh)"),
                Choice("fuzz",   "Fuzzing Tool          (Fuzzing_tool.py)"),
                Choice("back",   "← Back"),
            ],
        ).execute()
        if choice == "back":
            break
        run_tool(choice)

# ── Main menu ────────────────────────────────────────────────
def main_menu():
    console.print(Panel(
        Text("  Hybrid Cybersecurity Engine  ", style="bold white on blue"),
        expand=False,
    ))

    while True:
        choice = inquirer.select(
            message="Main Menu — select an option:",
            choices=[
                Choice("full",     "1. Full Automated Scan"),
                Choice("malware",  "2. AI Malware Detector"),
                Choice("backdoor", "3. Backdoor Scanner"),
                Choice("vuln",     "4. Vulnerability Scanner"),
                Choice("manual",   "5. Manual Tools"),
                Choice("custom",   "6. Customize Scans"),
                Choice("exit",     "0. Exit"),
            ],
        ).execute()

        if   choice == "exit":     console.print("[green]Goodbye.[/green]"); break
        elif choice == "full":     run_full_scan()
        elif choice == "malware":  run_tool("malware")
        elif choice == "backdoor": run_tool("backdoor")
        elif choice == "vuln":     run_tool("vuln")
        elif choice == "manual":   manual_tools_menu()
        elif choice == "custom":   customize_scans()

if __name__ == "__main__":
    main_menu()
