#!/usr/bin/env python3
import importlib
import subprocess
import sys
import os

# Required dependencies
DEPENDENCIES = ["InquirerPy", "rich", "watchdog"]

def in_virtualenv():
    """Detect if running inside a virtual environment."""
    return (
        hasattr(sys, "real_prefix")  # legacy venv
        or (hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix)  # modern venv
    )

def ensure_dependencies():
    """Check and install dependencies based on environment (venv/system)."""
    missing = []
    for dep in DEPENDENCIES:
        try:
            importlib.import_module(dep)
        except ImportError:
            missing.append(dep)

    if missing:
        print(f"[setup] Missing python packages: {', '.join(missing)}")
        try:
            if in_virtualenv():
                print("[setup] Detected virtualenv → installing normally...")
                subprocess.check_call([sys.executable, "-m", "pip", "install", *missing])
            else:
                print("[setup] No virtualenv detected → installing with --user...")
                subprocess.check_call([sys.executable, "-m", "pip", "install", "--user", *missing])
            print("[setup] Installation complete.")
        except Exception as e:
            print(f"[error] Failed to install packages: {e}")
            sys.exit(1)

# Run setup
ensure_dependencies()

# Now safe to import
from InquirerPy import inquirer
from rich.console import Console
from rich.table import Table
import time

console = Console()

def main_menu():
    while True:
        choice = inquirer.select(
            message="Select an option:",
            choices=[
                "1. Full Automated Scan",
                "2. AI Malware Detector + Cuckoo Sandbox",
                "3. Backdoor Scanner",
                "4. Customize Scans (multi-select)",
                "5. Open Terminal",
                "0. Exit",
            ],
        ).execute()

        if choice.startswith("0"):
            console.print("[green]Exiting...[/green]")
            break
        else:
            console.print(f"[yellow]You selected:[/yellow] {choice}")
            time.sleep(1)

if __name__ == "__main__":
    main_menu()
