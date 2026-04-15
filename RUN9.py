#!/usr/bin/env python3
"""
HYBRID CYBERSECURITY ENGINE — PROFESSIONAL EDITION v4
Dark navy | Card-click demo | Results panel | Clean login
Run:     python3 hce_final.py
Install: sudo apt install python3-tk -y
"""
import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3, hashlib, threading, time, random, datetime

# ═══════════════════════════════════════════════════════
#  COLOUR PALETTE  — Dark navy, never washed out
# ═══════════════════════════════════════════════════════
BG      = "#f0f4ff"   # page background  — ice white
PANEL   = "#e8f0fe"   # panel background — sky wash
CARD    = "#ffffff"   # card background  — pure white
CARD2   = "#e0eafa"   # raised / hover   — light blue
BORDER  = "#c8d8f0"   # borders
BDR2    = "#90b4e8"   # highlighted border

BLUE    = "#1565c0"   # manual tools accent — royal blue
BLUEH   = "#1976d2"   # blue hover
BDIM    = "#0d3a7a"   # automated tools accent — dark blue

GREEN   = "#1565c0"   # scan complete  — use blue (monochromatic)
AMBER   = "#f59e0b"   # warning        — only non-blue status colour
RED     = "#ef5350"   # threat / error — only non-blue status colour
PURPLE  = "#0d3a7a"   # automated tools — dark blue shade

T1      = "#0a1628"   # primary text   — midnight navy
T2      = "#2a4a7a"   # secondary text — medium blue
T3      = "#5a7898"   # tertiary       — muted blue
T4      = "#90b4e8"   # very dim       — periwinkle

TAG_BASH    = ("#dce8fb", "#0d3a7a")
TAG_PYTHON  = ("#d8e4f8", "#091e42")
TAG_AI      = ("#dde8fb", "#0d2a5a")
TAG_SANDBOX = ("#d5e5f8", "#0a1e3a")

ROLE_BADGE = {
    "admin":   ("#0d3a7a", "#e8f0fe"),
    "analyst": ("#1565c0", "#ffffff"),
    "viewer":  ("#2a5298", "#e8f0fe"),
    "guest":   ("#c8d8f0", "#2a4a7a"),
}

F = "Segoe UI"
def fnt(s, b=False): return (F, s, "bold") if b else (F, s)

# ═══════════════════════════════════════════════════════
#  PERMISSIONS / ACL
# ═══════════════════════════════════════════════════════
PERMISSIONS = {
    "admin":   ["run_manual", "run_auto", "view_results",
                "manage_users", "view_logs", "export", "config"],
    "analyst": ["run_manual", "run_auto", "view_results", "export"],
    "viewer":  ["view_results"],
    "guest":   [],
}
def can(user, action):
    return action in PERMISSIONS.get(user["role"], [])

# ═══════════════════════════════════════════════════════
#  DATABASE
# ═══════════════════════════════════════════════════════
DB = "hce_final.db"
def _h(p): return hashlib.sha256(p.encode()).hexdigest()

def init_db():
    c = sqlite3.connect(DB); cur = c.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'viewer',
        active INTEGER DEFAULT 1,
        created TEXT DEFAULT CURRENT_TIMESTAMP)""")
    cur.execute("""CREATE TABLE IF NOT EXISTS audit(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT, action TEXT,
        ts TEXT DEFAULT CURRENT_TIMESTAMP)""")
    for u, p, r in [
        ("admin",    "admin123",   "admin"),
        ("analyst1", "analyst123", "analyst"),
        ("viewer1",  "viewer123",  "viewer"),
        ("guest",    "guest123",   "guest"),
    ]:
        try:
            cur.execute(
                "INSERT INTO users(username,password,role) VALUES(?,?,?)",
                (u, _h(p), r))
        except: pass
    c.commit(); c.close()

def db_login(u, p):
    c = sqlite3.connect(DB); cur = c.cursor()
    cur.execute(
        "SELECT id,username,role,active FROM users "
        "WHERE username=? AND password=?", (u, _h(p)))
    row = cur.fetchone(); c.close()
    if row and row[3]:
        db_audit(row[1], "LOGIN")
        return {"id": row[0], "username": row[1], "role": row[2]}
    return None

def db_audit(u, a):
    try:
        c = sqlite3.connect(DB)
        c.execute(
            "INSERT INTO audit(username,action,ts) VALUES(?,?,?)",
            (u, a, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        c.commit(); c.close()
    except: pass

def db_users():
    c = sqlite3.connect(DB); cur = c.cursor()
    cur.execute(
        "SELECT id,username,role,active,created FROM users ORDER BY id")
    r = cur.fetchall(); c.close(); return r

def db_add_user(u, p, r):
    try:
        c = sqlite3.connect(DB)
        c.execute(
            "INSERT INTO users(username,password,role) VALUES(?,?,?)",
            (u, _h(p), r))
        c.commit(); c.close(); return True
    except: return False

def db_toggle(uid, active):
    c = sqlite3.connect(DB)
    c.execute("UPDATE users SET active=? WHERE id=?",
              (0 if active else 1, uid))
    c.commit(); c.close()

def db_audit_log():
    c = sqlite3.connect(DB); cur = c.cursor()
    cur.execute(
        "SELECT username,action,ts FROM audit "
        "ORDER BY id DESC LIMIT 100")
    r = cur.fetchall(); c.close(); return r

# ═══════════════════════════════════════════════════════
#  TOOL DEFINITIONS
# ═══════════════════════════════════════════════════════
MANUAL_TOOLS = [
    {
        "id": "url", "icon": "🔗",
        "name": "URL Scanner", "tag": "BASH",
        "tag_style": TAG_BASH, "accent": BLUE,
        "desc": "Analyses URLs against VirusTotal API and global "
                "blacklists for phishing and malware indicators.",
        "steps": [
            "Initialising scan engine",
            "Resolving DNS records",
            "Connecting to VirusTotal API",
            "Querying 72 security engines",
            "Checking global blacklists",
            "Analysing redirect chain",
            "Compiling threat report",
        ],
        "out": [
            ("info", "Target URL    :  https://example.com"),
            ("info", "Resolved IP   :  93.184.216.34"),
            ("info", "VT Engines    :  0 / 72 flagged"),
            ("info", "Blacklists    :  Not listed"),
            ("ok",   "VERDICT:  URL IS CLEAN — No threats detected"),
        ],
    },
    {
        "id": "domain", "icon": "🌐",
        "name": "Domain Checker", "tag": "BASH",
        "tag_style": TAG_BASH, "accent": BLUE,
        "desc": "WHOIS lookup, DNS enumeration and domain reputation "
                "analysis via multiple intelligence sources.",
        "steps": [
            "Initialising domain analysis",
            "Running WHOIS lookup",
            "Fetching DNS A records",
            "Fetching MX and NS records",
            "Checking domain age",
            "Querying reputation databases",
            "Building domain report",
        ],
        "out": [
            ("info", "Domain        :  example.com"),
            ("info", "Registrar     :  GoDaddy LLC"),
            ("info", "Created       :  1995-08-14  (30 years ago)"),
            ("info", "DNS A Record  :  93.184.216.34"),
            ("ok",   "VERDICT:  DOMAIN TRUSTED — Clean and established"),
        ],
    },
    {
        "id": "port", "icon": "🔌",
        "name": "Port Scanner", "tag": "BASH",
        "tag_style": TAG_BASH, "accent": BLUE,
        "desc": "SYN scan to discover open TCP/UDP ports and identify "
                "running services on target hosts.",
        "steps": [
            "Initialising port scanner",
            "Sending SYN probes to target",
            "Scanning common ports 1–1024",
            "Scanning extended range 1025–8080",
            "Fingerprinting detected services",
            "Detecting OS signature",
            "Building port map",
        ],
        "out": [
            ("info", "Target Host   :  192.168.1.1"),
            ("info", "22  / tcp      OPEN    OpenSSH 8.2"),
            ("info", "80  / tcp      OPEN    Apache httpd 2.4.49"),
            ("info", "443 / tcp      OPEN    OpenSSL / HTTPS"),
            ("warn", "8080 / tcp     OPEN    HTTP Proxy — review required"),
            ("warn", "VERDICT:  1 port flagged for security review"),
        ],
    },
    {
        "id": "net", "icon": "📡",
        "name": "Network Scanner", "tag": "BASH",
        "tag_style": TAG_BASH, "accent": BLUE,
        "desc": "ARP broadcast sweep to discover all live hosts on a "
                "subnet and map the network topology.",
        "steps": [
            "Initialising network scanner",
            "Sending ARP broadcast sweep",
            "Waiting for host responses",
            "Resolving hostnames via DNS",
            "Analysing TTL values",
            "Mapping network topology",
            "Saving network map to database",
        ],
        "out": [
            ("info", "Subnet        :  192.168.1.0/24"),
            ("info", "192.168.1.1   ALIVE   Gateway / Router"),
            ("info", "192.168.1.10  ALIVE   Workstation (Windows)"),
            ("info", "192.168.1.15  ALIVE   Network Printer"),
            ("warn", "192.168.1.99  ALIVE   UNKNOWN DEVICE"),
            ("warn", "VERDICT:  1 unrecognised host — investigate"),
        ],
    },
    {
        "id": "usb", "icon": "💾",
        "name": "USB Device Scanner", "tag": "BASH",
        "tag_style": TAG_BASH, "accent": BLUE,
        "desc": "Enumerates connected USB devices and verifies file "
                "hashes against known threat databases.",
        "steps": [
            "Initialising USB scanner",
            "Enumerating connected USB devices",
            "Reading device descriptors",
            "Mounting device filesystem",
            "Computing SHA256 hashes",
            "Cross-referencing threat database",
            "Generating device report",
        ],
        "out": [
            ("info", "Device        :  SanDisk Ultra  (ID 0781:5581)"),
            ("info", "Mount Point   :  /media/usb0"),
            ("info", "Files Scanned :  214"),
            ("info", "Hash Matches  :  0 / 4,821,033 signatures"),
            ("ok",   "VERDICT:  USB DEVICE IS CLEAN"),
        ],
    },
]

AUTO_TOOLS = [
    {
        "id": "malware", "icon": "🦠",
        "name": "Malware Scanner", "tag": "PYTHON",
        "tag_style": TAG_PYTHON, "accent": PURPLE,
        "desc": "Hash-based detection engine cross-referencing 4.8 million "
                "malware signatures (MD5 / SHA256).",
        "steps": [
            "Initialising malware engine",
            "Loading 4,821,033 signatures",
            "Indexing target directory",
            "Computing MD5 / SHA256 hashes",
            "Cross-referencing signature database",
            "Analysing PE headers",
            "Measuring file entropy scores",
            "Finalising threat verdict",
        ],
        "out": [
            ("info", "Scan Path     :  /home/user/Downloads"),
            ("info", "Files Found   :  47  |  Signatures: 4,821,033 loaded"),
            ("warn", "installer.exe :  HIGH entropy (7.94) — suspicious"),
            ("warn", "installer.exe :  Matches Trojan.Generic.DB signature"),
            ("err",  "VERDICT:  THREAT DETECTED — 1 malicious file found"),
        ],
    },
    {
        "id": "ai", "icon": "🤖",
        "name": "AI Malware Detector", "tag": "AI / ML",
        "tag_style": TAG_AI, "accent": PURPLE,
        "desc": "RandomForest ML classifier for zero-day and obfuscated "
                "malware detection — 94.7% accuracy.",
        "steps": [
            "Initialising ML pipeline",
            "Loading RandomForest model weights",
            "Extracting 256 feature dimensions",
            "Normalising feature vectors",
            "Running inference pipeline",
            "Calculating confidence scores",
            "Classifying threat category",
        ],
        "out": [
            ("info", "Sample        :  suspicious.exe"),
            ("info", "Model         :  RandomForest v2.1"),
            ("info", "Confidence    :  94.7%"),
            ("warn", "Category      :  TROJAN / Dropper"),
            ("err",  "AI VERDICT:  FILE IS MALICIOUS"),
        ],
    },
    {
        "id": "backdoor", "icon": "🚪",
        "name": "Backdoor Scanner", "tag": "PYTHON",
        "tag_style": TAG_PYTHON, "accent": PURPLE,
        "desc": "Detects reverse shells, Remote Access Trojans (RATs) "
                "and persistent backdoor implants.",
        "steps": [
            "Initialising backdoor scanner",
            "Enumerating all running processes",
            "Analysing outbound network connections",
            "Scanning startup registry entries",
            "Reviewing scheduled tasks",
            "Auditing cron jobs",
            "Compiling threat verdict",
        ],
        "out": [
            ("info", "Processes     :  142 reviewed"),
            ("info", "Connections   :  8 outbound connections found"),
            ("warn", "PID 3847      :  python3 → 45.33.32.156:4444"),
            ("warn", "Connection    :  Non-standard port — C2 pattern"),
            ("err",  "VERDICT:  ACTIVE REVERSE SHELL DETECTED"),
        ],
    },
    {
        "id": "vuln", "icon": "🛡",
        "name": "Vulnerability Scanner", "tag": "PYTHON",
        "tag_style": TAG_PYTHON, "accent": PURPLE,
        "desc": "CVE database assessment with CVSS severity scoring "
                "against detected software versions.",
        "steps": [
            "Initialising vulnerability scanner",
            "Enumerating target services",
            "Detecting software versions",
            "Fetching NVD CVE database",
            "Matching version fingerprints",
            "Calculating CVSS severity scores",
            "Generating vulnerability report",
        ],
        "out": [
            ("info", "Target        :  192.168.1.10"),
            ("info", "Services      :  Apache 2.4.49,  OpenSSL 1.0.2"),
            ("warn", "CVE-2021-41773  Apache Path Traversal   CVSS 9.8  CRITICAL"),
            ("warn", "CVE-2016-0800   OpenSSL DROWN Attack    CVSS 7.4  HIGH"),
            ("err",  "VERDICT:  2 critical vulnerabilities — patch immediately"),
        ],
    },
    {
        "id": "cuckoo", "icon": "🧪",
        "name": "Cuckoo Sandbox", "tag": "SANDBOX",
        "tag_style": TAG_SANDBOX, "accent": PURPLE,
        "desc": "Dynamic behavioural analysis by detonating samples "
                "inside an isolated Windows 10 virtual machine.",
        "steps": [
            "Initialising sandbox environment",
            "Restoring Win10 x64 VM snapshot",
            "Detonating sample in isolation",
            "Monitoring 1,847 API calls",
            "Capturing network traffic",
            "Recording filesystem changes",
            "Analysing memory dumps",
            "Generating behavioural report",
        ],
        "out": [
            ("info", "Sample        :  sample.exe  |  VM: Windows 10 x64"),
            ("info", "API Calls     :  1,847 logged over 120 seconds"),
            ("warn", "C2 Attempts   :  3 outbound connections blocked"),
            ("warn", "Persistence   :  Registry key created at HKLM\\Run"),
            ("err",  "VERDICT:  RANSOMWARE BEHAVIOUR DETECTED"),
        ],
    },
]

# ═══════════════════════════════════════════════════════
#  TOOL CARD  — click to demo, no input / run button
# ═══════════════════════════════════════════════════════
class ToolCard(tk.Frame):
    def __init__(self, parent, tool, user,
                 stats_cb, **kw):
        super().__init__(parent, bg=CARD,
                         highlightthickness=1,
                         highlightbackground=BORDER,
                         cursor="hand2", **kw)
        self.tool     = tool
        self.user     = user
        self.stats_cb = stats_cb
        self._running = False
        self._done    = False
        self._build()

        # Hover effect
        self.bind("<Enter>", lambda e:
            self.configure(
                highlightbackground=tool["accent"]))
        self.bind("<Leave>", lambda e:
            self.configure(
                highlightbackground=(
                    tool["accent"] if self._done
                    else BORDER)))

        # Click anywhere on card to run
        self.bind("<Button-1>", lambda e: self._run())
        for child in self.winfo_children():
            child.bind("<Button-1>",
                       lambda e: self._run())

    def _build(self):
        acc = self.tool["accent"]

        # Top colour strip
        tk.Frame(self, bg=acc,
                 height=3).pack(fill="x")

        body = tk.Frame(self, bg=CARD,
                        padx=16, pady=12)
        body.pack(fill="both", expand=True)

        # ── Row 1: icon · name · tag ──────────
        r1 = tk.Frame(body, bg=CARD)
        r1.pack(fill="x")

        ib = tk.Frame(r1, bg=CARD2,
                      width=36, height=36)
        ib.pack(side="left", padx=(0, 10))
        ib.pack_propagate(False)
        tk.Label(ib, text=self.tool["icon"],
                 bg=CARD2, font=fnt(16),
                 fg=acc).place(
            relx=.5, rely=.5, anchor="center")

        tk.Label(r1, text=self.tool["name"],
                 bg=CARD, fg=T1,
                 font=fnt(13, True)).pack(
            side="left")

        tbg, tfg = self.tool["tag_style"]
        tk.Label(r1,
                 text=f"  {self.tool['tag']}  ",
                 bg=tbg, fg=tfg,
                 font=fnt(10, True)).pack(
            side="right", pady=3)

        # ── Row 2: description ────────────────
        tk.Label(body, text=self.tool["desc"],
                 bg=CARD, fg=T2,
                 font=fnt(11),
                 wraplength=340,
                 justify="left",
                 anchor="w").pack(
            fill="x", pady=(6, 8))

        # ── Row 3: process flow ───────────────
        flow = "  →  ".join(self.tool["steps"])
        tk.Label(body, text=flow,
                 bg=CARD, fg=T3,
                 font=fnt(9),
                 wraplength=340,
                 justify="left",
                 anchor="w").pack(
            fill="x", pady=(0, 8))

        # ── Progress bar ──────────────────────
        self._pvar = tk.DoubleVar(value=0)
        sty = ttk.Style()
        sid = f"tc_{self.tool['id']}.Horizontal.TProgressbar"
        sty.configure(sid,
                      troughcolor=PANEL,
                      background=acc,
                      thickness=5,
                      borderwidth=0)
        ttk.Progressbar(body,
                        variable=self._pvar,
                        maximum=100,
                        style=sid).pack(
            fill="x", pady=(0, 5))

        # ── Status ────────────────────────────
        sr = tk.Frame(body, bg=CARD)
        sr.pack(fill="x")
        tk.Label(sr, text="Status:",
                 bg=CARD, fg=T3,
                 font=fnt(10)).pack(side="left")
        self._svar = tk.StringVar(
            value="Click card to run demo")
        self._slbl = tk.Label(
            sr, textvariable=self._svar,
            bg=CARD, fg=T3,
            font=fnt(10))
        self._slbl.pack(side="left", padx=6)

    # ── Run demo ─────────────────────────────
    def _run(self):
        if self._running: return
        self._running = True
        self._done    = False
        self.configure(highlightbackground=BORDER)
        self._pvar.set(0)

        sty = ttk.Style()
        sid = f"tc_{self.tool['id']}.Horizontal.TProgressbar"
        sty.configure(sid,
                      background=self.tool["accent"])

        self._svar.set("Starting...")
        self._slbl.config(fg=BLUE)
        db_audit(self.user["username"],
                 f"DEMO:{self.tool['id']}")

        threading.Thread(
            target=self._work,
            daemon=True).start()

    def _work(self):
        steps = self.tool["steps"]
        total = len(steps)

        for i, step in enumerate(steps):
            time.sleep(random.uniform(0.4, 0.75))
            pct = int((i + 1) / total * 100)
            self.after(0,
                       lambda p=pct, s=step:
                       self._tick(p, s))

        out = list(self.tool["out"])
        threat = any(c == "err" for c, _ in out)
        self.after(0,
                   lambda h=threat:
                   self._finish(h))

    def _tick(self, pct, step):
        self._pvar.set(pct)
        self._svar.set(step)
        self._slbl.config(fg=BLUE)

        sty = ttk.Style()
        sid = f"tc_{self.tool['id']}.Horizontal.TProgressbar"
        sty.configure(sid, background=AMBER)

    def _finish(self, threat, out=None):
        self._running = False
        self._done    = True
        self._pvar.set(100)

        sty = ttk.Style()
        sid = f"tc_{self.tool['id']}.Horizontal.TProgressbar"

        if threat:
            sty.configure(sid, background=RED)
            self._svar.set("Threat detected")
            self._slbl.config(fg=RED)
            self.configure(
                highlightbackground=RED)
        else:
            sty.configure(sid, background=BLUE)
            self._svar.set("Scan complete — Clean")
            self._slbl.config(fg=BLUE)
            self.configure(
                highlightbackground=BLUE)

        self.stats_cb(threat)

# ═══════════════════════════════════════════════════════
#  SCROLLABLE TOOL PANEL
# ═══════════════════════════════════════════════════════
class ToolPanel(tk.Frame):
    def __init__(self, parent, title, subtitle,
                 accent, tools, user,
                 stats_cb, **kw):
        super().__init__(parent, bg=PANEL, **kw)

        # Accent strip + header
        tk.Frame(self, bg=accent,
                 height=3).pack(fill="x")
        hdr = tk.Frame(self, bg="#0f1e35",
                       padx=18, pady=12)
        hdr.pack(fill="x")

        left = tk.Frame(hdr, bg="#0f1e35")
        left.pack(side="left")
        tk.Label(left, text=title,
                 bg="#0f1e35", fg="#e8f0fe",
                 font=fnt(15, True)).pack(
            anchor="w")
        tk.Label(left, text=subtitle,
                 bg="#0f1e35", fg="#5a7898",
                 font=fnt(11)).pack(anchor="w")

        tbg = ("#0f3d8a" if accent == BLUE
               else "#3b1f6b")
        tfg = ("#7eb3ff" if accent == BLUE
               else "#c4b5fd")
        tk.Label(hdr,
                 text=f"  {len(tools)} tools  ",
                 bg=tbg, fg=tfg,
                 font=fnt(10, True)).pack(
            side="right", pady=8)

        tk.Frame(self, bg=BORDER,
                 height=1).pack(fill="x")

        # Scrollable canvas
        cv = tk.Canvas(self, bg=PANEL,
                       highlightthickness=0)
        sb = tk.Scrollbar(
            self, orient="vertical",
            command=cv.yview,
            bg=PANEL, troughcolor=PANEL)
        inner = tk.Frame(cv, bg=PANEL)
        inner.bind(
            "<Configure>",
            lambda e: cv.configure(
                scrollregion=cv.bbox("all")))
        cv.create_window(
            (0, 0), window=inner, anchor="nw")
        cv.configure(yscrollcommand=sb.set)
        cv.pack(side="left",
                fill="both", expand=True)
        sb.pack(side="right", fill="y")

        for ev in ("<MouseWheel>",
                   "<Button-4>", "<Button-5>"):
            cv.bind(ev, lambda e, c=cv:
                c.yview_scroll(
                    -1 if (e.num == 4
                           or getattr(e, "delta", 0) > 0)
                    else 1, "units"))

        for tool in tools:
            ToolCard(inner, tool, user,
                     stats_cb).pack(
                fill="x", padx=12, pady=6)

# ═══════════════════════════════════════════════════════
#  ADMIN PANEL
# ═══════════════════════════════════════════════════════
class AdminPanel(tk.Toplevel):
    def __init__(self, parent, user):
        super().__init__(parent)
        self.title("Admin Control Panel")
        self.geometry("960x680")
        self.configure(bg=BG)
        self.resizable(True, True)
        self._user = user
        self._build()

    def _build(self):
        tk.Frame(self, bg=BLUE,
                 height=3).pack(fill="x")
        hdr = tk.Frame(self, bg=CARD,
                       padx=24, pady=14)
        hdr.pack(fill="x")
        tk.Label(hdr, text="Admin Control Panel",
                 bg=CARD, fg=T1,
                 font=fnt(17, True)).pack(
            side="left")
        tk.Label(hdr,
                 text=f"   Signed in as  "
                      f"{self._user['username']}",
                 bg=CARD, fg=T3,
                 font=fnt(11)).pack(
            side="left", pady=4)
        tk.Button(hdr, text="✕  Close",
                  bg=CARD, fg=T2,
                  font=fnt(12), relief="flat",
                  cursor="hand2",
                  activebackground=CARD2,
                  activeforeground=T1,
                  command=self.destroy).pack(
            side="right")
        tk.Frame(self, bg=BORDER,
                 height=1).pack(fill="x")

        sty = ttk.Style()
        sty.configure("Adm.TNotebook",
                      background=BG,
                      borderwidth=0,
                      tabmargins=[0, 0, 0, 0])
        sty.configure("Adm.TNotebook.Tab",
                      background=CARD,
                      foreground=T3,
                      font=fnt(12, True),
                      padding=[20, 10])
        sty.map("Adm.TNotebook.Tab",
                background=[("selected", CARD2)],
                foreground=[("selected", BLUE)])

        nb = ttk.Notebook(self,
                          style="Adm.TNotebook")
        nb.pack(fill="both", expand=True)

        for name, builder in [
            ("  ACL Reference  ",    self._acl),
            ("  User Management  ",  self._users),
            ("  Add User  ",         self._add),
            ("  Audit Log  ",        self._audit),
        ]:
            f = tk.Frame(nb, bg=BG)
            nb.add(f, text=name)
            builder(f)

    # ── ACL matrix ────────────────────────────
    def _acl(self, p):
        f = tk.Frame(p, bg=BG,
                     padx=28, pady=22)
        f.pack(fill="both", expand=True)

        tk.Label(f, text="Access Control Matrix",
                 bg=BG, fg=T1,
                 font=fnt(16, True)).pack(
            anchor="w")
        tk.Label(f,
                 text="Defines exactly what each "
                      "role is permitted to do "
                      "within the system.",
                 bg=BG, fg=T2,
                 font=fnt(12)).pack(
            anchor="w", pady=(4, 20))

        tbl = tk.Frame(f, bg=BG)
        tbl.pack(anchor="w", fill="x")

        headers = ["Permission / Action",
                   "Admin", "Analyst",
                   "Viewer", "Guest"]
        hfg = [T2, RED, "#60a5fa", AMBER, T3]

        for ci, (h, fg) in enumerate(
                zip(headers, hfg)):
            tk.Label(tbl, text=h,
                     bg=CARD2, fg=fg,
                     font=fnt(11, True),
                     width=(28 if ci == 0 else 8),
                     anchor=(
                         "w" if ci == 0
                         else "center"),
                     padx=14, pady=10
                     ).grid(row=0, column=ci,
                            padx=2, pady=2,
                            sticky="ew")

        actions = [
            ("Run Manual Tools (Bash)",
             "run_manual"),
            ("Run Automated Scans (Python/AI)",
             "run_auto"),
            ("View Scan Results & Reports",
             "view_results"),
            ("Manage User Accounts",
             "manage_users"),
            ("View Full Audit Log",
             "view_logs"),
            ("Export Reports",
             "export"),
            ("System Configuration",
             "config"),
        ]

        for ri, (label, action) in enumerate(
                actions, 1):
            rb = CARD2 if ri % 2 == 0 else CARD
            tk.Label(tbl,
                     text=f"  {label}",
                     bg=rb, fg=T1,
                     font=fnt(12),
                     anchor="w",
                     padx=14, pady=11
                     ).grid(row=ri, column=0,
                            padx=2, pady=1,
                            sticky="ew")
            for ci, role in enumerate(
                    ["admin", "analyst",
                     "viewer", "guest"], 1):
                ok = action in PERMISSIONS[role]
                tk.Label(tbl,
                         text="✔" if ok else "—",
                         bg=rb,
                         fg=GREEN if ok else T4,
                         font=fnt(14, True),
                         anchor="center",
                         pady=11
                         ).grid(row=ri, column=ci,
                                padx=2, pady=1,
                                sticky="ew")

        note = tk.Frame(f, bg=CARD2,
                        padx=18, pady=14)
        note.pack(fill="x", pady=(22, 0))
        tk.Label(note,
                 text="Admin-only responsibilities",
                 bg=CARD2, fg=RED,
                 font=fnt(12, True)).pack(
            anchor="w", pady=(0, 8))
        for item in [
            "Create, edit and deactivate user accounts",
            "Assign and change user role permissions",
            "Access the full audit trail of all activity",
            "Configure API keys and system settings",
            "Delete or archive historical scan reports",
        ]:
            tk.Label(note,
                     text=f"   •   {item}",
                     bg=CARD2, fg=T2,
                     font=fnt(12)).pack(
                anchor="w", pady=3)

    # ── User management ───────────────────────
    def _users(self, p):
        f = tk.Frame(p, bg=BG,
                     padx=22, pady=18)
        f.pack(fill="both", expand=True)

        tk.Label(f, text="Registered Users",
                 bg=BG, fg=T1,
                 font=fnt(14, True)).pack(
            anchor="w")
        tk.Label(f,
                 text="Select a user then click "
                      "Toggle to enable or disable.",
                 bg=BG, fg=T2,
                 font=fnt(12)).pack(
            anchor="w", pady=(3, 14))

        sty = ttk.Style()
        sty.configure("U.Treeview",
                       background=CARD,
                       foreground=T1,
                       fieldbackground=CARD,
                       font=fnt(12),
                       rowheight=34)
        sty.configure("U.Treeview.Heading",
                       background=CARD2,
                       foreground=BLUE,
                       font=fnt(11, True))
        sty.map("U.Treeview",
                background=[("selected", CARD2)])

        cols = ("ID", "Username", "Role",
                "Status", "Created")
        self._tree = ttk.Treeview(
            f, columns=cols,
            show="headings", height=9,
            style="U.Treeview")
        for col, w in zip(
                cols, [50, 160, 110, 100, 200]):
            self._tree.heading(col, text=col)
            self._tree.column(col, width=w)
        self._tree.pack(fill="both", expand=True)

        btn_row = tk.Frame(f, bg=BG)
        btn_row.pack(pady=10, anchor="w")

        def refresh():
            for r in self._tree.get_children():
                self._tree.delete(r)
            for row in db_users():
                s = ("Active" if row[3]
                     else "Disabled")
                self._tree.insert(
                    "", "end",
                    values=(row[0], row[1],
                            row[2].capitalize(),
                            s, row[4]))

        def toggle():
            sel = self._tree.selection()
            if not sel:
                messagebox.showwarning(
                    "Select",
                    "Please select a user first.")
                return
            v = self._tree.item(
                sel[0])["values"]
            if v[1] == self._user["username"]:
                messagebox.showerror(
                    "Error",
                    "Cannot disable your own account.")
                return
            db_toggle(v[0], v[3] == "Active")
            db_audit(self._user["username"],
                     f"TOGGLE:{v[1]}")
            refresh()

        for txt, cmd, fg in [
            ("Refresh", refresh, BLUE),
            ("Toggle Active / Disabled",
             toggle, AMBER),
        ]:
            tk.Button(btn_row, text=txt,
                      bg=CARD2, fg=fg,
                      font=fnt(12, True),
                      relief="flat",
                      cursor="hand2",
                      activebackground=BDR2,
                      activeforeground=T1,
                      padx=18, pady=8,
                      command=cmd).pack(
                side="left", padx=6)
        refresh()

    # ── Add user ──────────────────────────────
    def _add(self, p):
        f = tk.Frame(p, bg=BG,
                     padx=44, pady=22)
        f.pack(fill="both", expand=True)

        tk.Label(f, text="Create New User",
                 bg=BG, fg=T1,
                 font=fnt(15, True)).pack(
            anchor="w")
        tk.Label(f,
                 text="New accounts are active "
                      "immediately upon creation.",
                 bg=BG, fg=T2,
                 font=fnt(12)).pack(
            anchor="w", pady=(3, 20))

        self._nu = tk.StringVar()
        self._np = tk.StringVar()
        self._nr = tk.StringVar(value="viewer")

        for label, var, show in [
            ("Username", self._nu, ""),
            ("Password", self._np, "●"),
        ]:
            tk.Label(f, text=label,
                     bg=BG, fg=T2,
                     font=fnt(12, True)).pack(
                anchor="w", pady=(10, 4))
            e = tk.Entry(
                f, textvariable=var, show=show,
                bg=CARD, fg=T1,
                insertbackground=BLUE,
                relief="flat", font=fnt(13),
                highlightthickness=1,
                highlightbackground=BORDER,
                highlightcolor=BLUE,
                width=30)
            e.pack(anchor="w", ipady=9)

        tk.Label(f, text="Role",
                 bg=BG, fg=T2,
                 font=fnt(12, True)).pack(
            anchor="w", pady=(10, 4))

        sty = ttk.Style()
        sty.configure("R.TCombobox",
                      fieldbackground=CARD,
                      background=CARD,
                      foreground=T1,
                      font=fnt(12))
        ttk.Combobox(
            f, textvariable=self._nr,
            values=["admin", "analyst",
                    "viewer", "guest"],
            state="readonly",
            font=fnt(13), width=22,
            style="R.TCombobox").pack(anchor="w")

        # Role guide
        guide = tk.Frame(f, bg=CARD2,
                         padx=16, pady=12)
        guide.pack(anchor="w", pady=14,
                   fill="x")
        tk.Label(guide,
                 text="Role Permissions Guide",
                 bg=CARD2, fg=T2,
                 font=fnt(11, True)).pack(
            anchor="w", pady=(0, 8))
        for role, desc, clr in [
            ("Admin",
             "Full access — all tools, "
             "user management, logs, config",
             RED),
            ("Analyst",
             "Run scans + view results "
             "+ export reports",
             "#60a5fa"),
            ("Viewer",
             "View scan results only — "
             "cannot run tools",
             AMBER),
            ("Guest",
             "No access — "
             "placeholder account",
             T3),
        ]:
            row = tk.Frame(guide, bg=CARD2)
            row.pack(fill="x", pady=3)
            tk.Label(row,
                     text=f"{role:<10}",
                     bg=CARD2, fg=clr,
                     font=fnt(12, True),
                     width=10,
                     anchor="w").pack(
                side="left")
            tk.Label(row, text=desc,
                     bg=CARD2, fg=T3,
                     font=fnt(11)).pack(
                side="left")

        self._msg = tk.StringVar()
        tk.Label(f, textvariable=self._msg,
                 bg=BG, fg=GREEN,
                 font=fnt(11)).pack(
            anchor="w", pady=6)

        def create():
            u  = self._nu.get().strip()
            pw = self._np.get().strip()
            r  = self._nr.get()
            if not u or not pw:
                self._msg.set(
                    "Username and password required.")
                return
            if db_add_user(u, pw, r):
                db_audit(
                    self._user["username"],
                    f"ADD_USER:{u}:{r}")
                self._msg.set(
                    f"✔  User '{u}' created "
                    f"with role: {r}")
                self._nu.set("")
                self._np.set("")
            else:
                self._msg.set(
                    f"Username '{u}' already exists.")

        tk.Button(f, text="Create User",
                  bg=BLUE, fg="#ffffff",
                  font=fnt(13, True),
                  relief="flat", cursor="hand2",
                  activebackground=BLUEH,
                  activeforeground="#ffffff",
                  padx=24, pady=10,
                  command=create).pack(
            anchor="w", pady=8)

    # ── Audit log ─────────────────────────────
    def _audit(self, p):
        f = tk.Frame(p, bg=BG,
                     padx=22, pady=18)
        f.pack(fill="both", expand=True)

        tk.Label(f, text="System Audit Log",
                 bg=BG, fg=T1,
                 font=fnt(14, True)).pack(
            anchor="w")
        tk.Label(f,
                 text="All user actions are "
                      "automatically recorded.",
                 bg=BG, fg=T2,
                 font=fnt(12)).pack(
            anchor="w", pady=(3, 14))

        sty = ttk.Style()
        sty.configure("AL.Treeview",
                       background=CARD,
                       foreground=T1,
                       fieldbackground=CARD,
                       font=fnt(12),
                       rowheight=30)
        sty.configure("AL.Treeview.Heading",
                       background=CARD2,
                       foreground=AMBER,
                       font=fnt(11, True))
        sty.map("AL.Treeview",
                background=[("selected", CARD2)])

        cols = ("User", "Action", "Timestamp")
        tv = ttk.Treeview(
            f, columns=cols,
            show="headings", height=14,
            style="AL.Treeview")
        for col, w in zip(cols, [160, 300, 200]):
            tv.heading(col, text=col)
            tv.column(col, width=w)
        for row in db_audit_log():
            tv.insert("", "end", values=row)

        sb = ttk.Scrollbar(
            f, orient="vertical",
            command=tv.yview)
        tv.configure(yscrollcommand=sb.set)
        tv.pack(side="left",
                fill="both", expand=True)
        sb.pack(side="right", fill="y")

# ═══════════════════════════════════════════════════════
#  TOP BAR
# ═══════════════════════════════════════════════════════
class TopBar(tk.Frame):
    def __init__(self, parent, user,
                 on_logout, on_admin,
                 stats, **kw):
        super().__init__(parent, bg="#0a1628",
                         height=56, **kw)
        self.pack_propagate(False)
        self._stats = stats

        # Left accent strip
        tk.Frame(self, bg=BLUE,
                 width=4).pack(
            side="left", fill="y")

        # Logo + name
        tk.Label(self, text="  HCE  ",
                 bg="#1565c0", fg="#ffffff",
                 font=fnt(14, True)).pack(
            side="left", pady=14)
        tk.Label(self,
                 text="  Hybrid Cybersecurity Engine",
                 bg="#0a1628", fg="#e8f0fe",
                 font=fnt(14, True)).pack(
            side="left")
        tk.Label(self,
                 text="  |  Security Operations Dashboard",
                 bg="#0a1628", fg="#5a7898",
                 font=fnt(11)).pack(side="left")

        # Right side
        tk.Frame(self, bg="#1a2a45",
                 width=1).pack(
            side="right", fill="y")

        tk.Button(self, text="  Sign Out  ",
                  bg="#0a1628", fg="#5a7898",
                  font=fnt(12), relief="flat",
                  cursor="hand2",
                  activebackground=RED,
                  activeforeground="#ffffff",
                  command=on_logout).pack(
            side="right", padx=8, pady=14)

        if user["role"] == "admin":
            tk.Button(self,
                      text="  Admin Panel  ",
                      bg="#0d3a7a", fg="#90b4e8",
                      font=fnt(12, True),
                      relief="flat",
                      cursor="hand2",
                      activebackground=BLUE,
                      activeforeground="#ffffff",
                      command=on_admin).pack(
                side="right", padx=4, pady=14)

        # Role badge + username
        rb, rf = ROLE_BADGE.get(
            user["role"], (CARD2, T2))
        tk.Label(self,
                 text=f"  {user['role'].capitalize()}  ",
                 bg=rb, fg=rf,
                 font=fnt(10, True)).pack(
            side="right", pady=18)
        tk.Label(self,
                 text=f"  {user['username']}  ",
                 bg=CARD, fg=T1,
                 font=fnt(13, True)).pack(
            side="right", padx=2)

        # Live stat counters
        self._sv = tk.StringVar(value="0")
        self._tv = tk.StringVar(value="0")

        for label, var, clr in [
            ("Scans",   self._sv, BLUE),
            ("Threats", self._tv, RED),
        ]:
            box = tk.Frame(self, bg="#0f1e35",
                           padx=16)
            box.pack(side="left",
                     padx=8, pady=10)
            tk.Label(box, textvariable=var,
                     bg="#0f1e35", fg=clr,
                     font=(F, 20, "bold")).pack()
            tk.Label(box, text=label,
                     bg="#0f1e35", fg="#5a7898",
                     font=fnt(9)).pack()

        # Live clock
        self._clk = tk.StringVar()
        tk.Label(self, textvariable=self._clk,
                 bg="#0a1628", fg="#5a7898",
                 font=fnt(11)).pack(
            side="left", padx=14)
        self._tick()

    def refresh(self):
        self._sv.set(str(self._stats["runs"]))
        self._tv.set(str(self._stats["threats"]))

    def _tick(self):
        self._clk.set(
            datetime.datetime.now().strftime(
                "%Y-%m-%d   %H:%M:%S"))
        self.after(1000, self._tick)

# ═══════════════════════════════════════════════════════
#  DASHBOARD
# ═══════════════════════════════════════════════════════
class Dashboard(tk.Frame):
    def __init__(self, parent, user,
                 on_logout, **kw):
        super().__init__(parent, bg=BG, **kw)
        self._user  = user
        self._out   = on_logout
        self._stats = {"runs": 0, "threats": 0}
        self._build()

    def _cb(self, threat):
        self._stats["runs"] += 1
        if threat:
            self._stats["threats"] += 1
        self._topbar.refresh()

    def _build(self):
        # Top bar
        self._topbar = TopBar(
            self, self._user, self._out,
            lambda: AdminPanel(self, self._user),
            self._stats)
        self._topbar.pack(fill="x")
        tk.Frame(self, bg=BLUE,
                 height=2).pack(fill="x")

        # Main body — two tool panels
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True)


        # Left — manual tools
        if can(self._user, "run_manual"):
            ToolPanel(
                body,
                "Manual Analysis Tools",
                "Bash-powered  |  5 tools",
                BLUE, MANUAL_TOOLS,
                self._user,
                self._cb).pack(
                side="left", fill="both",
                expand=True)
        else:
            self._locked(
                body,
                "Manual Analysis Tools",
                BLUE).pack(
                side="left", fill="both",
                expand=True)

        # Divider
        tk.Frame(body, bg=BORDER,
                 width=1).pack(
            side="left", fill="y")

        # Right — automated tools
        if can(self._user, "run_auto"):
            ToolPanel(
                body,
                "Automated Scan Engine",
                "Python + AI/ML  |  5 tools",
                PURPLE, AUTO_TOOLS,
                self._user,
                self._cb).pack(
                side="right", fill="both",
                expand=True)
        else:
            self._locked(
                body,
                "Automated Scan Engine",
                PURPLE).pack(
                side="right", fill="both",
                expand=True)

    def _locked(self, parent, title, accent):
        f = tk.Frame(parent, bg=PANEL)
        tk.Frame(f, bg=accent,
                 height=3).pack(fill="x")
        tk.Frame(f, bg=PANEL).pack(
            expand=True, fill="both")
        tk.Label(f, text="🔒",
                 bg=PANEL, fg=T4,
                 font=fnt(36)).pack(pady=(60, 8))
        tk.Label(f, text=title,
                 bg=PANEL, fg=T2,
                 font=fnt(14, True)).pack()
        tk.Label(f, text="Access Restricted",
                 bg=PANEL, fg=RED,
                 font=fnt(12)).pack(pady=6)
        tk.Label(f,
                 text="Your role does not have\n"
                      "permission to use these tools.",
                 bg=PANEL, fg=T3,
                 font=fnt(12),
                 justify="center").pack()
        return f

# ═══════════════════════════════════════════════════════
#  LOGIN SCREEN
# ═══════════════════════════════════════════════════════
class LoginScreen(tk.Frame):
    def __init__(self, parent, on_login, **kw):
        super().__init__(parent, bg=BG, **kw)
        self._on_login = on_login
        self._attempts = 0
        self._build()

    def _build(self):
        # Two-column layout
        left = tk.Frame(self, bg=CARD, width=420)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)
        tk.Frame(left, bg=BORDER, width=1).pack(
            side="left", fill="y")

        right = tk.Frame(self, bg=BG)
        right.pack(side="right",
                   fill="both", expand=True)

        # ── LEFT: branding ────────────────────
        brand = tk.Frame(left, bg=CARD, padx=38)
        brand.pack(side="left",
                   fill="both", expand=True)

        # Vertical centering
        tk.Frame(brand, bg=CARD).pack(expand=True)

        tk.Label(brand, text="HCE",
                 bg=CARD, fg="#1565c0",
                 font=(F, 62, "bold")).pack(
            anchor="w")
        tk.Label(brand,
                 text="Hybrid Cybersecurity\nEngine",
                 bg=CARD, fg="#0a1628",
                 font=(F, 20, "bold"),
                 justify="left").pack(anchor="w")
        tk.Label(brand,
                 text="Professional Security Suite",
                 bg=CARD, fg="#2a4a7a",
                 font=fnt(12)).pack(
            anchor="w", pady=(4, 30))

        tk.Frame(brand, bg=BORDER,
                 height=1).pack(
            fill="x", pady=(0, 20))

        # Feature list
        features = [
            ("🔗", "5 Manual Bash analysis tools"),
            ("🤖", "AI-powered zero-day detection"),
            ("🧪", "Dynamic Cuckoo Sandbox analysis"),
            ("🛡", "CVE vulnerability scanning"),
            ("📋", "Full audit trail — SQLite logging"),
            ("👥", "Role-based access control (RBAC)"),
        ]
        for icon, text in features:
            row = tk.Frame(brand, bg=CARD)
            row.pack(fill="x", pady=5)
            ib = tk.Frame(row, bg="#e8f0fe",
                          width=32, height=32)
            ib.pack(side="left", padx=(0, 12))
            ib.pack_propagate(False)
            tk.Label(ib, text=icon,
                     bg="#e8f0fe",
                     font=fnt(14)).place(
                relx=.5, rely=.5, anchor="center")
            tk.Label(row, text=text,
                     bg=CARD, fg="#2a4a7a",
                     font=fnt(12)).pack(
                side="left")

        tk.Frame(brand, bg=CARD).pack(expand=True)
        tk.Label(brand,
                 text="v4.0  |  Kali Linux  |  "
                      "Python Tkinter  |  SQLite",
                 bg=CARD, fg="#90b4e8",
                 font=fnt(10)).pack(pady=20)

        # ── RIGHT: login form ─────────────────
        form_outer = tk.Frame(right, bg=BG)
        form_outer.place(relx=.5, rely=.5,
                         anchor="center")

        form = tk.Frame(
            form_outer, bg=CARD,
            padx=50, pady=44,
            highlightthickness=1,
            highlightbackground=BORDER)
        form.pack()

        # Top accent
        tk.Frame(form, bg=BLUE,
                 height=3).pack(
            fill="x", pady=(0, 26))

        tk.Label(form, text="Sign in",
                 bg=CARD, fg="#0a1628",
                 font=(F, 23, "bold")).pack(
            anchor="w")
        tk.Label(form,
                 text="Enter your credentials "
                      "to access the system",
                 bg=CARD, fg="#2a4a7a",
                 font=fnt(12)).pack(
            anchor="w", pady=(4, 26))

        # Username + Password fields
        self._uvar = tk.StringVar()
        self._pvar = tk.StringVar()

        for label, var, show in [
            ("Username", self._uvar, ""),
            ("Password", self._pvar, "●"),
        ]:
            tk.Label(form, text=label,
                     bg=CARD, fg="#2a4a7a",
                     font=fnt(12, True)).pack(
                anchor="w", pady=(10, 4))
            e = tk.Entry(
                form, textvariable=var,
                show=show,
                bg=PANEL, fg=T1,
                insertbackground=BLUE,
                relief="flat", font=fnt(13),
                highlightthickness=1,
                highlightbackground=BORDER,
                highlightcolor=BLUE,
                width=26)
            e.pack(fill="x", ipady=11)
            if label == "Username": e.focus()
            if show:
                e.bind("<Return>",
                       lambda ev: self._auth())

        # Error message
        self._msg = tk.StringVar()
        tk.Label(form, textvariable=self._msg,
                 bg=CARD, fg="#ef5350",
                 font=fnt(11)).pack(
            anchor="w", pady=(12, 4))

        # Sign in button
        tk.Button(
            form, text="Sign In  →",
            bg=BLUE, fg="#ffffff",
            font=(F, 13, "bold"),
            relief="flat", bd=0,
            cursor="hand2",
            activebackground=BLUEH,
            activeforeground="#ffffff",
            command=self._auth
        ).pack(fill="x", ipady=13,
               pady=(4, 0))

    def _auth(self):
        if self._attempts >= 3:
            self._msg.set(
                "Account locked. "
                "Restart the application.")
            return
        user = db_login(
            self._uvar.get().strip(),
            self._pvar.get().strip())
        if user:
            self._on_login(user)
        else:
            self._attempts += 1
            left = 3 - self._attempts
            self._msg.set(
                f"Invalid credentials. "
                f"{left} attempt"
                f"{'s' if left != 1 else ''} "
                "remaining."
                if left else "Account locked.")

# ═══════════════════════════════════════════════════════
#  APPLICATION
# ═══════════════════════════════════════════════════════
class App:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title(
            "Hybrid Cybersecurity Engine")
        self.root.configure(bg=BG)
        self.root.attributes("-fullscreen", True)
        self.root.bind(
            "<Escape>",
            lambda e: self.root.attributes(
                "-fullscreen", False))
        self.root.bind(
            "<F11>",
            lambda e: self.root.attributes(
                "-fullscreen", True))

        sty = ttk.Style()
        sty.theme_use("default")
        sty.configure(
            "Vertical.TScrollbar",
            background=CARD,
            troughcolor=PANEL,
            arrowcolor=BORDER,
            bordercolor=CARD)

        self._cur = None
        self._login()
        self.root.mainloop()

    def _login(self):
        if self._cur:
            self._cur.destroy()
        self._cur = LoginScreen(
            self.root, self._enter)
        self._cur.pack(fill="both", expand=True)

    def _enter(self, user):
        if self._cur:
            self._cur.destroy()
        self._cur = Dashboard(
            self.root, user, self._login)
        self._cur.pack(fill="both", expand=True)


if __name__ == "__main__":
    init_db()
    App()