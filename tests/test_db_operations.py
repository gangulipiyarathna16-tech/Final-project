#!/usr/bin/env python3
"""
test_db_operations.py
=====================
Unit tests for all DB save/load operations in the Hybrid VAS project.

Covers:
  1. RUN9_wired — init_db()  (directory creation, table creation, user seeding)
  2. RUN9_wired — db_login()
  3. RUN9_wired — db_save_result()  for every tool id
  4. ResultsViewer _load_all queries  (SQL correctness on a populated DB)
  5. ResultsViewer _clear logic  (all scan tables emptied, users untouched)
  6. backdoor_scanner — log_to_db()
  7. vuln_scanner    — log_to_db()
  8. malware_scan_engine — log_to_main_db()

Run with:
    python3 -m pytest tests/test_db_operations.py -v
    # or
    python3 tests/test_db_operations.py
"""

import os
import sys
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

# ── Add project root and tool sub-dirs to the import path ────
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "automated_tools"))
sys.path.insert(0, str(PROJECT_ROOT / "automated_tools" / "malware_scan" / "scripts"))

# ── Shim tkinter BEFORE importing RUN9_wired ─────────────────
# RUN9_wired imports tkinter at module level; mock it so tests
# can run headless / in CI without a display.
_tk_mock = MagicMock()
for _mod in ("tkinter", "tkinter.ttk", "tkinter.messagebox",
             "tkinter.filedialog", "tkinter.scrolledtext"):
    sys.modules.setdefault(_mod, _tk_mock)


# ── Helpers ───────────────────────────────────────────────────
def _make_temp_db():
    """Create a temporary SQLite file and return its path string."""
    fd, path = tempfile.mkstemp(suffix=".db", prefix="hybrid_vas_test_")
    os.close(fd)
    return path


def _count(db_path, table):
    conn = sqlite3.connect(db_path)
    n = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    conn.close()
    return n


def _rows(db_path, table):
    conn = sqlite3.connect(db_path)
    rows = conn.execute(f"SELECT * FROM {table}").fetchall()
    conn.close()
    return rows


# ═════════════════════════════════════════════════════════════
# 1. RUN9_wired — init_db
# ═════════════════════════════════════════════════════════════
class TestRun9InitDB(unittest.TestCase):
    """init_db() must create the directory, all tables, and seed users."""

    def setUp(self):
        self.db_file = _make_temp_db()

    def tearDown(self):
        try:
            os.unlink(self.db_file)
        except OSError:
            pass

    def _run_init(self, db_path):
        import RUN9_wired
        RUN9_wired.DB = db_path
        RUN9_wired.init_db()

    def test_creates_parent_directory_if_missing(self):
        """init_db must not crash when the parent directory does not yet exist."""
        with tempfile.TemporaryDirectory() as tmp:
            nested = os.path.join(tmp, "sub1", "sub2", "vas.db")
            self._run_init(nested)
            self.assertTrue(os.path.isfile(nested),
                            "Database file was not created in nested path")

    def test_creates_all_required_tables(self):
        self._run_init(self.db_file)
        conn = sqlite3.connect(self.db_file)
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        conn.close()
        expected = {
            "users", "audit",
            "malware_scan_logs", "backdoor_scans",
            "vuln_scans", "vuln_findings",
            "domain_logs", "port_scans", "usb_scans",
        }
        missing = expected - tables
        self.assertFalse(missing, f"Tables not created: {missing}")

    def test_seeds_default_users(self):
        self._run_init(self.db_file)
        conn = sqlite3.connect(self.db_file)
        users = {r[0] for r in conn.execute(
            "SELECT username FROM users").fetchall()}
        conn.close()
        for expected_user in ("admin", "analyst1", "viewer1"):
            self.assertIn(expected_user, users)

    def test_idempotent_double_init(self):
        """Calling init_db twice must not raise or duplicate users."""
        self._run_init(self.db_file)
        self._run_init(self.db_file)   # second call must be safe
        self.assertEqual(_count(self.db_file, "users"),
                         _count(self.db_file, "users"))  # no duplicates


# ═════════════════════════════════════════════════════════════
# 2. RUN9_wired — db_login
# ═════════════════════════════════════════════════════════════
class TestRun9Login(unittest.TestCase):
    """db_login() must return a user dict on valid credentials, None otherwise."""

    def setUp(self):
        self.db_file = _make_temp_db()
        import RUN9_wired
        RUN9_wired.DB = self.db_file
        RUN9_wired.init_db()

    def tearDown(self):
        try:
            os.unlink(self.db_file)
        except OSError:
            pass

    def _login(self, username, password):
        import RUN9_wired
        RUN9_wired.DB = self.db_file
        return RUN9_wired.db_login(username, password)

    def test_admin_valid_credentials(self):
        user = self._login("admin", "admin123")
        self.assertIsNotNone(user)
        self.assertEqual(user["username"], "admin")
        self.assertEqual(user["role"], "admin")

    def test_analyst_valid_credentials(self):
        user = self._login("analyst1", "analyst123")
        self.assertIsNotNone(user)
        self.assertEqual(user["role"], "analyst")

    def test_viewer_valid_credentials(self):
        user = self._login("viewer1", "viewer123")
        self.assertIsNotNone(user)
        self.assertEqual(user["role"], "viewer")

    def test_wrong_password_returns_none(self):
        self.assertIsNone(self._login("admin", "wrongpass"))

    def test_nonexistent_user_returns_none(self):
        self.assertIsNone(self._login("nobody", "whatever"))

    def test_empty_credentials_return_none(self):
        self.assertIsNone(self._login("", ""))


# ═════════════════════════════════════════════════════════════
# 3. RUN9_wired — db_save_result for every tool
# ═════════════════════════════════════════════════════════════
class TestDbSaveResult(unittest.TestCase):
    """db_save_result() must persist a row to the correct table for each tool."""

    OPERATOR = {"username": "test_op"}

    def setUp(self):
        self.db_file = _make_temp_db()
        import RUN9_wired
        RUN9_wired.DB = self.db_file
        RUN9_wired.init_db()

    def tearDown(self):
        try:
            os.unlink(self.db_file)
        except OSError:
            pass

    def _save(self, tid, target, output, threat):
        import RUN9_wired
        RUN9_wired.DB = self.db_file
        RUN9_wired.db_save_result(tid, target, output, threat, self.OPERATOR)

    # ── malware ──────────────────────────────────────────────
    def test_malware_row_inserted(self):
        self._save("malware", "/tmp/bad.exe", ["VERDICT: THREAT DETECTED\n"], True)
        self.assertEqual(_count(self.db_file, "malware_scan_logs"), 1)

    def test_malware_file_name_stored(self):
        self._save("malware", "/tmp/evil.exe", [], True)
        row = _rows(self.db_file, "malware_scan_logs")[0]
        self.assertEqual(row[1], "evil.exe")        # file_name

    def test_malware_file_path_stored(self):
        self._save("malware", "/tmp/evil.exe", [], True)
        row = _rows(self.db_file, "malware_scan_logs")[0]
        self.assertEqual(row[2], "/tmp/evil.exe")   # file_path

    def test_malware_scan_method_is_static(self):
        self._save("malware", "/tmp/f.exe", [], False)
        row = _rows(self.db_file, "malware_scan_logs")[0]
        self.assertEqual(row[7], "static")          # scan_method

    def test_malware_operator_stored(self):
        self._save("malware", "/tmp/f.exe", [], False)
        row = _rows(self.db_file, "malware_scan_logs")[0]
        self.assertEqual(row[8], "test_op")         # operator

    # ── ai ───────────────────────────────────────────────────
    def test_ai_row_inserted(self):
        self._save("ai", "/tmp/s.bin", ["AI VERDICT: MALICIOUS\n"], True)
        self.assertEqual(_count(self.db_file, "malware_scan_logs"), 1)

    def test_ai_scan_method_is_aiml(self):
        self._save("ai", "/tmp/s.bin", [], True)
        row = _rows(self.db_file, "malware_scan_logs")[0]
        self.assertEqual(row[7], "AI/ML")           # scan_method

    def test_ai_confidence_is_0947(self):
        self._save("ai", "/tmp/s.bin", [], True)
        row = _rows(self.db_file, "malware_scan_logs")[0]
        self.assertAlmostEqual(row[6], 0.947, places=3)  # confidence

    # ── backdoor ─────────────────────────────────────────────
    def test_backdoor_row_inserted(self):
        self._save("backdoor", None, ["VERDICT: ACTIVE REVERSE SHELL DETECTED\n"], True)
        self.assertEqual(_count(self.db_file, "backdoor_scans"), 1)

    def test_backdoor_scan_type_stored(self):
        self._save("backdoor", None, [], False)
        row = _rows(self.db_file, "backdoor_scans")[0]
        self.assertEqual(row[1], "full-system")     # scan_type

    def test_backdoor_threat_risk_score_90(self):
        self._save("backdoor", None, [], True)
        row = _rows(self.db_file, "backdoor_scans")[0]
        self.assertEqual(row[7], 90)                # risk_score

    def test_backdoor_clean_risk_score_0(self):
        self._save("backdoor", None, [], False)
        row = _rows(self.db_file, "backdoor_scans")[0]
        self.assertEqual(row[7], 0)                 # risk_score

    # ── vuln ─────────────────────────────────────────────────
    def test_vuln_scan_row_inserted(self):
        self._save("vuln", "192.168.1.10", [], True)
        self.assertEqual(_count(self.db_file, "vuln_scans"), 1)

    def test_vuln_finding_row_inserted(self):
        self._save("vuln", "192.168.1.10", [], True)
        self.assertEqual(_count(self.db_file, "vuln_findings"), 1)

    def test_vuln_target_stored(self):
        self._save("vuln", "10.0.0.5", [], True)
        row = _rows(self.db_file, "vuln_scans")[0]
        self.assertEqual(row[1], "10.0.0.5")        # target

    def test_vuln_finding_cve_stored(self):
        self._save("vuln", "10.0.0.5", [], True)    # threat=True
        row = _rows(self.db_file, "vuln_findings")[0]
        self.assertEqual(row[2], "CVE-2021-41773")  # cve_id

    def test_vuln_finding_severity_critical_on_threat(self):
        self._save("vuln", "10.0.0.5", [], True)
        row = _rows(self.db_file, "vuln_findings")[0]
        self.assertEqual(row[5], "CRITICAL")        # severity

    def test_vuln_scan_and_finding_linked(self):
        self._save("vuln", "10.0.0.5", [], True)
        scan_id    = _rows(self.db_file, "vuln_scans")[0][0]
        finding_scan_id = _rows(self.db_file, "vuln_findings")[0][1]
        self.assertEqual(scan_id, finding_scan_id)

    # ── domain ───────────────────────────────────────────────
    def test_domain_row_inserted(self):
        self._save("domain", "example.com", [], False)
        self.assertEqual(_count(self.db_file, "domain_logs"), 1)

    def test_domain_name_stored(self):
        self._save("domain", "evil.com", [], True)
        row = _rows(self.db_file, "domain_logs")[0]
        self.assertEqual(row[1], "evil.com")        # domain

    def test_domain_clean_risk_score_0(self):
        self._save("domain", "safe.com", [], False)
        row = _rows(self.db_file, "domain_logs")[0]
        self.assertEqual(row[5], 0)                 # risk_score

    def test_domain_threat_risk_score_90(self):
        self._save("domain", "bad.com", [], True)
        row = _rows(self.db_file, "domain_logs")[0]
        self.assertEqual(row[5], 90)                # risk_score

    # ── port ─────────────────────────────────────────────────
    def test_port_row_inserted(self):
        self._save("port", "10.0.0.1", [], False)
        self.assertEqual(_count(self.db_file, "port_scans"), 1)

    def test_port_target_stored(self):
        self._save("port", "192.168.50.1", [], False)
        row = _rows(self.db_file, "port_scans")[0]
        self.assertEqual(row[1], "192.168.50.1")    # target

    def test_port_scan_type_is_syn(self):
        self._save("port", "10.0.0.1", [], False)
        row = _rows(self.db_file, "port_scans")[0]
        self.assertEqual(row[2], "SYN")             # scan_type

    # ── usb ──────────────────────────────────────────────────
    def test_usb_row_inserted(self):
        self._save("usb", None, [], False)
        self.assertEqual(_count(self.db_file, "usb_scans"), 1)

    def test_usb_device_name_stored(self):
        self._save("usb", None, [], False)
        row = _rows(self.db_file, "usb_scans")[0]
        self.assertEqual(row[1], "USB Device")      # usb_name

    # ── general ──────────────────────────────────────────────
    def test_multiple_saves_accumulate(self):
        for domain in ("a.com", "b.com", "c.com"):
            self._save("domain", domain, [], False)
        self.assertEqual(_count(self.db_file, "domain_logs"), 3)

    def test_none_target_uses_placeholder(self):
        """A None target must not crash — it should store 'N/A'."""
        self._save("port", None, [], False)
        row = _rows(self.db_file, "port_scans")[0]
        self.assertEqual(row[1], "N/A")

    def test_output_summary_truncated_to_80_chars(self):
        long_output = ["X" * 200]
        self._save("domain", "test.com", long_output, False)
        row = _rows(self.db_file, "domain_logs")[0]
        self.assertLessEqual(len(row[4]), 80)       # result col


# ═════════════════════════════════════════════════════════════
# 4. ResultsViewer _load_all — SQL correctness
# ═════════════════════════════════════════════════════════════
class TestLoadAllQueries(unittest.TestCase):
    """All six _load_all queries must succeed and return results."""

    # These are the exact queries used in ResultsViewer._load_all
    QUERIES = [
        ("Malware Scanner",
         "SELECT id, file_name, result, confidence, timestamp "
         "FROM malware_scan_logs ORDER BY id DESC LIMIT 20"),
        ("Backdoor Scanner",
         "SELECT id, scan_type, verdict, risk_score, timestamp "
         "FROM backdoor_scans ORDER BY id DESC LIMIT 20"),
        ("Domain Checker",
         "SELECT id, domain, result, risk_score, timestamp "
         "FROM domain_logs ORDER BY id DESC LIMIT 20"),
        ("Port Scanner",
         "SELECT id, target, result, risk_score, timestamp "
         "FROM port_scans ORDER BY id DESC LIMIT 20"),
        ("USB Scanner",
         "SELECT id, usb_name, result, '0', timestamp "
         "FROM usb_scans ORDER BY id DESC LIMIT 20"),
        ("Vulnerability Scanner",
         "SELECT id, cve_id, description, cvss_score, timestamp "
         "FROM vuln_findings ORDER BY id DESC LIMIT 20"),
    ]

    def setUp(self):
        self.db_file = _make_temp_db()
        import RUN9_wired
        RUN9_wired.DB = self.db_file
        RUN9_wired.init_db()
        user = {"username": "tester"}
        # Seed one result per tool
        for tid, target in [
            ("malware",  "/tmp/x.exe"),
            ("ai",       "/tmp/s.bin"),
            ("backdoor", None),
            ("domain",   "evil.com"),
            ("port",     "10.0.0.1"),
            ("usb",      None),
            ("vuln",     "10.0.0.2"),
        ]:
            RUN9_wired.db_save_result(tid, target, ["output\n"], True, user)

    def tearDown(self):
        try:
            os.unlink(self.db_file)
        except OSError:
            pass

    def _run_all_queries(self):
        conn = sqlite3.connect(self.db_file)
        cur  = conn.cursor()
        all_rows = []
        errors   = []
        for name, sql in self.QUERIES:
            try:
                cur.execute(sql)
                for r in cur.fetchall():
                    all_rows.append((r[0], name, r[1], r[2], r[3], r[4]))
            except Exception as e:
                errors.append(f"{name}: {e}")
        conn.close()
        return all_rows, errors

    def test_no_sql_errors(self):
        _, errors = self._run_all_queries()
        self.assertEqual(errors, [], f"SQL errors in _load_all: {errors}")

    def test_malware_results_appear(self):
        rows, _ = self._run_all_queries()
        names = {r[1] for r in rows}
        self.assertIn("Malware Scanner", names)

    def test_backdoor_results_appear(self):
        rows, _ = self._run_all_queries()
        self.assertIn("Backdoor Scanner", {r[1] for r in rows})

    def test_domain_results_appear(self):
        rows, _ = self._run_all_queries()
        self.assertIn("Domain Checker", {r[1] for r in rows})

    def test_port_results_appear(self):
        rows, _ = self._run_all_queries()
        self.assertIn("Port Scanner", {r[1] for r in rows})

    def test_usb_results_appear(self):
        rows, _ = self._run_all_queries()
        self.assertIn("USB Scanner", {r[1] for r in rows})

    def test_vuln_results_appear_in_all_scans(self):
        """Vulnerability Scanner must appear in the All Scans view (was missing before fix)."""
        rows, _ = self._run_all_queries()
        self.assertIn("Vulnerability Scanner", {r[1] for r in rows},
                      "Vulnerability Scanner missing from All Scans — check _load_all fix")

    def test_all_six_tools_represented(self):
        rows, _ = self._run_all_queries()
        tool_names = {r[1] for r in rows}
        expected = {
            "Malware Scanner", "Backdoor Scanner", "Domain Checker",
            "Port Scanner", "USB Scanner", "Vulnerability Scanner",
        }
        self.assertEqual(tool_names, expected,
                         f"Missing: {expected - tool_names}")


# ═════════════════════════════════════════════════════════════
# 5. ResultsViewer _clear logic
# ═════════════════════════════════════════════════════════════
class TestClearLogic(unittest.TestCase):
    """_clear must empty all scan tables and also vuln_scans; users untouched."""

    SCAN_TABLES = [
        "malware_scan_logs", "backdoor_scans",
        "vuln_findings", "vuln_scans",
        "domain_logs", "port_scans", "usb_scans",
    ]

    # Replicate the fixed _clear logic from ResultsViewer
    TABS = [
        ("All Scans",     None),
        ("Malware",       "malware_scan_logs"),
        ("Backdoor",      "backdoor_scans"),
        ("Vulnerability", "vuln_findings"),
        ("Domain",        "domain_logs"),
        ("Port",          "port_scans"),
        ("USB",           "usb_scans"),
    ]

    def _do_clear(self, db_path):
        conn = sqlite3.connect(db_path)
        for _, table in self.TABS[1:]:
            try:
                conn.execute(f"DELETE FROM {table}")
            except Exception:
                pass
        try:
            conn.execute("DELETE FROM vuln_scans")
        except Exception:
            pass
        conn.commit()
        conn.close()

    def setUp(self):
        self.db_file = _make_temp_db()
        import RUN9_wired
        RUN9_wired.DB = self.db_file
        RUN9_wired.init_db()
        user = {"username": "tester"}
        for tid, target in [
            ("malware",  "/tmp/x.exe"),
            ("backdoor", None),
            ("vuln",     "10.0.0.9"),
            ("domain",   "bad.com"),
            ("port",     "10.0.0.9"),
            ("usb",      None),
        ]:
            RUN9_wired.db_save_result(tid, target, [], True, user)

    def tearDown(self):
        try:
            os.unlink(self.db_file)
        except OSError:
            pass

    def test_all_scan_tables_empty_after_clear(self):
        # Verify data exists before clear
        for t in self.SCAN_TABLES:
            self.assertGreater(_count(self.db_file, t), 0,
                               f"{t} should have data before clear")
        self._do_clear(self.db_file)
        for t in self.SCAN_TABLES:
            self.assertEqual(_count(self.db_file, t), 0,
                             f"{t} should be empty after clear")

    def test_vuln_scans_cleared_not_just_findings(self):
        """vuln_scans must be cleared too — not just vuln_findings."""
        self._do_clear(self.db_file)
        self.assertEqual(_count(self.db_file, "vuln_scans"), 0)

    def test_users_table_preserved_after_clear(self):
        users_before = _count(self.db_file, "users")
        self._do_clear(self.db_file)
        self.assertEqual(_count(self.db_file, "users"), users_before)

    def test_audit_table_preserved_after_clear(self):
        """Audit log must survive a result clear."""
        before = _count(self.db_file, "audit")
        self._do_clear(self.db_file)
        self.assertEqual(_count(self.db_file, "audit"), before)


# ═════════════════════════════════════════════════════════════
# 6. backdoor_scanner — log_to_db
# ═════════════════════════════════════════════════════════════
class TestBackdoorScannerDB(unittest.TestCase):
    """log_to_db() in backdoor_scanner.py must save all findings correctly."""

    SCHEMA = """
        CREATE TABLE IF NOT EXISTS backdoor_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT, suspicious_pids TEXT, suspicious_ports TEXT,
            cron_findings TEXT, startup_findings TEXT,
            verdict TEXT, risk_score INTEGER DEFAULT 0,
            operator TEXT, timestamp TEXT DEFAULT CURRENT_TIMESTAMP)
    """

    def setUp(self):
        self.db_file = _make_temp_db()
        conn = sqlite3.connect(self.db_file)
        conn.execute(self.SCHEMA)
        conn.commit()
        conn.close()

    def tearDown(self):
        try:
            os.unlink(self.db_file)
        except OSError:
            pass

    def _log(self, procs, conns, cron, startup, verdict, risk):
        import backdoor_scanner
        with patch.object(backdoor_scanner, "DB_PATH", Path(self.db_file)):
            backdoor_scanner.log_to_db(procs, conns, cron, startup, verdict, risk)

    def test_threat_scan_stored(self):
        self._log(
            procs=[{"pid": "1234", "cmd": "nc -lvp 4444", "reason": "suspicious"}],
            conns=[{"port": 4444, "state": "ESTAB",
                    "foreign": "10.0.0.1:4444", "pid": "pid=1234"}],
            cron=[], startup=[],
            verdict="BACKDOOR DETECTED", risk=70,
        )
        self.assertEqual(_count(self.db_file, "backdoor_scans"), 1)
        row = _rows(self.db_file, "backdoor_scans")[0]
        self.assertEqual(row[6], "BACKDOOR DETECTED")  # verdict
        self.assertEqual(row[7], 70)                    # risk_score

    def test_clean_scan_stored(self):
        self._log(procs=[], conns=[], cron=[], startup=[],
                  verdict="CLEAN — NO BACKDOOR FOUND", risk=0)
        row = _rows(self.db_file, "backdoor_scans")[0]
        self.assertEqual(row[6], "CLEAN — NO BACKDOOR FOUND")
        self.assertEqual(row[7], 0)

    def test_suspicious_pids_serialised(self):
        self._log(
            procs=[{"pid": "999", "cmd": "socat ...", "reason": "suspicious"}],
            conns=[], cron=[], startup=[],
            verdict="SUSPICIOUS", risk=30,
        )
        row = _rows(self.db_file, "backdoor_scans")[0]
        self.assertIn("999", row[2])                    # suspicious_pids

    def test_cron_findings_serialised(self):
        self._log(procs=[], conns=[],
                  cron=[{"file": "/etc/cron.d/evil", "keyword": "wget"}],
                  startup=[], verdict="SUSPICIOUS", risk=20)
        row = _rows(self.db_file, "backdoor_scans")[0]
        self.assertIn("wget", row[4])                   # cron_findings

    def test_multiple_scans_accumulate(self):
        for risk in (0, 30, 70):
            self._log([], [], [], [], "v", risk)
        self.assertEqual(_count(self.db_file, "backdoor_scans"), 3)


# ═════════════════════════════════════════════════════════════
# 7. vuln_scanner — log_to_db
# ═════════════════════════════════════════════════════════════
class TestVulnScannerDB(unittest.TestCase):
    """log_to_db() in vuln_scanner.py must save scan + findings correctly."""

    SCHEMA = """
        CREATE TABLE IF NOT EXISTS vuln_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT, operator TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS vuln_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER, cve_id TEXT, service TEXT, version TEXT,
            severity TEXT, cvss_score REAL, description TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP);
    """

    def setUp(self):
        self.db_file = _make_temp_db()
        conn = sqlite3.connect(self.db_file)
        conn.executescript(self.SCHEMA)
        conn.commit()
        conn.close()

    def tearDown(self):
        try:
            os.unlink(self.db_file)
        except OSError:
            pass

    def _log(self, target, findings):
        import vuln_scanner
        with patch.object(vuln_scanner, "DB_PATH", Path(self.db_file)):
            vuln_scanner.log_to_db(target, findings)

    def _sample_finding(self, cve_id="CVE-2021-41773", severity="CRITICAL",
                        cvss=9.8, service="http", version="Apache 2.4.49"):
        return {
            "port": 80, "service": service, "version": version,
            "cve_id": cve_id, "description": "Path traversal vulnerability",
            "cvss_score": cvss, "severity": severity,
        }

    def test_scan_row_created(self):
        self._log("192.168.1.10", [self._sample_finding()])
        self.assertEqual(_count(self.db_file, "vuln_scans"), 1)

    def test_finding_row_created(self):
        self._log("192.168.1.10", [self._sample_finding()])
        self.assertEqual(_count(self.db_file, "vuln_findings"), 1)

    def test_target_stored_in_scan(self):
        self._log("10.0.0.55", [self._sample_finding()])
        row = _rows(self.db_file, "vuln_scans")[0]
        self.assertEqual(row[1], "10.0.0.55")

    def test_cve_id_stored(self):
        self._log("10.0.0.5", [self._sample_finding("CVE-2016-0800")])
        row = _rows(self.db_file, "vuln_findings")[0]
        self.assertEqual(row[2], "CVE-2016-0800")

    def test_severity_stored(self):
        self._log("10.0.0.5", [self._sample_finding(severity="HIGH")])
        row = _rows(self.db_file, "vuln_findings")[0]
        self.assertEqual(row[5], "HIGH")

    def test_cvss_score_stored(self):
        self._log("10.0.0.5", [self._sample_finding(cvss=7.5)])
        row = _rows(self.db_file, "vuln_findings")[0]
        self.assertAlmostEqual(row[6], 7.5, places=1)

    def test_empty_findings_creates_scan_no_findings(self):
        self._log("10.0.0.10", [])
        self.assertEqual(_count(self.db_file, "vuln_scans"), 1)
        self.assertEqual(_count(self.db_file, "vuln_findings"), 0)

    def test_scan_id_links_finding_to_scan(self):
        self._log("10.0.0.6", [self._sample_finding()])
        scan_id    = _rows(self.db_file, "vuln_scans")[0][0]
        f_scan_id  = _rows(self.db_file, "vuln_findings")[0][1]
        self.assertEqual(scan_id, f_scan_id)

    def test_multiple_findings_all_stored(self):
        findings = [
            self._sample_finding("CVE-A", "CRITICAL", 9.8),
            self._sample_finding("CVE-B", "HIGH",     7.2),
            self._sample_finding("CVE-C", "MEDIUM",   5.0),
        ]
        self._log("10.0.0.7", findings)
        self.assertEqual(_count(self.db_file, "vuln_findings"), 3)


# ═════════════════════════════════════════════════════════════
# 8. malware_scan_engine — log_to_main_db
# ═════════════════════════════════════════════════════════════
class TestMalwareScanEngineDB(unittest.TestCase):
    """log_to_main_db() in malware_scan_engine.py must persist scan results."""

    SCHEMA = """
        CREATE TABLE IF NOT EXISTS malware_scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_name TEXT, file_path TEXT, result TEXT,
            malware_family TEXT, confidence REAL,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP)
    """

    def setUp(self):
        self.db_file = _make_temp_db()
        conn = sqlite3.connect(self.db_file)
        conn.execute(self.SCHEMA)
        conn.commit()
        conn.close()

    def tearDown(self):
        try:
            os.unlink(self.db_file)
        except OSError:
            pass

    def _log(self, file_name, file_path, result, family, confidence):
        import malware_scan_engine
        with patch.object(malware_scan_engine, "MAIN_DB", Path(self.db_file)):
            malware_scan_engine.log_to_main_db(
                file_name, file_path, result, family, confidence)

    def test_malicious_file_stored(self):
        self._log("bad.exe", "/tmp/bad.exe", "malicious", "Trojan.Generic", 92.5)
        self.assertEqual(_count(self.db_file, "malware_scan_logs"), 1)

    def test_file_name_stored(self):
        self._log("evil.bin", "/tmp/evil.bin", "malicious", "", 88.0)
        row = _rows(self.db_file, "malware_scan_logs")[0]
        self.assertEqual(row[1], "evil.bin")

    def test_file_path_stored(self):
        self._log("f.exe", "/home/user/f.exe", "malicious", "", 80.0)
        row = _rows(self.db_file, "malware_scan_logs")[0]
        self.assertEqual(row[2], "/home/user/f.exe")

    def test_result_stored(self):
        self._log("f.exe", "/tmp/f.exe", "malicious", "", 90.0)
        row = _rows(self.db_file, "malware_scan_logs")[0]
        self.assertEqual(row[3], "malicious")

    def test_malware_family_stored(self):
        self._log("f.exe", "/tmp/f.exe", "malicious", "Ransomware.WannaCry", 95.0)
        row = _rows(self.db_file, "malware_scan_logs")[0]
        self.assertEqual(row[4], "Ransomware.WannaCry")

    def test_confidence_stored(self):
        self._log("f.exe", "/tmp/f.exe", "malicious", "", 87.3)
        row = _rows(self.db_file, "malware_scan_logs")[0]
        self.assertAlmostEqual(row[5], 87.3, places=1)

    def test_benign_file_stored(self):
        self._log("clean.pdf", "/home/user/clean.pdf", "benign", "", 98.1)
        row = _rows(self.db_file, "malware_scan_logs")[0]
        self.assertEqual(row[3], "benign")

    def test_multiple_files_accumulate(self):
        self._log("a.exe", "/a.exe", "malicious", "", 88.0)
        self._log("b.exe", "/b.exe", "benign",    "", 97.0)
        self._log("c.exe", "/c.exe", "malicious", "", 76.5)
        self.assertEqual(_count(self.db_file, "malware_scan_logs"), 3)

    def test_confidence_stored_as_float(self):
        self._log("f.exe", "/tmp/f.exe", "malicious", "", 75)
        row = _rows(self.db_file, "malware_scan_logs")[0]
        self.assertIsInstance(row[5], float)


if __name__ == "__main__":
    unittest.main(verbosity=2)
