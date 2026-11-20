import json
import sqlite3
import unittest
from contextlib import closing
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

from scanner.history import compare, list_scans, save_scan
from scanner.models import Change, ScanResult


def sample():
    return {
        "scan_id": "scan-1", "app_name": "sample",
        "target": {"source": "./sample", "url": None},
        "scanned_at": "2026-11-17T19:00:00+09:00", "risk_score": 20,
        "profile": {"framework": "Flask", "routes": 1, "auth": None},
        "findings": [{
            "id": "F-001", "title": "샘플", "severity": "High", "confidence": "Likely",
            "location": {"file": "app.py", "line": 12}, "cwe": "CWE-89", "owasp": "A03",
            "evidence": "PRIVATE-EVIDENCE", "how_found": ["static:semgrep"],
            "impact_ko": "", "remediation_ko": "", "fix_diff": "PRIVATE-DIFF",
        }], "report_md": "PRIVATE-REPORT",
    }


class HistoryTests(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = Path(tmp.name) / "history.sqlite3"

    def test_legacy_result(self):
        result = ScanResult.from_json(json.dumps(sample()))
        data = json.loads(result.to_json())
        self.assertIsNone(data["commit"])
        self.assertIsNone(data["findings"][0]["change"])
        self.assertEqual(data["scan_type"], "full")
        self.assertEqual(data["trigger"], "manual")
        self.assertEqual(data["delta"], {"new": 0, "fixed": 0})
        self.assertEqual(data["summary"]["High"], 1)
        self.assertEqual(ScanResult.from_json(result.to_json()), result)

    def test_compare_matches_by_fingerprint(self):
        base = ScanResult.from_json(json.dumps(sample())).findings[0]
        old = lambda fid, fp, file="app.py", **kw: replace(base, id=fid, fingerprint=fp, location=replace(base.location, file=file), **kw)
        previous = ScanResult.from_json(json.dumps(sample()))
        previous.commit = "c1"
        previous.findings = [old("F-001", "same", introduced_in="c0"), old("F-002", "same", introduced_in="c0"),
                             old("F-003", "gone"), old("F-004", "broken", file="half.py"),
                             old("F-007", "flow", file="Store.java", trace=[{'file': 'Service.java'}]),
                             old("F-005", "old-fix", change=Change.FIXED)]
        now = [old("F-001", "same"), old("F-002", "fresh")]
        kept, gone = compare(now, previous, "c2", ["half.py", "Service.java"])
        self.assertEqual([(f.change, f.introduced_in) for f in now], [(Change.EXISTING, "c0"), (Change.NEW, "c2")])
        # One of two identical fingerprints vanished, so exactly one is fixed; the unparsed file stays open.
        self.assertEqual(sorted(f.fingerprint for f in gone), ["gone", "same"])
        self.assertTrue(all(f.change == Change.FIXED for f in gone))
        self.assertEqual([(f.fingerprint, f.change) for f in kept], [("broken", Change.EXISTING), ("flow", Change.EXISTING)])
        self.assertTrue(all(f.evidence != base.evidence and not f.fix_diff for f in kept + gone))
        self.assertEqual(previous.findings[2].change, None)  # the stored previous result is not mutated
        previous.findings.append(old("F-006", ""))
        self.assertIsNone(compare([old("F-001", "same")], previous, "c3"))

    def test_commit_scan_snapshots_and_delta(self):
        data = sample()
        del data["target"], data["app_name"]
        data.update(repo={"name": "sample", "path": "./sample", "branch": "main"},
                    commit="abc1234", baseline_commit="def5678", scan_type="diff", trigger="git-hook")
        result = ScanResult.from_json(json.dumps(data))
        finding = result.findings[0]
        result.findings = [
            replace(finding, change=Change.NEW, introduced_in="abc1234"),
            replace(finding, id="F-002", change=Change.EXISTING, introduced_in="def5678"),
            replace(finding, id="F-003", change=Change.FIXED, introduced_in="def5678"),
        ]
        self.assertEqual(result.to_dict()["delta"], {"new": 1, "fixed": 1})
        self.assertEqual(result.to_dict()["summary"]["High"], 2)
        self.assertEqual(ScanResult.from_json(result.to_json()), result)
        self.assertEqual(list_scans(self.db, "./sample"), [])
        save_scan(self.db, result)
        save_scan(self.db, replace(result, scan_id="scan-2"))
        with self.assertRaises(sqlite3.IntegrityError):
            save_scan(self.db, replace(result, risk_score=99))
        rows = list_scans(self.db, "./sample")
        self.assertEqual([r["scan_id"] for r in rows], ["scan-2", "scan-1"])
        self.assertEqual(rows[1]["risk_score"], 20)
        self.assertEqual((rows[0]["new_count"], rows[0]["fixed_count"]), (1, 1))
        self.assertEqual(list_scans(self.db, "./other"), [])
        with closing(sqlite3.connect(self.db)) as db:
            records = db.execute("SELECT change, introduced_in FROM findings WHERE scan_id = ? "
                                 "ORDER BY finding_id", ("scan-1",)).fetchall()
            self.assertEqual(records, [("new", "abc1234"), ("existing", "def5678"), ("fixed", "def5678")])
            self.assertNotIn("PRIVATE-", "\n".join(db.iterdump()))

    def test_failed_finding_rolls_back_scan(self):
        result = ScanResult.from_json(json.dumps(sample()))
        result.findings *= 2
        with self.assertRaises(sqlite3.IntegrityError):
            save_scan(self.db, result)
        self.assertEqual(list_scans(self.db, "./sample"), [])
        result.findings.pop()
        save_scan(self.db, result)

    def test_diff_requires_both_commits(self):
        result = ScanResult.from_json(json.dumps(sample()))
        for head, base in [(None, "old"), ("new", None)]:
            with self.subTest(head=head, base=base), self.assertRaises(ValueError):
                replace(result, scan_type="diff", commit=head, baseline_commit=base).to_json()
