import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from fastapi.testclient import TestClient

from scanner.models import ScanResult
from test_history import sample
from vibescan import cli
from vibescan.dashboard import dashboard_app


class DashboardTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name) / "scans"
        self.client = TestClient(dashboard_app(self.root, "127.0.0.1:8765", "test-ticket"),
                                 base_url="http://127.0.0.1:8765")
        self.addCleanup(self.client.close)
        self.headers = {"X-VibeScan-Token": "test-ticket"}

    def save(self, data):
        folder = self.root / data["scan_id"]
        folder.mkdir(parents=True)
        path = folder / "scan_result.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_empty_does_not_create_results_or_database(self):
        response = self.client.get("/api/scans", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["scans"], [])
        self.assertFalse(self.root.exists())

    def test_history_detail_and_report_reuse_engine_schema(self):
        data = sample()
        data["findings"][0]["evidence"] = '<script>alert("test")</script>'
        self.save(data)
        newer = dict(data, scan_id="scan-2", scanned_at="2026-11-18T00:00:00Z")
        self.save(newer)
        listing = self.client.get("/api/scans", headers=self.headers).json()
        self.assertEqual([s["scan_id"] for s in listing["scans"]], ["scan-2", "scan-1"])
        self.assertNotIn("findings", listing["scans"][0])
        response = self.client.get("/api/scans/scan-1", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        detail = response.json()
        self.assertEqual(detail["summary"]["High"], 1)
        self.assertEqual(detail["report_md"], "PRIVATE-REPORT")
        self.assertIsNone(detail["findings"][0]["change"])
        self.assertEqual(detail["findings"][0]["evidence"], data["findings"][0]["evidence"])
        self.assertEqual(ScanResult.from_json(response.text).scan_id, "scan-1")
        self.assertEqual(list(self.root.rglob("*.sqlite3")), [])

    def test_local_access_boundary_and_asset_allowlist(self):
        self.save(sample())
        self.assertEqual(self.client.get("/api/scans").status_code, 403)
        self.assertEqual(self.client.get("/api/scans/scan-1", headers={"X-VibeScan-Token": "wrong"}).status_code, 403)
        for extra, status in [({"Host": "evil.example"}, 400),
                              ({"Origin": "https://evil.example"}, 403),
                              ({"Origin": "null"}, 403),
                              ({"Origin": "http://127.0.0.1:8765"}, 200)]:
            with self.subTest(extra=extra):
                self.assertEqual(self.client.get("/api/scans", headers=self.headers | extra).status_code, status)
        page = self.client.get("/")
        self.assertEqual(page.status_code, 200)
        self.assertNotIn("test-ticket", page.text)
        self.assertNotIn("PRIVATE-EVIDENCE", page.text)
        self.assertEqual(page.headers["cache-control"], "no-store")
        self.assertIn("frame-ancestors 'none'", page.headers["content-security-policy"])
        for asset in ("dashboard.js", "dashboard.css"):
            self.assertEqual(self.client.get("/assets/" + asset).status_code, 200)
        self.assertEqual(self.client.get("/assets/dashboard.py").status_code, 404)
        self.assertEqual(self.client.post("/api/scans", headers=self.headers).status_code, 405)

    def test_corrupt_missing_mismatched_and_oversized_results(self):
        good = self.save(sample())
        bad = self.root / "broken"
        bad.mkdir()
        (bad / "scan_result.json").write_text("PRIVATE-invalid-json")
        data = dict(sample(), scan_id="mismatch")
        mismatch = self.save(data)
        mismatch.write_text(json.dumps(sample()))
        self.assertEqual(self.client.get("/api/scans", headers=self.headers).json()["unavailable"], 2)
        for scan_id, status in (("broken", 422), ("mismatch", 422), ("missing", 404), ("..%5Coutside", 404)):
            response = self.client.get("/api/scans/" + scan_id, headers=self.headers)
            self.assertEqual(response.status_code, status)
            self.assertNotIn("PRIVATE", response.text)
        good.write_bytes(b" " * (16 * 1024 * 1024 + 1))
        self.assertEqual(self.client.get("/api/scans/scan-1", headers=self.headers).status_code, 422)

    def test_symlink_cannot_escape_results_folder(self):
        path = self.save(sample())
        outside = self.root.parent / "outside.json"
        path.rename(outside)
        try:
            path.symlink_to(outside)
        except OSError:
            self.skipTest("Creating symlinks is not allowed on this system")
        self.assertEqual(self.client.get("/api/scans/scan-1", headers=self.headers).status_code, 404)

    def test_cli_default_and_custom_output_directory(self):
        for args, expected in ((["vibescan"], self.root),
                               (["vibescan", "dashboard", "--results", str(self.root.parent / "custom")], self.root.parent / "custom")):
            with self.subTest(args=args), patch("sys.argv", args), \
                 patch.object(cli, "data_dir", return_value=self.root.parent), \
                 patch("vibescan.dashboard.serve") as serve:
                cli.main()
                serve.assert_called_once_with(expected)
