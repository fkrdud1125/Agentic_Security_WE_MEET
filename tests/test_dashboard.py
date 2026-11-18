import json
import os
import shutil
import subprocess
import threading
import time
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
        self.directory = self.root.parent / "state"
        self.client = self.enterContext(TestClient(
            dashboard_app(self.root, "127.0.0.1:8765", "test-ticket", self.directory),
            base_url="http://127.0.0.1:8765"))
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

    def repository(self):
        repo = self.root.parent / "repo"
        repo.mkdir()
        (repo / "app.py").write_text('API_TOKEN = "test-credential-value"\n')
        subprocess.run(["git", "-C", str(repo), "init", "-q", "-b", "main"], check=True)
        self.commit(repo)
        return repo

    def commit(self, repo):
        subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
        subprocess.run(["git", "-C", str(repo), "-c", "user.name=Test", "-c",
                        "user.email=test@example.invalid", "-c", "commit.gpgsign=false",
                        "commit", "-qm", "sample"], check=True)
        return subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"]).decode().strip()

    def wait_scan(self):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            job = self.client.get("/api/scan", headers=self.headers).json()
            if job["state"] != "running":
                return job
            time.sleep(0.02)
        self.fail("Scan did not finish")

    def test_repo_connection_is_validated_deduplicated_and_persistent(self):
        self.assertEqual(self.client.get("/api/repos", headers=self.headers).json(), {"repos": []})
        self.assertFalse(self.directory.exists())
        repo = self.repository()
        (repo / "child").mkdir()
        for path, reason in ((self.root.parent, "Git 저장소가 아니"), (repo / "child", "하위 폴더"),
                             (repo / "missing", "찾을 수 없습니다")):
            response = self.client.post("/api/repos", headers=self.headers, json={"path": str(path)})
            self.assertEqual(response.status_code, 422)
            self.assertIn(reason, response.json()["detail"])
        for path in (str(repo), str(repo) + "/."):
            response = self.client.post("/api/repos", headers=self.headers, json={"path": path})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["branch"], "main")
        app = dashboard_app(self.root, "127.0.0.1:8765", "new-ticket", self.directory)
        with TestClient(app, base_url="http://127.0.0.1:8765") as reopened:
            rows = reopened.get("/api/repos", headers={"X-VibeScan-Token": "new-ticket"}).json()["repos"]
            self.assertEqual(rows, [{"path": str(repo.resolve()), "name": "repo"}])
        with TestClient(dashboard_app(repo / "out", "127.0.0.1:8765", "test-ticket", self.directory),
                        base_url="http://127.0.0.1:8765") as inside:
            response = inside.post("/api/repos", headers=self.headers, json={"path": str(repo)})
            self.assertEqual(response.status_code, 422)
            self.assertIn("저장소 안에", response.json()["detail"])

    def test_scan_posts_require_access_and_a_connected_repository(self):
        repo = self.repository()
        body = {"path": str(repo)}
        with patch("vibescan.dashboard.scan") as engine:
            for endpoint in ("/api/repos", "/api/scan"):
                self.assertEqual(self.client.post(endpoint, json=body).status_code, 403)
                self.assertEqual(self.client.post(endpoint, headers=self.headers | {"Origin": "https://outside.invalid"}, json=body).status_code, 403)
            self.assertEqual(self.client.post("/api/scan", headers=self.headers, json=body).status_code, 404)
            self.assertEqual(self.client.post("/api/scan", headers=self.headers, json=body | {"offline": "false"}).status_code, 422)
            self.assertEqual(self.client.post("/api/repos", headers=self.headers, json=body | {"command": "anything"}).status_code, 422)
            engine.assert_not_called()

    def test_real_scan_and_rescan_use_latest_head_without_model_by_default(self):
        repo = self.repository()
        self.client.post("/api/repos", headers=self.headers, json={"path": str(repo)})
        ids = []
        with patch("vibescan.cli.access_token") as token:
            for value in ("first", "second"):
                (repo / "app.py").write_text(f'API_TOKEN = "test-credential-{value}"\n')
                head = self.commit(repo)
                response = self.client.post("/api/scan", headers=self.headers, json={"path": str(repo)})
                self.assertEqual(response.status_code, 202)
                self.assertTrue(response.json()["offline"])
                job = self.wait_scan()
                self.assertEqual(job["state"], "completed", job)
                ids.append(job["scan_id"])
                saved = self.client.get("/api/scans/" + job["scan_id"], headers=self.headers).json()
                self.assertEqual(saved["commit"], head)
                self.assertEqual(len(saved["findings"]), 1)
                self.assertNotIn("test-credential-", json.dumps(saved))
            token.assert_not_called()
        self.assertEqual(len(set(ids)), 2)
        self.assertEqual(len(self.client.get("/api/scans", headers=self.headers).json()["scans"]), 2)

    def test_duplicate_scan_is_rejected_and_failure_preserves_previous_results(self):
        repo = self.repository()
        self.client.post("/api/repos", headers=self.headers, json={"path": str(repo)})
        old = self.save(sample())
        before = old.read_bytes()
        release = threading.Event()

        def fail(*args, **kwargs):
            release.wait(5)
            raise RuntimeError("PRIVATE-PROVIDER-ERROR")

        with patch("vibescan.dashboard.scan", side_effect=fail) as engine:
            try:
                body = {"path": str(repo), "offline": False}
                self.assertEqual(self.client.post("/api/scan", headers=self.headers, json=body).status_code, 202)
                self.assertEqual(self.client.post("/api/scan", headers=self.headers, json=body).status_code, 409)
                self.assertEqual(self.client.get("/api/scan", headers=self.headers).json()["state"], "running")
                self.assertEqual(self.client.get("/api/scans/scan-1", headers=self.headers).status_code, 200)
            finally:
                release.set()
            job = self.wait_scan()
            self.assertEqual(job["state"], "failed")
            self.assertNotIn("PRIVATE", json.dumps(job))
            engine.assert_called_once_with(repo.resolve(), self.root.resolve(), self.directory.resolve(), offline=False)
        self.assertEqual(old.read_bytes(), before)
        with patch("vibescan.dashboard.scan", return_value=(old.parent, "quota reached", "limit")):
            self.assertEqual(self.client.post("/api/scan", headers=self.headers, json={"path": str(repo)}).status_code, 202)
            job = self.wait_scan()
            self.assertEqual((job["state"], job["issue"]), ("completed", "limit"))

    def wait_login(self):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            data = self.client.get("/api/auth", headers=self.headers).json()
            if data["login"]["state"] != "running":
                return data
            time.sleep(0.02)
        self.fail("Login did not finish")

    def test_login_status_and_single_login_window(self):
        self.assertEqual(self.client.get("/api/auth").status_code, 403)
        self.assertEqual(self.client.post("/api/login", json={}).status_code, 403)
        self.assertEqual(self.client.get("/api/auth", headers=self.headers).json()["state"], "register")
        release = threading.Event()

        def signed_in(directory, open_url, done):
            self.assertEqual(directory, self.directory.resolve())
            self.assertEqual(done, "http://127.0.0.1:8765/")
            self.assertTrue(open_url("http://127.0.0.1:9999/auth/login?key=k"))
            release.wait(5)
            return "로그인 완료 · 구독 사용 가능"

        with patch("vibescan.dashboard.login", side_effect=signed_in), \
                patch("vibescan.dashboard.status", return_value={"state": "ready", "message": "ok"}):
            try:
                self.assertEqual(self.client.post("/api/login", headers=self.headers, json={}).status_code, 202)
                self.assertEqual(self.client.post("/api/login", headers=self.headers, json={}).status_code, 409)
                deadline = time.monotonic() + 5
                while "url" not in self.client.get("/api/auth", headers=self.headers).json()["login"]:
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.02)
            finally:
                release.set()
            data = self.wait_login()
            self.assertEqual((data["state"], data["login"]["state"]), ("ready", "completed"))
        with patch("vibescan.dashboard.login", side_effect=ValueError("PRIVATE-CODE")), \
                patch("vibescan.dashboard.status", side_effect=OSError("PRIVATE-PATH")):
            self.client.post("/api/login", headers=self.headers, json={})
            data = self.wait_login()
            self.assertEqual((data["state"], data["login"]["state"]), ("login", "failed"))
            self.assertNotIn("PRIVATE", json.dumps(data))

    def test_github_url_is_cloned_validated_and_refreshed_before_rescan(self):
        remote = self.root.parent / "remote"
        source = remote / "owner" / "demo"
        source.parent.mkdir(parents=True)
        shutil.move(self.repository(), source)
        # Redirect github.com to the local folder so clone and fetch run for real without a network.
        redirect = {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": f"url.{remote.as_uri()}/.insteadOf",
                    "GIT_CONFIG_VALUE_0": "https://github.com/"}
        with patch.dict(os.environ, redirect):
            for url in ("https://github.com/owner", "https://gitlab.com/owner/demo", "https://github.com/owner/..",
                        "https://github.com/owner/demo/extra", "http://github.com/owner/demo"):
                response = self.client.post("/api/repos", headers=self.headers, json={"path": url})
                self.assertEqual(response.status_code, 422, url)
                self.assertIn("형식", response.json()["detail"])
            response = self.client.post("/api/repos", headers=self.headers, json={"path": "https://github.com/owner/missing"})
            self.assertEqual(response.status_code, 422)
            self.assertIn("복제하지 못했습니다", response.json()["detail"])
            self.assertFalse((self.directory / "github/owner/missing").exists())

            # An empty repository and a leftover interrupted clone must not block a later connection.
            empty = remote / "owner" / "empty"
            subprocess.run(["git", "init", "-q", "-b", "main", str(empty)], check=True)
            response = self.client.post("/api/repos", headers=self.headers, json={"path": "https://github.com/owner/empty"})
            self.assertEqual(response.status_code, 422)
            self.assertIn("빈 저장소", response.json()["detail"])
            self.assertFalse((self.directory / "github/owner/empty").exists())
            leftover = self.directory / "github/.partial/owner/empty"
            leftover.mkdir(parents=True)
            (leftover / "half-written").write_text("x")
            (empty / "app.py").write_text("print(1)\n")
            self.commit(empty)
            response = self.client.post("/api/repos", headers=self.headers, json={"path": "https://github.com/owner/empty"})
            self.assertEqual(response.status_code, 200, response.text)
            self.assertFalse(leftover.exists())

            response = self.client.post("/api/repos", headers=self.headers, json={"path": "https://github.com/owner/demo"})
            self.assertEqual(response.status_code, 200, response.text)
            clone = self.directory.resolve() / "github" / "owner" / "demo"
            self.assertEqual(response.json()["path"], str(clone))
            again = self.client.post("/api/repos", headers=self.headers, json={"path": " git@github.com:owner/demo.git "})
            self.assertEqual(again.json()["path"], str(clone))

            (source / "app.py").write_text('API_TOKEN = "test-credential-newer"\n')
            head = self.commit(source)
            with patch("vibescan.cli.access_token") as token:
                self.client.post("/api/scan", headers=self.headers, json={"path": str(clone)})
                job = self.wait_scan()
                token.assert_not_called()
            self.assertEqual(job["state"], "completed", job)
            self.assertEqual(self.client.get("/api/scans/" + job["scan_id"], headers=self.headers).json()["commit"], head)

            source.rename(source.with_name("moved"))  # git objects are read-only, so rmtree fails on Windows
            self.client.post("/api/scan", headers=self.headers, json={"path": str(clone)})
            job = self.wait_scan()
            self.assertEqual(job["state"], "failed")
            self.assertIn("최신 커밋", job["message"])

    def test_fixable_engine_error_is_shown_but_others_stay_generic(self):
        repo = self.repository()
        self.client.post("/api/repos", headers=self.headers, json={"path": str(repo)})
        for error, shown in ((cli.ScanInputError("검사 가능한 텍스트 파일이 없습니다."), "텍스트 파일이 없습니다"),
                             (ValueError("PRIVATE-SOURCE"), "스캔에 실패했습니다")):
            with patch("vibescan.dashboard.scan", side_effect=error):
                self.client.post("/api/scan", headers=self.headers, json={"path": str(repo)})
                job = self.wait_scan()
            self.assertEqual(job["state"], "failed")
            self.assertIn(shown, job["message"])
            self.assertNotIn("PRIVATE", job["message"])

    def test_logout_forgets_tokens_and_reports_status(self):
        self.assertEqual(self.client.post("/api/logout", json={}).status_code, 403)
        with patch("vibescan.dashboard.logout") as forget, \
                patch("vibescan.dashboard.status", return_value={"state": "login", "message": "로그인 필요"}):
            data = self.client.post("/api/logout", headers=self.headers, json={}).json()
            forget.assert_called_once_with(self.directory.resolve())
            self.assertEqual(data["state"], "login")
        with patch("vibescan.dashboard.logout", side_effect=OSError("PRIVATE-PATH")):
            response = self.client.post("/api/logout", headers=self.headers, json={})
            self.assertEqual(response.status_code, 503)
            self.assertNotIn("PRIVATE", response.text)
