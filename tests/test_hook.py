import json
import os
import sqlite3
import subprocess
import time
import unittest
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import ANY, patch

from scanner.models import Trigger
from vibescan import hook

GIT = ["-c", "user.name=Test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false"]


class HookTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.repo = self.base / "repo"
        self.repo.mkdir()
        (self.repo / "app.py").write_text('API_TOKEN = "test-credential-value"\n')
        subprocess.run(["git", "-C", str(self.repo), "init", "-q", "-b", "main"], check=True)
        self.head = self.commit("first")
        self.hook = self.repo / ".git/hooks/post-commit"

    def commit(self, message, env=None):
        subprocess.run(["git", "-C", str(self.repo), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.repo), *GIT, "commit", "-qm", message], check=True, env=env)
        return subprocess.check_output(["git", "-C", str(self.repo), "rev-parse", "HEAD"]).decode().strip()

    def connect(self, directory):
        directory.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(directory / "scan-history.sqlite3")) as db, db:
            db.execute("CREATE TABLE IF NOT EXISTS connected_repos(path TEXT PRIMARY KEY NOT NULL)")
            db.execute("INSERT INTO connected_repos VALUES (?)", (str(self.repo.resolve()),))

    def test_install_never_overwrites_other_hooks(self):
        self.assertFalse(hook.installed(self.repo))
        hook.install(self.repo)
        self.assertTrue(hook.installed(self.repo))
        self.assertIn("hook-trigger", self.hook.read_text(encoding="utf-8"))
        hook.install(self.repo)  # reinstalling our own hook is fine
        hook.uninstall(self.repo)
        self.assertFalse(self.hook.exists())

        self.hook.write_text("#!/bin/sh\necho mine\n")
        with self.assertRaises(ValueError):
            hook.install(self.repo)
        hook.uninstall(self.repo)
        self.assertEqual(self.hook.read_text(), "#!/bin/sh\necho mine\n")

        subprocess.run(["git", "-C", str(self.repo), "config", "core.hooksPath", ".husky"], check=True)
        with self.assertRaises(ValueError):
            hook.install(self.repo)
        self.assertFalse((self.repo / ".husky").exists())

    def test_trigger_scans_only_connected_repos_at_the_latest_commit(self):
        state = self.base / "state"
        with patch("vibescan.cli.scan", return_value=(state / "scans/x", "", None)) as scan:
            self.assertIsNone(hook.trigger(self.repo, self.head, state, wait=0))  # not connected
            self.connect(state)
            self.assertIsNone(hook.trigger(self.repo, "an-older-commit", state, wait=0))  # a newer hook will scan
            scan.assert_not_called()
            hook.trigger(self.repo, self.head, state, wait=0)
            scan.assert_called_once_with(self.repo.resolve(), state / "scans", state, offline=True,
                                         trigger=Trigger.GIT_HOOK, progress=ANY, new_high_only=False)
        with patch("vibescan.cli.scan", side_effect=ValueError("검사 실패 사유")):
            hook.trigger(self.repo, self.head, state, wait=0)
        self.assertIn("검사 실패 사유", (state / "hook.log").read_text(encoding="utf-8"))

    def test_real_commit_runs_a_background_scan_without_waiting(self):
        # Point the hook's data folder at a temp directory instead of the user's real one.
        env = os.environ | {"LOCALAPPDATA": str(self.base), "XDG_CONFIG_HOME": str(self.base)}
        state = self.base / "vibescan"
        self.connect(state)
        hook.install(self.repo)
        (self.repo / "app.py").write_text('API_TOKEN = "test-credential-newer"\n')
        started = time.monotonic()
        head = self.commit("second", env)
        self.assertLess(time.monotonic() - started, hook.DEBOUNCE)  # the commit did not wait for the scan
        deadline = time.monotonic() + 90
        results = []
        while not results and time.monotonic() < deadline:
            time.sleep(0.5)
            results = list((state / "scans").glob("*/scan_result.json"))
        self.assertTrue(results, (state / "hook.log").read_text(encoding="utf-8") if (state / "hook.log").exists() else "no log")
        data = json.loads(results[0].read_text(encoding="utf-8"))
        self.assertEqual((data["commit"], data["trigger"]), (head, "git-hook"))
        self.assertNotIn("test-credential-", json.dumps(data))

    def test_trigger_follows_consent_and_clears_its_live_progress(self):
        state = self.base / "state"
        self.connect(state)
        seen = []

        def fake(*args, progress, **kwargs):
            progress(3, "발견 후보 1건")
            seen.append((kwargs, json.loads((state / "live.json").read_text(encoding="utf-8"))))
            return state / "scans/x", "", None

        hook.save_settings(state, background_llm=True)
        with patch("vibescan.cli.scan", side_effect=fake):
            hook.trigger(self.repo, self.head, state, wait=0)
        kwargs, live = seen[0]
        self.assertEqual((kwargs["offline"], kwargs["new_high_only"]), (False, True))
        self.assertEqual((live["stage"], live["log"], live["commit"]), (3, ["발견 후보 1건"], self.head))
        self.assertFalse((state / "live.json").exists())
