import json
import os
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from scanner.history import list_scans
from scanner.ingest import snapshot
from scanner.models import ScanResult
from vibescan import cli, inference


class PipelineTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.repo = self.base / "sample"
        self.repo.mkdir()
        self.git("init", "-q")
        (self.repo / "app.py").write_text('API_TOKEN = "private-value-1234"\n')
        (self.repo / ".env.local").write_text("SENSITIVE")
        (self.repo / ".gitignore").write_text("exclude.py\n")
        (self.repo / "exclude.py").write_text("SENSITIVE")
        (self.repo / "binary.py").write_bytes(b"a\0b")
        (self.repo / ".vibescanignore").write_text("ignore.py\n")
        (self.repo / "ignore.py").write_text("SENSITIVE")
        self.git("add", "-f", ".")
        self.git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "-qm", "sample")
        (self.repo / "app.py").write_text("dirty = True")
        (self.repo / "untracked.py").write_text("untracked = True")

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args])

    def test_snapshot_reads_committed_sources(self):
        dest = self.base / "snapshot"
        dest.mkdir()
        commit, _, files = snapshot(self.repo, dest)
        self.assertEqual(commit, self.git("rev-parse", "HEAD").decode().strip())
        self.assertEqual(files, ["app.py"])
        self.assertIn("API_TOKEN", (dest / "app.py").read_text())

    def test_authenticated_pipeline_and_quota_fallback(self):
        out, state = self.base / "out", self.base / "state"
        plan = {"checks": cli.CHECKS[::-1]}
        review = {"reviews": [{"id": "F-001", "impact": "인증정보 노출 가능", "fix": "환경변수로 이동하세요.",
                                "confidence": "Likely"}]}
        for response in ([plan, review], [inference.SessionError("사용량 한도")]):
            with patch("scanner.static.semgrep", return_value=[]), \
                 patch.object(cli, "access_token", return_value="private-test-token"), \
                 patch.object(inference, "model_for", return_value="model"), \
                 patch.object(inference, "ask", side_effect=response) as ask:
                folder, note = cli.scan(self.repo, out, state)
            result = ScanResult.from_json((folder / "scan_result.json").read_text(encoding="utf-8"))
            self.assertEqual(len(result.findings), 1)
            self.assertNotIn("private-value", str(ask.call_args_list))
            self.assertNotIn("private-value", result.to_json())
            self.assertEqual(result.report_md, (folder / "report.md").read_text(encoding="utf-8"))
            if len(response) == 2:
                self.assertEqual(result.checklist, plan["checks"])
                self.assertIn("1/1", note)
            else:
                self.assertIn("사용량", note)
        self.assertEqual(len(list_scans(state / "scan-history.sqlite3", str(self.repo))), 2)

    def test_stream_requires_completion(self):
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=None)
        delta = b'data: {"type":"response.output_text.delta","delta":"{}"}'
        with patch.object(inference, "request", return_value=response) as send:
            response.iter_lines.return_value = [delta]
            with self.assertRaises(inference.SessionError):
                inference.ask("t", "m", "instructions", {})
            response.iter_lines.return_value = [delta, b'data: {"type":"response.completed"}']
            self.assertEqual(inference.ask("t", "m", "instructions", {}), {})
            self.assertFalse(send.call_args.kwargs["json"]["store"])
            self.assertTrue(send.call_args.kwargs["json"]["stream"])
