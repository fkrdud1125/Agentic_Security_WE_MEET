"""Findings must be understandable locally: real code, a concrete impact and a fix, but never a whole secret."""
import json
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from model_answers import plan_answer, review_answer
from scanner.detectors import secrets
from vibescan import cli, inference

KEY = "sk_live_" + "a1B2c3D4e5F6g7H8i9J0"
GIT = ["-c", "user.name=T", "-c", "user.email=t@e.invalid", "-c", "commit.gpgsign=false"]


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(self.enterContext(TemporaryDirectory()))
        self.repo = self.base / "repo"
        self.repo.mkdir()
        (self.repo / "app.py").write_text(
            "import sqlite3\n"
            "\n"
            "# billing client\n"
            f'STRIPE_KEY = "{KEY}"\n'
            "\n"
            "def find(db, title):\n"
            "    query = \"SELECT * FROM notes WHERE title = '\" + title + \"'\"\n"
            "    return db.execute(query).fetchone()\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.repo), *GIT, "commit", "-qm", "x"], check=True)

    def test_evidence_is_real_code_with_only_the_secret_masked(self):
        with patch("scanner.static.semgrep", return_value=[]):
            folder, _, _ = cli.scan(self.repo, self.base / "out", self.base / "state", offline=True)
        raw = (folder / "scan_result.json").read_text(encoding="utf-8")
        self.assertNotIn(KEY, raw)
        secret = next(f for f in json.loads(raw)["findings"] if f["location"]["line"] == 4)
        self.assertIn('>    4 | STRIPE_KEY = "sk_l••••"', secret["evidence"])
        self.assertIn("# billing client", secret["evidence"])  # surrounding code is shown as is
        self.assertIn("'STRIPE_KEY'", secret["impact_ko"])
        self.assertIn('+STRIPE_KEY = os.environ["STRIPE_KEY"]', secret["fix_diff"])
        self.assertIn("근거 코드:", json.loads(raw)["report_md"])

    def test_model_receives_sanitized_snippets_not_the_local_evidence(self):
        with patch("scanner.static.semgrep", return_value=[]), \
                patch.object(cli, "access_token", return_value="t"), \
                patch.object(inference, "model_for", return_value="m"), \
                patch.object(inference, "ask", side_effect=[plan_answer(), review_answer([{"id": "F-001", "severity": "High"}])]) as ask:
            cli.scan(self.repo, self.base / "out", self.base / "state")
        sent = json.dumps([call.args for call in ask.call_args_list], ensure_ascii=False)
        self.assertNotIn("sk_l", sent)
        self.assertNotIn("# billing client", sent)  # comments are stripped from model context
        self.assertNotIn('"evidence"', sent)

    def test_identifier_words_and_lockfiles_are_not_credentials(self):
        found = lambda name, text: [h.line for h in secrets.detect(name, text) if h.severity.value != "Info"]
        # From a public repository: vocabulary lists, UI keys and npm package names.
        self.assertEqual(found("service.py", 'GROUP_KEY_NAME_TOKENS = (\n    "department",\n    "category",\n)\n'), [])
        self.assertEqual(found("service.py", 'NAME_TOKENS = ("department", "category")\n'), [])
        self.assertEqual(found("Workbench.tsx", 'const tab = { key: "analysis" as const };\n'), [])
        self.assertEqual(found("frontend/package-lock.json", '"js-tokens": "^3.0.0 || ^4.0.0"\n'), [])
        # Real credentials keep being reported.
        self.assertEqual(found("app.py", 'password = "letmeinnow"\n'), [1])
        self.assertEqual(found("frontend/package-lock.json", '"token": "ghp_' + "a1B2c3D4e5F6g7H8i9J0k1L2" + '"\n'), [1])

    def test_secret_fix_for_javascript(self):
        hit = secrets.detect("server.js", f'const STRIPE_KEY = "{KEY}";\n')[0]
        self.assertIn("+const STRIPE_KEY = process.env.STRIPE_KEY;", hit.fix)
        self.assertNotIn(KEY, hit.fix)

    def test_every_rule_explains_its_impact_and_shows_a_fix(self):
        for path in sorted(Path(__file__).resolve().parents[1].glob("rules/vibescan/*.yml")):
            for rule in json.loads(path.read_text(encoding="utf-8"))["rules"]:
                meta = rule["metadata"]["vibescan"]
                with self.subTest(rule=rule["id"]):
                    self.assertGreater(len(meta.get("impact_ko", "")), 30)
                    self.assertTrue(meta.get("fix_example", "").startswith("-"))


if __name__ == "__main__":
    unittest.main()
