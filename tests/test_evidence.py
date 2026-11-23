"""Findings must be understandable locally: real code, a concrete impact and a fix, but never a whole secret."""
import json
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from model_answers import review_answer
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
        from test_assessment import answer_for
        def answer(*args):
            payload = args[-1]
            return answer_for(payload) if isinstance(payload, dict) else review_answer(payload)
        with patch("scanner.static.semgrep", return_value=[]), \
                patch.object(cli, "access_token", return_value="t"), \
                patch.object(inference, "model_for", return_value="m"), \
                patch.object(inference, "ask", side_effect=answer) as ask:
            cli.scan(self.repo, self.base / "out", self.base / "state")
        self.assertGreaterEqual(ask.call_count, 2)
        sent = json.dumps([call.args for call in ask.call_args_list], ensure_ascii=False)
        self.assertNotIn("sk_l", sent)
        self.assertNotIn("# billing client", sent)  # comments are stripped from model context
        self.assertNotIn('"evidence"', json.dumps(ask.call_args_list[0].args))
        self.assertNotIn('app.py', sent)  # Both stages send aliases, never source paths.

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

    def test_reading_keys_from_the_environment_or_placeholders_is_not_a_leak(self):
        found = lambda name, text: [h.line for h in secrets.detect(name, text + "\n")]
        # The real key lives in a git-ignored .env; committed code only names the variable.
        for name, text in [("app.py", 'api_key = os.environ["OPENAI_API_KEY"]'),
                           ("app.py", 'api_key = os.getenv("OPENAI_API_KEY")'),
                           ("app.py", "client = OpenAI(api_key=settings.openai_api_key)"),
                           ("app.py", 'headers = {"Authorization": f"Bearer {api_key}"}'),
                           ("api.ts", "const apiKey = process.env.OPENAI_API_KEY;"),
                           ("api.ts", "const apiKey = import.meta.env.VITE_API_KEY;"),
                           # A library parameter filled with a word, not a credential (seen in a real repo).
                           ("codex.py", 'llm = ChatCodex(api_key="codex-oauth")'),
                           ("app.py", 'OPENAI_API_KEY = "your-api-key-here"')]:
            with self.subTest(text=text):
                self.assertEqual(found(name, text), [])
        # Hard-coded generated keys and human-chosen passwords are still reported.
        self.assertEqual(found("app.py", 'API_KEY = "a8F3kQ9zL2mX7pR4tV6w"'), [1])
        self.assertEqual(found("app.py", 'API_TOKEN = "5f4dcc3b5aa765d61d8327deb882cf99"'), [1])
        self.assertEqual(found("app.py", 'password = (\n    "letmeinnow"\n)'), [2])  # name and value on different lines

    def test_secret_fix_for_javascript(self):
        hit = secrets.detect("server.js", f'const STRIPE_KEY = "{KEY}";\n')[0]
        self.assertIn("+const STRIPE_KEY = process.env.STRIPE_KEY;", hit.fix)
        self.assertNotIn(KEY, hit.fix)

    def test_field_identifiers_are_not_credentials(self):
        cases = {
            "AdminOnlyAspect.java": 'private static final String DETAIL_EVALUATION_ERROR_KEY = "detailEvaluationError";',
            "messages.ts": 'const CACHE_KEY = "HTTPResponseErrorV2"; // password is handled elsewhere',
            "view.json": '{"key": "isAccountLockedByPolicy", "tokenLabel": "Choose a password"}',
            "config.py": 'SECRET_KEY_ENV_NAME = "APPLICATION_SIGNING_KEY"\nPASSWORD_LABEL = "New password"\n'
                         'TOKENIZER = "VocabularyModelV2"\nFIELDS_KEY = (\n "detailEvaluationError",\n)',
        }
        for name, source in cases.items():
            with self.subTest(name=name):
                self.assertEqual(secrets.detect(name, source), [])

    def test_neighboring_names_do_not_weaken_credentials_or_masking(self):
        text = ('FIELD_KEY = "detailEvaluationError"; adminPassword = "letmeinnow"\n'
                f'ERROR_LABEL = "{KEY}"\n'
                'signing = {"SECRET_KEY": "dev"}\n'
                'ACCESS_KEY = "A7qaB!93dH82tTK9"\n')
        hits = secrets.detect("config.py", text)
        self.assertEqual([(h.line, h.rule_id) for h in hits],
                         [(1, "literal-token"), (2, "literal-token"), (3, "weak-signing-key"), (4, "literal-token")])
        self.assertIn("detailEvaluationError", secrets.hidden_values(text))
        self.assertNotIn("detailEvaluationError", {h.secret for h in hits})

    def test_application_keys_and_public_token_addresses(self):
        address = '0x' + 'a1' * 20
        source = f'''class Case {{
            String idempotencyKey = "e2e-audit-created-" + UUID.randomUUID();
            String orderKey = "0x{'a1' * 32}";
            String tmpObjectKey = "uploads/admin/test/" + UUID.randomUUID() + ".png";
            String token = "{address}";
            String 실제password = "prefix-constant-123456" /* generated later */
                + shortToken();
            String secretKey = "{KEY}" + getSuffix();
        }}'''
        hits = secrets.detect("src/test/java/Case.java", source)
        self.assertEqual([(h.line, h.severity.value) for h in hits], [(8, 'High')])
        self.assertEqual(secrets.detect("app.yml", f'token-contract-address: "{address}"'), [])

    def test_dynamic_password_prefix_vs_complete_literal(self):
        source = '''class Case { void run() {
            String password = "FixedPass1234!"
                + uniqueToken().substring(0, 8);
            password = "FixedPass1234!";
        }}'''
        self.assertEqual([h.line for h in secrets.detect("Case.java", source)], [4])

    def test_export_masks_short_sibling_and_clipped_secrets(self):
        from scanner.static import inspect
        long_value = "Aa19" * 60
        (self.base / "config.py").write_text(
            f'SECRET_KEY = "dev"; password = "second-private"; api_token = "{long_value}"; backup_password = "Pin789"\n'
            'other_password = (\n    "Pin456"\n)\n'
        )
        with patch("scanner.static.semgrep", return_value=[]):
            findings = inspect(self.base, ["config.py"])
        self.assertTrue(findings)
        for finding in findings:
            for value in ("dev", "second-private", long_value[:12], "Pin789", "Pin456"):
                self.assertNotIn(value, finding.evidence + finding.fix_diff)

    def test_every_rule_explains_its_impact_and_shows_a_fix(self):
        for path in sorted(Path(__file__).resolve().parents[1].glob("rules/vibescan/*.yml")):
            for rule in json.loads(path.read_text(encoding="utf-8"))["rules"]:
                meta = rule["metadata"]["vibescan"]
                with self.subTest(rule=rule["id"]):
                    self.assertGreater(len(meta.get("impact_ko", "")), 30)
                    self.assertTrue(meta.get("fix_example", "").startswith("-"))


if __name__ == "__main__":
    unittest.main()
