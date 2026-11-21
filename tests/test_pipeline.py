import json
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from scanner.history import list_scans
from scanner.ingest import snapshot
from scanner.models import ScanResult
from vibescan import cli, inference
from model_answers import review_answer


class PipelineTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.repo = self.base / "sample"
        self.repo.mkdir()
        self.git("init", "-q")
        (self.repo / "app.py").write_text('API_TOKEN = "private-value-Pq8Rs2Tu6V"\n')
        (self.repo / ".env.local").write_text("SENSITIVE")
        (self.repo / ".gitignore").write_text("exclude.py\n")
        (self.repo / "exclude.py").write_text("SENSITIVE")
        (self.repo / "binary.py").write_bytes(b"a\0b")
        (self.repo / ".vibescanignore").write_text("ignore.py\n.env.local\n")
        (self.repo / "ignore.py").write_text("SENSITIVE")
        (self.repo / "nested").mkdir()
        (self.repo / "nested" / "hide.py").write_text("SENSITIVE")
        (self.repo / "nested" / ".gitignore").write_text("!hide.py")
        with (self.repo / ".gitignore").open("a") as ignored:
            ignored.write("nested/\n")
        self.git("add", "-f", ".")
        oid = subprocess.check_output(["git", "-C", str(self.repo), "hash-object", "-w", "--stdin"],
                                      input=b"app.py").decode().strip()
        self.git("update-index", "--add", "--cacheinfo", f"120000,{oid},link.py")
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

    def test_criteria_lifecycle_report_and_ai_failure_preserve_static_work(self):
        for offline, fail in ((True, False), (False, False), (False, True)):
            with self.subTest(offline=offline, fail=fail):
                updates = []
                with patch("scanner.static.semgrep", return_value=[]), \
                     patch.object(cli, "access_token", return_value="t"), \
                     patch.object(inference, "model_for", return_value="m"), \
                     patch.object(inference, "ask", side_effect=(
                         inference.SessionError("사용량 한도", "limit") if fail else
                         lambda *args: review_answer(args[-1]))):
                    folder, _, _ = cli.scan(self.repo, self.base / "out", self.base / "state",
                                             offline=offline, criteria_progress=updates.append)
                data = json.loads((folder / "scan_result.json").read_text())
                self.assertTrue(all(len(rows) == 31 for rows in updates))
                row = lambda rows: next(c for c in rows if c["code"] == "IL")
                self.assertEqual(row(updates[0])["execution"], "pending")
                self.assertTrue(any(row(rows)["execution"] == "running" for rows in updates))
                final = row(data["criteria"])
                self.assertEqual(final["findings"], ["F-001"])
                # This fixture includes a skipped binary file, so static coverage remains partial
                # regardless of whether the optional AI review succeeds.
                self.assertEqual(final["execution"], "partial")
                self.assertEqual(final["ai"]["state"], "skipped" if offline else "failed" if fail else "completed")
                self.assertEqual(final["ai"]["reviewed"], 0 if offline or fail else 1)
                self.assertEqual(updates[-1], data["criteria"])
                self.assertEqual(ScanResult.from_json(json.dumps(data)).criteria, data["criteria"])
                self.assertEqual(data["report_md"], (folder / "report.md").read_text())
                for item in data["criteria"]:
                    self.assertIn(f"| {item['code']} · {item['name']} |", data["report_md"])
                self.assertEqual(len([c for c in data["criteria"] if c["framework"] == "owasp"]), 10)
                self.assertEqual(len([c for c in data["criteria"] if c["framework"] == "kisa"]), 21)

    def test_authenticated_pipeline_and_quota_fallback(self):
        out, state = self.base / "out", self.base / "state"
        review = review_answer([{"id": "F-001", "severity": "High"}])
        for response, expected_issue in ((review, None), (inference.SessionError("사용량 한도", "limit"), "limit")):
            with self.subTest(issue=expected_issue), \
                 patch("scanner.static.semgrep", return_value=[]), \
                 patch.object(cli, "access_token", return_value="private-test-token"), \
                 patch.object(inference, "model_for", return_value="model"), \
                 patch.object(cli.analysis, "plan", return_value=cli.analysis.default_coverage()) as plan, \
                 patch.object(inference, "ask", side_effect=[response]) as ask:
                folder, note, issue = cli.scan(self.repo, out, state)
            plan.assert_not_called()
            self.assertEqual(ask.call_count, 1)
            self.assertEqual(issue, expected_issue)
            result = ScanResult.from_json((folder / "scan_result.json").read_text(encoding="utf-8"))
            self.assertEqual(len(result.findings), 1)
            self.assertNotIn("private-value", str(ask.call_args_list))
            self.assertNotIn("private-value", result.to_json())
            self.assertEqual(result.report_md, (folder / "report.md").read_text(encoding="utf-8"))
            self.assertEqual([c["id"] for c in result.coverage],
                             [c["id"] for c in cli.analysis.default_coverage()])
            if expected_issue is None:
                self.assertIn("1/1", note)
                self.assertTrue(result.findings[0].triage_reason)
            else:
                self.assertIn("사용량", note)
                self.assertFalse(result.findings[0].triage_reason)
        self.assertEqual(len(list_scans(state / "scan-history.sqlite3", str(self.repo))), 2)

    def test_unreadable_or_excluded_source_keeps_previous_finding(self):
        out, state = self.base / "out", self.base / "state"
        with patch("scanner.static.semgrep", return_value=[]):
            cli.scan(self.repo, out, state, offline=True)
            for payload in (b"\xff", b"x" * (1024 * 1024 + 1), b"ignored"):
                with self.subTest(size=len(payload)):
                    (self.repo / "app.py").write_bytes(payload)
                    if payload == b"ignored":
                        (self.repo / ".vibescanignore").write_text("app.py\nignore.py\n.env.local\n")
                    self.git("add", "-u")
                    self.git("-c", "user.name=T", "-c", "user.email=t@e.invalid", "-c",
                             "commit.gpgsign=false", "commit", "-qm", "partial")
                    folder, _, _ = cli.scan(self.repo, out, state, offline=True)
                    result = json.loads((folder / "scan_result.json").read_text(encoding="utf-8"))
                    self.assertIn("app.py", result["partial_files"])
                    self.assertEqual(result["delta"]["fixed"], 0)
                    row = next(r for r in result["kisa_checklist"] if r["code"] == "CI-05")
                    self.assertEqual(row["findings"], [result["findings"][0]["id"]])

    def test_comparison_follows_branch_and_commit_ancestry(self):
        out, state = self.base / "out", self.base / "state"
        def scan():
            folder, _, _ = cli.scan(self.repo, out, state, offline=True)
            return json.loads((folder / "scan_result.json").read_text(encoding="utf-8"))

        first_branch = self.git("branch", "--show-current").decode().strip()
        with patch("scanner.static.semgrep", return_value=[]):
            self.git("switch", "-qc", "feature")
            first = scan()
            self.git("switch", "-q", first_branch)
            self.assertIsNone(scan()["baseline_commit"])
            self.git("switch", "-q", "feature")
            self.assertEqual(scan()["baseline_commit"], first["commit"])
            self.git("restore", "--", "app.py")
            self.git("switch", "--orphan", "replacement")
            (self.repo / "app.py").write_text("print(1)")
            self.git("add", "app.py")
            self.git("-c", "user.name=T", "-c", "user.email=t@example.invalid",
                     "-c", "commit.gpgsign=false", "commit", "-qm", "unrelated history")
            self.git("branch", "-M", "feature")
            rewritten = scan()
            self.assertIsNone(rewritten["baseline_commit"])
            self.assertEqual(rewritten["delta"]["fixed"], 0)

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
            self.assertEqual(send.call_args.kwargs["json"]["input"],
                             [{"role": "user", "content": "{}"}])

    def test_requests_that_disable_model_use(self):
        for status in (401, 403, 429):
            response = Mock(status_code=status)
            with self.subTest(status=status), patch("requests.request", return_value=response) as call:
                with self.assertRaises(inference.SessionError):
                    inference.request("GET", "/models", "private-test-token")
                self.assertEqual(call.call_count, 1)
                response.close.assert_called_once()

    def test_bad_request_identifies_the_failed_stage(self):
        for path, stage in (("/models", "모델 목록 조회"), ("/responses", "모델 응답 생성")):
            response = Mock(status_code=400)
            with self.subTest(path=path), patch("requests.request", return_value=response):
                with self.assertRaisesRegex(inference.SessionError, stage + " 실패 · HTTP 400"):
                    inference.request("POST", path, "private-test-token")
                response.close.assert_called_once()

    def test_scan_failure_leaves_no_success_artifacts(self):
        with patch("scanner.static.semgrep", side_effect=RuntimeError("analysis failed")):
            with self.assertRaises(RuntimeError):
                cli.scan(self.repo, self.base / "out", self.base / "state", offline=True)
        self.assertFalse((self.base / "out").exists())
        self.assertFalse((self.base / "state/scan-history.sqlite3").exists())

    def test_dismissal_updates_risk_report_and_saved_history(self):
        reply = review_answer([{"id": "F-001", "severity": "High"}])
        reply["reviews"][0].update(decision="dismiss", severity="Info", reason="테스트 전용 고정 표본으로 확인")
        with patch("scanner.static.semgrep", return_value=[]), \
                patch.object(cli, "access_token", return_value="t"), \
                patch.object(inference, "model_for", return_value="m"), \
                patch.object(inference, "ask", return_value=reply):
            folder, _, _ = cli.scan(self.repo, self.base / "out", self.base / "state")
        data = json.loads((folder / "scan_result.json").read_text(encoding="utf-8"))
        self.assertEqual(data["risk_score"], 0)
        self.assertEqual(data["summary"]["High"], 0)
        self.assertEqual(data["dismissed_count"], 1)
        self.assertIn("오탐 후보", data["report_md"])
        self.assertIn("테스트 전용", data["findings"][0]["triage_reason"])
        self.assertEqual(list_scans(self.base / "state/scan-history.sqlite3", str(self.repo))[0]["risk_score"], 0)

    def test_quota_stops_remaining_batches_and_preserves_all_findings(self):
        from dataclasses import replace
        from scanner.models import Finding, Location, Severity, Confidence
        base = Finding("F-001", "비밀값", "CWE-798", "A07", Severity.HIGH, Confidence.POTENTIAL,
                       Location("app.py", 1), "[가림]", ["static:secret"], "영향", "수정", "diff")
        findings = [replace(base, id=f"F-{i:03}") for i in range(1, 33)]
        first = review_answer([{"id": f.id, "severity": "High"} for f in findings[:5]])
        with patch.object(cli, "inspect", return_value=findings), \
                patch.object(cli, "access_token", return_value="t"), \
                patch.object(inference, "model_for", return_value="m"), \
                patch.object(inference, "ask", side_effect=[first, inference.SessionError("사용량 한도", "limit")]) as ask:
            folder, note, issue = cli.scan(self.repo, self.base / "out", self.base / "state")
        self.assertEqual(ask.call_count, 2)
        self.assertEqual(issue, "limit")
        self.assertIn("5/32", note)
        data = json.loads((folder / "scan_result.json").read_text(encoding="utf-8"))
        self.assertEqual(len(data["findings"]), 32)
        self.assertEqual(sum(bool(f["triage_reason"]) for f in data["findings"]), 5)

    def test_no_findings_skips_triage_and_unsupported_rules_are_explicit(self):
        self.git("rm", "-rf", ".")
        (self.repo / "untracked.py").unlink()
        (self.repo / "main.js").write_text("const value = 1;")
        self.git("add", ".")
        self.git("-c", "user.name=Test", "-c", "user.email=test@example.invalid", "-c",
                 "commit.gpgsign=false", "commit", "-qm", "JS only")
        with patch("scanner.static.semgrep", return_value=[]), \
                patch.object(cli, "access_token") as token, \
                patch.object(inference, "model_for") as model, \
                patch.object(cli.analysis, "plan", return_value=cli.analysis.default_coverage()) as plan, \
                patch.object(inference, "ask") as ask:
            folder, _, issue = cli.scan(self.repo, self.base / "out", self.base / "state")
        token.assert_not_called()
        model.assert_not_called()
        plan.assert_not_called()
        ask.assert_not_called()
        self.assertIsNone(issue)
        data = json.loads((folder / "scan_result.json").read_text(encoding="utf-8"))
        self.assertEqual(data["findings"], [])
        self.assertEqual({c["id"] for c in data["coverage"] if c["execution"] == "completed"}, {"secrets", "sql", "xss"})
        self.assertEqual(next(c for c in data['kisa_checklist'] if c['code']=='V-03')['status'], '수동 확인 필요')

    def test_invalid_review_preserves_local_findings_and_saved_report(self):
        with patch("scanner.static.semgrep", return_value=[]), \
                patch.object(cli, "access_token", return_value="t"), \
                patch.object(inference, "model_for", return_value="m"), \
                patch.object(inference, "ask", return_value={"reviews": []}) as ask:
            folder, note, issue = cli.scan(self.repo, self.base / "out", self.base / "state")
        ask.assert_called_once()
        self.assertEqual(issue, "error")
        data = json.loads((folder / "scan_result.json").read_text(encoding="utf-8"))
        self.assertEqual(len(data["coverage"]), 5)
        self.assertEqual(len(data["findings"]), 1)
        self.assertEqual(data["findings"][0]["triage_reason"], "")
        self.assertEqual(data["report_md"], (folder / "report.md").read_text(encoding="utf-8"))
        self.assertIn(note, data["report_md"])
        self.assertEqual(len(list_scans(self.base / "state/scan-history.sqlite3", str(self.repo))), 1)

    def test_static_analysis_precedes_authentication_and_ai_review(self):
        events = []
        inspect = cli.inspect

        def run_inspection(*args):
            findings = inspect(*args)
            events.append("static_complete")
            return findings

        def token(*args):
            events.append("authenticate")
            return "t"

        def model(*args):
            events.append("model")
            return "m"

        def answer(token, model, instruction, findings):
            events.append("review")
            return review_answer(findings)

        with patch("scanner.static.semgrep", return_value=[]), \
                patch.object(cli, "inspect", side_effect=run_inspection), \
                patch.object(cli, "access_token", side_effect=token), \
                patch.object(inference, "model_for", side_effect=model), \
                patch.object(inference, "ask", side_effect=answer), \
                patch.object(cli.analysis, "plan", return_value=cli.analysis.default_coverage()) as plan:
            _, _, issue = cli.scan(self.repo, self.base / "out", self.base / "state")
        self.assertIsNone(issue)
        plan.assert_not_called()
        self.assertEqual(events, ["static_complete", "authenticate", "model", "review"])

    def test_offline_scan_saves_local_results_without_ai_calls(self):
        with patch("scanner.static.semgrep", return_value=[]), \
                patch.object(cli, "access_token") as token, \
                patch.object(inference, "model_for") as model, \
                patch.object(cli.analysis, "plan", return_value=cli.analysis.default_coverage()) as plan, \
                patch.object(inference, "ask") as ask:
            folder, _, issue = cli.scan(self.repo, self.base / "out", self.base / "state", offline=True)
        for call in (token, model, plan, ask):
            call.assert_not_called()
        self.assertIsNone(issue)
        data = json.loads((folder / "scan_result.json").read_text(encoding="utf-8"))
        self.assertEqual(len(data["findings"]), 1)
        self.assertFalse(data["findings"][0]["triage_reason"])
        self.assertEqual(data["report_md"], (folder / "report.md").read_text(encoding="utf-8"))

    def test_no_reviewable_source_skips_authentication_and_keeps_finding(self):
        from scanner.models import Confidence, Finding, Location, Severity
        finding = Finding("F-001", "비밀값", "CWE-798", "", Severity.HIGH, Confidence.POTENTIAL,
                          Location("app.js", 1), "[가림]", ["static:secret"], "영향", "수정", "diff")
        with patch.object(cli, "inspect", return_value=[finding]), \
                patch.object(cli, "access_token") as token, \
                patch.object(inference, "model_for") as model, \
                patch.object(cli.analysis, "plan", return_value=cli.analysis.default_coverage()) as plan, \
                patch.object(inference, "ask") as ask:
            folder, note, issue = cli.scan(self.repo, self.base / "out", self.base / "state")
        for call in (token, model, plan, ask):
            call.assert_not_called()
        self.assertIsNone(issue)
        data = json.loads((folder / "scan_result.json").read_text(encoding="utf-8"))
        self.assertEqual(len(data["findings"]), 1)
        self.assertFalse(data["findings"][0]["triage_reason"])
        self.assertIn("문맥", note)
        self.assertIn(note, data["report_md"])

    def test_python_source_without_extractable_context_skips_ai_connection(self):
        source = 'BANNER = ' + repr('ordinary description ' * 400) + '\nAPI_TOKEN = "private-fixture-Pq8Rs2Tu6V"\n'
        (self.repo / "app.py").write_text(source)
        self.git("add", "app.py")
        self.git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "-qm", "large surrounding source")
        with patch("scanner.static.semgrep", return_value=[]), \
                patch.object(cli, "access_token") as token, \
                patch.object(inference, "model_for") as model, \
                patch.object(inference, "ask") as ask:
            folder, note, issue = cli.scan(self.repo, self.base / "out", self.base / "state")
        for call in (token, model, ask):
            call.assert_not_called()
        self.assertIsNone(issue)
        self.assertIn("AI 검토 불가", note)
        self.assertIn("문맥", note)
        data = json.loads((folder / "scan_result.json").read_text(encoding="utf-8"))
        self.assertEqual(len(data["findings"]), 1)
        self.assertFalse(data["findings"][0]["triage_reason"])
        self.assertIn(note, data["report_md"])

    def test_unextractable_candidates_do_not_consume_review_limit(self):
        from dataclasses import replace
        from scanner.models import Confidence, Finding, Location, Severity
        source = ('BANNER = ' + repr('ordinary description ' * 400)
                  + '\nAPI_TOKEN = "private-fixture-Pq8Rs2Tu6V"\n' + '\n' * 20
                  + 'SECOND_KEY = "private-fixture-Xq7Lm2Pz9Wr4"\n')
        (self.repo / "app.py").write_text(source)
        self.git("add", "app.py")
        self.git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "-qm", "mixed context sizes")
        base = Finding("F-001", "비밀값", "CWE-798", "", Severity.HIGH, Confidence.POTENTIAL,
                       Location("app.py", 2), "[가림]", ["static:secret"], "영향", "수정", "diff")
        findings = [replace(base, id=f"F-{i:03}") for i in range(1, 31)]
        findings.append(replace(base, id="F-031", location=Location("app.py", len(source.splitlines()))))
        with patch.object(cli, "inspect", return_value=findings), \
                patch.object(cli, "access_token", return_value="t") as token, \
                patch.object(inference, "model_for", return_value="m") as model, \
                patch.object(inference, "ask", side_effect=lambda token, model, instruction, batch: review_answer(batch)) as ask:
            folder, note, issue = cli.scan(self.repo, self.base / "out", self.base / "state")
        self.assertIsNone(issue)
        token.assert_called_once()
        model.assert_called_once()
        ask.assert_called_once()
        self.assertEqual([item["id"] for item in ask.call_args.args[3]], ["F-031"])
        data = json.loads((folder / "scan_result.json").read_text(encoding="utf-8"))
        self.assertEqual(len(data["findings"]), 31)
        self.assertEqual([f["id"] for f in data["findings"] if f["triage_reason"]], ["F-031"])
        self.assertIn("1/31", note)
        self.assertIn("문맥", note)
        self.assertEqual(data["report_md"], (folder / "report.md").read_text(encoding="utf-8"))

    def test_connection_failures_preserve_local_results_and_history(self):
        for failure in ("authentication", "model"):
            with self.subTest(failure=failure), \
                    patch("scanner.static.semgrep", return_value=[]), \
                    patch.object(cli, "access_token", return_value="t") as token, \
                    patch.object(inference, "model_for", return_value="m") as model, \
                    patch.object(inference, "ask") as ask:
                if failure == "authentication":
                    token.side_effect = inference.SessionError("로그인 필요", "login")
                else:
                    model.side_effect = ValueError("invalid model response")
                folder, note, issue = cli.scan(self.repo, self.base / "out", self.base / "state")
            ask.assert_not_called()
            self.assertEqual(issue, "login" if failure == "authentication" else "error")
            data = json.loads((folder / "scan_result.json").read_text(encoding="utf-8"))
            self.assertEqual(len(data["findings"]), 1)
            self.assertFalse(data["findings"][0]["triage_reason"])
            self.assertIn(note, data["report_md"])
            self.assertEqual(data["report_md"], (folder / "report.md").read_text(encoding="utf-8"))
        self.assertEqual(len(list_scans(self.base / "state/scan-history.sqlite3", str(self.repo))), 2)

    def test_static_failure_does_not_authenticate_or_call_ai(self):
        with patch.object(cli, "inspect", side_effect=RuntimeError("analysis failed")), \
                patch.object(cli, "access_token") as token, \
                patch.object(inference, "model_for") as model, \
                patch.object(inference, "ask") as ask:
            with self.assertRaisesRegex(RuntimeError, "analysis failed"):
                cli.scan(self.repo, self.base / "out", self.base / "state")
        for call in (token, model, ask):
            call.assert_not_called()
        self.assertFalse((self.base / "out").exists())
        self.assertFalse((self.base / "state/scan-history.sqlite3").exists())

    def test_review_limit_keeps_unreviewed_findings_and_uses_only_six_batches(self):
        from dataclasses import replace
        from scanner.models import Confidence, Finding, Location, Severity
        base = Finding("F-001", "비밀값", "CWE-798", "", Severity.HIGH, Confidence.POTENTIAL,
                       Location("app.py", 1), "[가림]", ["static:secret"], "영향", "수정", "diff")
        findings = [replace(base, id=f"F-{i:03}") for i in range(1, 33)]
        with patch.object(cli, "inspect", return_value=findings), \
                patch.object(cli, "access_token", return_value="t"), \
                patch.object(inference, "model_for", return_value="m"), \
                patch.object(cli.analysis, "plan", return_value=cli.analysis.default_coverage()) as plan, \
                patch.object(inference, "ask", side_effect=lambda token, model, instruction, batch: review_answer(batch)) as ask:
            folder, note, issue = cli.scan(self.repo, self.base / "out", self.base / "state")
        plan.assert_not_called()
        self.assertIsNone(issue)
        self.assertEqual(ask.call_count, 6)
        self.assertEqual([len(call.args[3]) for call in ask.call_args_list], [5] * 6)
        reviewed_ids = [item["id"] for call in ask.call_args_list for item in call.args[3]]
        self.assertEqual(len(set(reviewed_ids)), 30)
        data = json.loads((folder / "scan_result.json").read_text(encoding="utf-8"))
        self.assertEqual(len(data["findings"]), 32)
        self.assertEqual(sum(bool(f["triage_reason"]) for f in data["findings"]), 30)
        self.assertIn("30/32", note)
        self.assertIn("30", note)
        self.assertEqual(data["report_md"], (folder / "report.md").read_text(encoding="utf-8"))

    def test_background_review_sends_only_new_high_findings_and_reports_progress(self):
        out, state = self.base / "out", self.base / "state"
        with patch("scanner.static.semgrep", return_value=[]):
            cli.scan(self.repo, out, state, offline=True)
            (self.repo / "app.py").write_text('API_TOKEN = "private-value-Pq8Rs2Tu6V"\nSECOND_KEY = "private-value-Xq7Lm2Pz9Wr4"\n')
            self.git("add", "app.py")
            self.git("-c", "user.name=Test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false",
                     "commit", "-qm", "second secret")
            steps = []
            with patch.object(cli, "access_token", return_value="t"), \
                    patch.object(inference, "model_for", return_value="m"), \
                    patch.object(cli.analysis, "plan", return_value=cli.analysis.default_coverage()) as plan, \
                    patch.object(cli.analysis, "review", side_effect=lambda ctx, batch, *a: len(batch)) as review:
                folder, note, _ = cli.scan(self.repo, out, state, new_high_only=True,
                                           progress=lambda stage, text: steps.append((stage, text)))
        plan.assert_not_called()  # background scans spare the quota: no planning call
        sent = [f for call in review.call_args_list for f in call.args[1]]
        self.assertTrue(sent)
        self.assertTrue(all(f.change == "new" and f.severity in ("Critical", "High") for f in sent))
        data = json.loads((folder / "scan_result.json").read_text(encoding="utf-8"))
        self.assertEqual(len(sent), sum(f["change"] == "new" for f in data["findings"]))
        self.assertIn("새 High 이상만", note)
        self.assertEqual(sorted({stage for stage, _ in steps}), [0, 1, 2, 3, 4])
        self.assertEqual([stage for stage, _ in steps], sorted(stage for stage, _ in steps))
        self.assertNotIn("private-value", json.dumps(steps, ensure_ascii=False))

    def test_background_scan_without_new_high_findings_skips_ai_connection(self):
        out, state = self.base / "out", self.base / "state"
        with patch("scanner.static.semgrep", return_value=[]):
            cli.scan(self.repo, out, state, offline=True)
            with patch.object(cli, "access_token") as token, \
                    patch.object(inference, "model_for") as model, \
                    patch.object(cli.analysis, "plan", return_value=cli.analysis.default_coverage()) as plan, \
                    patch.object(inference, "ask") as ask:
                folder, _, issue = cli.scan(self.repo, out, state, new_high_only=True)
        for call in (token, model, plan, ask):
            call.assert_not_called()
        self.assertIsNone(issue)
        data = json.loads((folder / "scan_result.json").read_text(encoding="utf-8"))
        self.assertEqual(len(data["findings"]), 1)
        self.assertEqual(data["findings"][0]["change"], "existing")
        self.assertEqual(data["delta"]["new"], 0)
        self.assertTrue(data["baseline_commit"])

    def test_paths_differing_only_in_case_do_not_fail_the_scan(self):
        repo = self.base / "case"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        blob = subprocess.check_output(["git", "-C", str(repo), "hash-object", "-w", "--stdin"],
                                       input=b'API_TOKEN = "private-value-Pq8Rs2Tu6V"\n').decode().strip()
        for name in ("Config.py", "config.py"):  # made on Linux; one file on Windows and macOS
            subprocess.run(["git", "-C", str(repo), "update-index", "--add", "--cacheinfo", f"100644,{blob},{name}"], check=True)
        subprocess.run(["git", "-C", str(repo), "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                        "-c", "commit.gpgsign=false", "commit", "-qm", "case"], check=True)
        with patch("scanner.static.semgrep", return_value=[]):
            folder, _, _ = cli.scan(repo, self.base / "out", self.base / "state", offline=True)
        data = json.loads((folder / "scan_result.json").read_text(encoding="utf-8"))
        scanned = {f["location"]["file"] for f in data["findings"]}
        # Every path is either scanned or reported as not checked, never silently dropped.
        self.assertEqual(scanned | set(data["partial_files"]), {"Config.py", "config.py"})
