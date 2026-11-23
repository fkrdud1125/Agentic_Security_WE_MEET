import copy
import json
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scanner.assessment import prepare, public_assessments, select_findings, structural_source
from scanner.context import Context
from scanner.criteria import build_criteria
from scanner.detectors.policy import detect
from scanner.models import ScanResult
from scanner.normalize import RawHit, normalize
from vibescan import analysis, cli, inference


def answer_for(payload, candidate=False):
    results = []
    for row in payload['criteria']:
        evidence = row['evidence'][0]
        offset, quote = next((i, line.strip()) for i, line in enumerate(evidence['code'].splitlines())
                             if len(line.strip()) >= 3)
        citations = [{'id': evidence['id'], 'line': evidence['start'] + offset, 'quote': quote[:100]}]
        results.append({'id': row['id'], 'outcome': 'candidate' if candidate else 'unassessed',
                        'reason': '호출자와 업무 정책 추가 확인 필요', 'citations': citations,
                        'candidates': [{'title': '복구 흐름 추가 검토', 'reason': '발급 대상과 만료 검증 확인 필요',
                                        'remediation': '테스트 계정으로 만료·재사용 확인', 'citations': citations}] if candidate else []})
    return {'assessments': results}


class AssessmentTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.files = ['auth.py', 'auth.ts', 'Auth.java']
        (self.root / 'auth.py').write_text('def reset_password(token):\n    return token\n', encoding='utf-8')
        (self.root / 'auth.ts').write_text('const password = "private-credential-123456";\nfunction login(user) { return authenticate(user); } // confidential\n', encoding='utf-8')
        (self.root / 'Auth.java').write_text('class Auth { void login() { authenticate(); } }', encoding='utf-8')
        self.context = Context(self.root, self.files)
        self.rows = build_criteria()
        self.prepared = prepare(self.context, self.root, self.files, self.rows)

    def test_multiple_languages_redaction_and_empty_evidence(self):
        packets = json.dumps(self.prepared)
        self.assertNotIn('private-credential-123456', packets)
        self.assertNotIn('confidential', packets)
        paths = {e['path'] for item in self.prepared.values() for e in item['packet']}
        self.assertEqual(paths, set(self.files))
        self.assertEqual(self.prepared['kisa:PR']['state'], 'pending')
        self.assertEqual(self.prepared['kisa:DI']['state'], 'skipped')
        self.assertEqual(self.prepared['kisa:DI']['feature'], 'unknown')
        self.assertNotIn('packet', public_assessments(self.prepared)['kisa:PR'])

    def test_ambiguous_nonpython_context_stays_local(self):
        for code in ('const token = `secret-${value}`;', 'const x = /secret/;', 'int x = a / b;',
                     'String x = """secret""";', '/* unfinished', 'const x = "unfinished'):
            self.assertEqual(structural_source(code), '')
        self.assertEqual(structural_source('// secret\nlogin("hidden");'), '\nlogin("[LITERAL]");')
        self.assertEqual(structural_source(r'\u0022hidden\u0022'), '')

    def test_deployment_context_only_sends_allowed_values(self):
        name = 'nginx.conf'
        (self.root / name).write_text('# internal host\nautoindex on;\nssl_certificate_key /private/secret.pem;\n', encoding='utf-8')
        files = self.files + [name]
        context = Context(self.root, files)
        prepared = prepare(context, self.root, files, self.rows)
        packet = prepared['kisa:DI']['packet']
        self.assertEqual(packet[0]['path'], name)
        self.assertIn('autoindex on;', packet[0]['code'])
        self.assertNotIn('secret.pem', json.dumps(prepared))
        self.assertNotIn('internal host', json.dumps(prepared))

    def test_validated_criterion_candidates_do_not_change_static_execution(self):
        rows = [r for r in self.rows if r['framework'] == 'kisa' and r['code'] == 'PR']
        with patch.object(inference, 'ask', side_effect=lambda *args: answer_for(args[-1], True)) as ask:
            self.assertEqual(analysis.review_criteria(self.context, rows, self.prepared, 't', 'm'), 1)
        sent = ask.call_args.args[-1]
        self.assertNotIn('path', sent['criteria'][0]['evidence'][0])
        self.assertNotIn('auth.py', json.dumps(sent))
        result = build_criteria(assessments=public_assessments(self.prepared))
        row = next(r for r in result if r['framework'] == 'kisa' and r['code'] == 'PR')
        self.assertEqual(row['execution'], 'unknown')
        self.assertEqual(row['assessment']['state'], 'completed')
        self.assertEqual(row['assessment']['outcome'], 'candidate')
        self.assertEqual(row['assessment']['dynamic'], 'not_run')
        self.assertEqual(row['findings'], [])
        self.assertEqual(row['assessment']['candidates'][0]['evidence'][0]['file'], 'auth.py')

    def test_bad_citation_duplicate_and_missing_rows_are_atomic(self):
        rows = [r for r in self.rows if r['framework'] == 'kisa' and r['code'] in ('PR', 'IA')]
        original = copy.deepcopy(self.prepared)
        def broken(payload, kind):
            answer = answer_for(payload)
            if kind == 'quote':
                answer['assessments'][-1]['citations'][0]['quote'] = 'invented_code()'
            elif kind == 'line':
                answer['assessments'][-1]['citations'][0]['line'] = 999
            elif kind == 'duplicate':
                answer['assessments'][-1]['id'] = answer['assessments'][0]['id']
            else:
                answer['assessments'].pop()
            return answer
        for kind in ('quote', 'line', 'duplicate', 'missing'):
            with self.subTest(kind=kind), patch.object(inference, 'ask', side_effect=lambda *args: broken(args[-1], kind)):
                with self.assertRaises(ValueError):
                    analysis.review_criteria(self.context, rows, self.prepared, 't', 'm')
            self.assertEqual(self.prepared, original)

    def test_context_budget_and_category_fairness(self):
        (self.root / 'auth.py').write_text('\n'.join(f'def login_{i}():\n    authenticate()' for i in range(200)), encoding='utf-8')
        context = Context(self.root, self.files)
        prepared = prepare(context, self.root, self.files, self.rows)
        self.assertTrue(all(len(r['packet']) <= 4 for r in prepared.values()))
        self.assertLessEqual(sum(len(e['code']) for r in prepared.values() for e in r['packet']), 60000)
        self.assertGreater(prepared['kisa:IA']['omitted_locations'], 0)
        hits = [RawHit('test', 'sql', 'x.py', i + 1, 'CWE-89', ['CI-02'], 'SQL', 'fix') for i in range(40)]
        hits.append(RawHit('test', 'csrf', 'z.py', 1, 'CWE-352', ['CI-07'], 'CSRF', 'fix'))
        selected = select_findings(normalize(hits))
        self.assertEqual(len(selected), 30)
        self.assertTrue(any(f.cwe == 'CWE-352' for f in selected))


class PolicyTests(unittest.TestCase):
    def test_unsupported_policy_files_do_not_claim_no_findings(self):
        from scanner.static import inspect
        from scanner.kisa import checklist
        with TemporaryDirectory() as temp, patch('scanner.static.semgrep', return_value=[]):
            root = Path(temp)
            (root / 'app.js').write_text('const value = 1;', encoding='utf-8')
            findings = inspect(root, ['app.js'])
        rows = build_criteria(checklist(findings, {'javascript': 1}, []), findings)
        for row in rows:
            if row['framework'] == 'kisa' and row['code'] in ('CF', 'BF', 'DI', 'WM'):
                self.assertEqual(row['execution'], 'manual')
                self.assertEqual(row['outcome'], 'unassessed')

    def test_explicit_policy_weaknesses_and_safe_controls(self):
        unsafe = 'WTF_CSRF_ENABLED = False\nAUTH_PASSWORD_VALIDATORS = []\n@csrf_exempt\ndef view(): pass\n'
        self.assertEqual({h.kisa[0] for h in detect('settings.py', unsafe)}, {'CI-07', 'CI-09'})
        self.assertEqual(detect('settings.py', 'WTF_CSRF_ENABLED = True\nAUTH_PASSWORD_VALIDATORS = [{"NAME": "validator"}]\n'), [])
        self.assertEqual(detect('x.py', '# WTF_CSRF_ENABLED = False\ns = "AUTH_PASSWORD_VALIDATORS = []"'), [])
        self.assertEqual({h.kisa[0] for h in detect('nginx.conf', 'autoindex on;\nTraceEnable on')}, {'CI-03', 'CI-21'})
        self.assertEqual(detect('nginx.conf', '# autoindex on;\nautoindex off;\nTraceEnable off'), [])
        self.assertEqual(detect('httpd.conf', 'Options +Indexes -Indexes'), [])
        self.assertEqual(len(detect('httpd.conf', 'Options +FollowSymLinks +Indexes')), 1)
        self.assertEqual(detect('app.js', 'autoindex on;'), [])

    def test_session_middleware_requires_review_only_without_explicit_csrf(self):
        self.assertEqual(len(detect('settings.py', 'MIDDLEWARE = ["django.contrib.sessions.middleware.SessionMiddleware"]')), 1)
        self.assertEqual(detect('settings.py', 'MIDDLEWARE = ["django.contrib.sessions.middleware.SessionMiddleware", "django.middleware.csrf.CsrfViewMiddleware"]'), [])


class AssessmentPipelineTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(self.enterContext(TemporaryDirectory()))
        self.repo = self.base / 'repo'
        self.repo.mkdir()
        (self.repo / 'auth.ts').write_text('function reset_password(token) { return token; }\n', encoding='utf-8')
        for args in (['init', '-q'], ['add', '.'], ['-c', 'user.name=Test', '-c', 'user.email=t@example.invalid',
                                                 '-c', 'commit.gpgsign=false', 'commit', '-qm', 'fixture']):
            subprocess.run(['git', '-C', str(self.repo), *args], check=True, capture_output=True)

    def scan(self, offline=False, new_high_only=False, fail=False, **options):
        updates = []
        with patch('scanner.static.semgrep', return_value=[]), \
             patch.object(cli, 'access_token', return_value='t') as login, \
             patch.object(inference, 'model_for', return_value='m'), \
             patch.object(inference, 'ask', side_effect=(inference.SessionError('quota', 'limit') if fail else
                          lambda *args: answer_for(args[-1], True))) as ask:
            folder, note, issue = cli.scan(self.repo, self.base / 'out', self.base / 'state', offline=offline,
                                           new_high_only=new_high_only, criteria_progress=updates.append, **options)
        result = ScanResult.from_json((folder / 'scan_result.json').read_text(encoding='utf-8'))
        self.assertEqual(result.report_md, (folder / 'report.md').read_text(encoding='utf-8'))
        self.assertEqual(updates[-1], result.criteria)
        return result, note, issue, login, ask

    def test_zero_static_findings_still_get_criterion_review(self):
        result, note, issue, login, ask = self.scan()
        self.assertIsNone(issue)
        login.assert_called_once()
        self.assertGreater(ask.call_count, 0)
        self.assertEqual(result.findings, [])
        self.assertEqual(result.risk_score, 0)
        self.assertEqual(len(result.criteria), 31)
        self.assertTrue(any(r['assessment']['candidates'] for r in result.criteria))
        self.assertIn('AI 추가 검토 후보', result.report_md)
        self.assertIn('실행 검증: 미수행', result.report_md)
        self.assertNotIn('packet', result.to_json())

    def test_saved_scan_dashboard_api_and_download_share_assessments(self):
        from fastapi.testclient import TestClient
        from vibescan.dashboard import dashboard_app
        result, _, _, _, _ = self.scan()
        app = dashboard_app(self.base / 'out', '127.0.0.1:8765', 'test', self.base / 'state')
        with TestClient(app, base_url='http://127.0.0.1:8765') as client:
            response = client.get('/api/scans/' + result.scan_id, headers={'X-VibeScan-Token': 'test'})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['criteria'], result.criteria)
        self.assertEqual(data['report_md'], result.report_md)
        for row in data['criteria']:
            assessment = row['assessment']
            self.assertIn(f"| {row['code']} · {row['name']} |", data['report_md'])
            self.assertIn(assessment['reason'], data['report_md'])
            for candidate in assessment['candidates']:
                self.assertIn(candidate['title'], data['report_md'])
                self.assertIn(candidate['remediation'], data['report_md'])
                for evidence in candidate['evidence']:
                    self.assertIn(f"{evidence['file']}:{evidence['line']}", data['report_md'])
        self.assertIn('기준 문맥 AI 검토', data['report_md'])
        self.assertNotIn('기준별 AI 문맥 검토 기록이 없는 항목', data['report_md'])

    def test_external_results_survive_storage_api_and_report(self):
        from fastapi.testclient import TestClient
        from vibescan.dashboard import dashboard_app
        dependency = dict(id='dependencies', kind='dependencies', kisa=[], owasp=['A03:2025'],
                          state='partial', outcome='candidate', reason='Dependency fixture scope',
                          evidence=['OSV fixture advisory'], omitted=['Unpinned fixture package'])
        runtime = dict(id='ownership', kind='runtime', kisa=['IA', 'IN'], owasp=['A01:2025'],
                       state='completed', outcome='no_findings', reason='Configured fixture checks only',
                       evidence=['Step 1 HTTP 403 matched'])
        config = {'base_url': 'https://example.invalid', 'checks': [
            {'id': 'ownership', 'criteria': ['IA', 'IN'], 'steps': [
                {'path': '/private', 'expect': {'status': [403]}}]}]}
        with patch.object(cli.dependencies, 'check', return_value=dependency), \
             patch.object(cli.runtime, 'run', return_value=[runtime]):
            result, _, _, _, _ = self.scan(offline=True, dependency_check=True, verification=config)
        app = dashboard_app(self.base / 'out', '127.0.0.1:8765', 'test', self.base / 'state')
        with TestClient(app, base_url='http://127.0.0.1:8765') as client:
            response = client.get('/api/scans/' + result.scan_id, headers={'X-VibeScan-Token': 'test'})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['criteria'], result.criteria)
        self.assertEqual(data['report_md'], result.report_md)
        self.assertEqual(len(data['criteria']), 31)
        for check in (dependency, runtime):
            linked = [r for r in data['criteria'] if check in r.get('checks', [])]
            self.assertTrue(linked)
            for text in [check['reason'], *check['evidence'], *check.get('omitted', [])]:
                self.assertIn(text, data['report_md'])
        self.assertEqual(data['risk_score'], 0)
        self.assertEqual(data['findings'], [])
        pr = next(r for r in data['criteria'] if r['code'] == 'PR')
        self.assertEqual(pr['checks'][0]['state'], 'skipped')
        self.assertEqual(pr['checks'][0]['outcome'], 'unassessed')

    def test_offline_and_hook_never_expand_ai_scope(self):
        for offline, hook in ((True, False), (False, True)):
            with self.subTest(offline=offline, hook=hook):
                result, _, _, login, ask = self.scan(offline=offline, new_high_only=hook)
                ask.assert_not_called()
                login.assert_not_called()
                self.assertTrue(all(r['assessment']['state'] == 'skipped' for r in result.criteria))

    def test_quota_failure_keeps_result_and_no_pending_states(self):
        result, _, issue, _, _ = self.scan(fail=True)
        self.assertEqual(issue, 'limit')
        states = {r['assessment']['state'] for r in result.criteria}
        self.assertIn('failed', states)
        self.assertFalse(states.intersection({'pending', 'running'}))
        self.assertTrue(all(r['assessment']['outcome'] == 'unassessed' for r in result.criteria))
