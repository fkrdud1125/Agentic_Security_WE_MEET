import copy
import json
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

from scanner import dependencies, runtime
from scanner.criteria import build_criteria, finding_codes
from scanner.detectors.policy import detect
from scanner.kisa import catalog, checklist
from scanner.normalize import normalize
from scanner.static import inspect
from scanner.supplemental import attach


class RemainingPolicyTests(unittest.TestCase):
    def test_all_five_remaining_categories_have_concrete_patterns(self):
        source = '''
LOGIN_DISABLED = True
PASSWORD_RESET_TIMEOUT = 172800
RATELIMIT_ENABLED = False
def checkout():
    gateway.charge(amount=request.form['amount'])
requests.post('http://example.invalid/login', json={'password': password})
'''
        hits = detect('settings.py', source)
        self.assertEqual({h.kisa[0] for h in hits}, {'CI-10', 'CI-12', 'CI-13', 'CI-17', 'CI-20'})
        self.assertEqual(len([i for i in catalog()['items'] if i.get('official_code') and i['detectors']]), 21)

    def test_safe_counterexamples_do_not_trigger(self):
        source = '''
LOGIN_DISABLED = False
PASSWORD_RESET_TIMEOUT = 600
RATELIMIT_ENABLED = True
def checkout():
    amount = calculate_price(order)
    gateway.charge(amount=amount)
requests.post('https://example.invalid/login', json={'password': password})
def authorize():
    try: return verify()
    except Exception: return False
LOGGING = {'disable_existing_loggers': False}
'''
        self.assertEqual(detect('settings.py', source), [])

    def test_owasp_logging_and_failopen_have_direct_evidence(self):
        source = "LOGGING = {'disable_existing_loggers': True}\ndef authorize():\n    try: return verify()\n    except Exception: return True\n"
        hits = detect('settings.py', source)
        findings = normalize(hits)
        codes = {code for f in findings for code in finding_codes(f)['owasp']}
        self.assertEqual(codes, {'A09:2025', 'A10:2025'})
        rows = build_criteria(checklist(findings, {'python': 1}, []), findings)
        for code in codes:
            row = next(r for r in rows if r['code'] == code)
            self.assertEqual(row['execution'], 'partial')
            self.assertEqual(row['outcome'], 'candidate')

    def test_unsupported_language_does_not_complete_remaining_checks(self):
        with TemporaryDirectory() as temp, patch('scanner.static.semgrep', return_value=[]):
            root = Path(temp)
            (root / 'app.js').write_text('const n = 1;', encoding='utf-8')
            findings = inspect(root, ['app.js'])
        rows = build_criteria(checklist(findings, {'javascript': 1}, []), findings)
        for row in rows:
            if row['framework'] == 'kisa' and row['code'] in ('IA', 'PR', 'PV', 'SN', 'AU'):
                self.assertEqual(row['execution'], 'manual')
                self.assertEqual(row['outcome'], 'unassessed')


class DependencyTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))

    def write(self, name, text):
        (self.root / name).write_text(text, encoding='utf-8')

    def response(self, payload, status=200):
        response = MagicMock()
        response.__enter__.return_value = response
        response.status_code = status
        response.iter_content.return_value = [json.dumps(payload).encode()]
        return response

    def test_exact_versions_and_private_or_unresolved_dependencies(self):
        self.write('requirements.txt', 'Django==4.0.0\nrequests>=2\n-r other.txt\n')
        self.write('package-lock.json', json.dumps({'packages': {
            '': {'name': 'my-app'},
            'node_modules/lodash': {'version': '4.17.0', 'resolved': 'https://registry.npmjs.org/lodash/-/lodash-4.17.0.tgz'},
            'node_modules/private': {'version': '1.0', 'resolved': 'https://internal.invalid/private.tgz'},
        }}))
        packages, omitted = dependencies.inventory(self.root, ['requirements.txt', 'package-lock.json'])
        self.assertEqual({(p['ecosystem'], p['name'], p['version']) for p in packages}, {('PyPI', 'django', '4.0.0'), ('npm', 'lodash', '4.17.0')})
        self.assertGreater(len(omitted), 0)
        self.write('requirements.txt', '--index-url https://private.invalid\nprivate==1.0\n')
        self.assertEqual(dependencies.inventory(self.root, ['requirements.txt'])[0], [])

    def test_osv_candidates_pagination_and_no_source_transmission(self):
        self.write('requirements.txt', 'django==4.0.0\n')
        with patch.object(dependencies.requests, 'Session') as factory:
            session = factory.return_value.__enter__.return_value
            session.post.return_value = self.response({'results': [{'vulns': [{'id': 'CVE-2023-TEST'}], 'next_page_token': 'more'}]})
            result = dependencies.check(self.root, ['requirements.txt'], enabled=True)
            payload = session.post.call_args.kwargs['json']
            self.assertEqual(payload, {'queries': [{'package': {'name': 'django', 'ecosystem': 'PyPI'}, 'version': '4.0.0'}]})
            self.assertFalse(session.trust_env)
            self.assertFalse(session.post.call_args.kwargs['allow_redirects'])
        self.assertEqual(result['state'], 'partial')
        self.assertEqual(result['outcome'], 'candidate')
        self.assertIn('CVE-2023-TEST', result['evidence'][0])
        self.assertEqual(result['checked_count'], 1)

    def test_disabled_failure_and_invalid_results_never_become_clean(self):
        self.write('requirements.txt', 'django==4.0.0\n')
        with patch.object(dependencies.requests, 'Session') as factory:
            self.assertEqual(dependencies.check(self.root, ['requirements.txt'])['state'], 'skipped')
            factory.assert_not_called()
        for payload, status in (({'results': []}, 200), ({'results': [{}]}, 503), ({'results': [{'vulns': [{'id': '<script>'}]}]}, 200)):
            with self.subTest(payload=payload), patch.object(dependencies.requests, 'Session') as factory:
                factory.return_value.__enter__.return_value.post.return_value = self.response(payload, status)
                result = dependencies.check(self.root, ['requirements.txt'], True)
            self.assertEqual(result['state'], 'failed')
            self.assertEqual(result['outcome'], 'unassessed')

    def test_no_advisories_means_only_queried_package_versions(self):
        self.write('requirements.txt', 'django==4.0.0\n')
        with patch.object(dependencies.requests, 'Session') as factory:
            factory.return_value.__enter__.return_value.post.return_value = self.response({'results': [{}]})
            result = dependencies.check(self.root, ['requirements.txt'], True)
        self.assertEqual(result['state'], 'completed')
        self.assertEqual(result['outcome'], 'no_findings')
        self.assertIn('미검증', result['reason'])

    def test_maven_pins_and_local_properties_keep_transitive_gap(self):
        self.write('pom.xml', '<project xmlns="http://maven.apache.org/POM/4.0.0"><properties><lib.version>1.2.3</lib.version></properties><dependencies><dependency><groupId>org.example</groupId><artifactId>demo</artifactId><version>${lib.version}</version></dependency></dependencies></project>')
        packages, omitted = dependencies.inventory(self.root, ['pom.xml'])
        self.assertEqual(packages[0]['ecosystem'], 'Maven')
        self.assertEqual(packages[0]['name'], 'org.example:demo')
        self.assertEqual(packages[0]['version'], '1.2.3')
        self.assertTrue(omitted)
        self.write('pom.xml', '<!DOCTYPE project [<!ENTITY name "secret">]><project/>')
        self.assertEqual(dependencies.inventory(self.root, ['pom.xml'])[0], [])

    def test_uv_and_poetry_lockfiles_deduplicate_exact_versions(self):
        self.write('uv.lock', '[[package]]\nname="demo"\nversion="1.0"\nsource={ registry="https://pypi.org/simple" }\n')
        self.write('poetry.lock', '[[package]]\nname="demo"\nversion="1.0"\n')
        packages, omitted = dependencies.inventory(self.root, ['uv.lock', 'poetry.lock'])
        self.assertEqual(len(packages), 1)
        self.assertEqual(len(packages[0]['files']), 2)
        self.assertEqual(omitted, [])


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        calls = self.calls
        class Handler(BaseHTTPRequestHandler):
            revoked = False
            def log_message(self, *args):
                pass
            def do_GET(self):
                calls.append(self.path)
                if self.path == '/redirect':
                    self.send_response(302)
                    self.send_header('Location', '/must-not-follow')
                    self.end_headers()
                    return
                token = self.headers.get('Authorization', '')
                code = 200 if token == 'Bearer alice-secret' and not Handler.revoked else 403 if token else 401
                self.send_response(code)
                self.end_headers()
                self.wfile.write(b'private-object-marker' if code == 200 else b'denied')
            def do_POST(self):
                calls.append(self.path)
                Handler.revoked = True
                self.send_response(204)
                self.end_headers()
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.config = {'base_url': f'http://127.0.0.1:{self.server.server_port}', 'allow_http_credentials': True,
                       'profiles': {'alice': {'Authorization': 'VS_ALICE'}, 'bob': {'Authorization': 'VS_BOB'}},
                       'checks': [{'id': 'ownership', 'criteria': ['IA', 'IN'], 'steps': [
                           {'path': '/resource', 'profile': 'alice', 'expect': {'status': [200], 'contains_env': 'VS_MARKER'}},
                           {'path': '/resource', 'profile': 'bob', 'expect': {'status': [403]}},
                           {'path': '/resource', 'expect': {'status': [401]}},
                       ]}]}
        self.enterContext(patch.dict(os.environ, {'VS_ALICE': 'Bearer alice-secret', 'VS_BOB': 'Bearer bob-secret', 'VS_MARKER': 'private-object-marker'}))

    def test_real_local_two_account_http_check_and_redacted_result(self):
        result = runtime.run(self.config)[0]
        self.assertEqual(result['state'], 'completed')
        self.assertEqual(result['outcome'], 'no_findings')
        self.assertEqual(len(self.calls), 3)
        text = json.dumps(result)
        for secret in ('alice-secret', 'bob-secret', 'private-object-marker'):
            self.assertNotIn(secret, text)
        rows = attach(build_criteria(), [result])
        self.assertEqual(next(r for r in rows if r['code'] == 'IN')['checks'][0]['state'], 'completed')
        self.assertEqual(next(r for r in rows if r['code'] == 'PR')['checks'][0]['state'], 'skipped')

    def test_mismatch_stops_scenario_and_never_follows_redirect(self):
        self.config['checks'][0]['steps'][0]['path'] = '/redirect'
        result = runtime.run(self.config)[0]
        self.assertEqual(result['outcome'], 'candidate')
        self.assertEqual(self.calls, ['/redirect'])
        self.assertEqual(result['state'], 'partial')

    def test_logout_reuse_sequence_requires_explicit_mutation_opt_in(self):
        self.config['checks'][0]['criteria'] = ['IS']
        self.config['checks'][0]['steps'] = [
            {'path': '/resource', 'profile': 'alice', 'expect': {'status': [200]}},
            {'path': '/logout', 'profile': 'alice', 'method': 'POST', 'expect': {'status': [204]}},
            {'path': '/resource', 'profile': 'alice', 'expect': {'status': [403]}},
        ]
        with self.assertRaises(ValueError):
            runtime.run(self.config)
        self.assertEqual(self.calls, [])
        self.config['allow_mutations'] = True
        self.assertEqual(runtime.run(self.config)[0]['state'], 'completed')
        self.assertEqual(len(self.calls), 3)

    def test_missing_credentials_and_http_credentials_block_before_requests(self):
        self.config['allow_http_credentials'] = False
        self.assertEqual(runtime.run(self.config)[0]['state'], 'skipped')
        self.assertEqual(self.calls, [])
        self.config['allow_http_credentials'] = True
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(runtime.run(self.config)[0]['state'], 'skipped')
        self.assertEqual(self.calls, [])

    def test_validation_blocks_cross_origin_and_excessive_requests(self):
        for path in ('https://other.invalid', '//other.invalid', '/\\other.invalid', '/path#fragment'):
            bad = copy.deepcopy(self.config)
            bad['checks'][0]['steps'][0]['path'] = path
            with self.subTest(path=path), self.assertRaises(ValueError):
                runtime.validate(bad)
        bad = copy.deepcopy(self.config)
        bad['checks'][0]['steps'] *= 14
        with self.assertRaises(ValueError):
            runtime.validate(bad)
        self.assertEqual(self.calls, [])
