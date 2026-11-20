import unittest
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from scanner.detectors.java import detect


API = '''package demo;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;
@RestController @RequestMapping(path="/admin") class Api {
    Service service;
    @GetMapping("/users") Object users(@RequestParam String name) {
        return service.search(name);
    }
}'''
SERVICE = '''package demo;
interface Service { Object search(String input); }
class UserService implements Service {
    Store store;
    public Object search(String input) {
        String sql = "select id from users where name = '" + input + "'";
        return store.read(sql);
    }
}'''
STORE = '''package demo;
import org.springframework.jdbc.core.JdbcTemplate;
class Store {
    JdbcTemplate jdbc;
    Object read(String query) { return jdbc.queryForList(query); }
}'''
CONFIG = '''package demo;
import org.springframework.context.annotation.*;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
@Configuration class Config {
    @Bean SecurityFilterChain security(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(a -> a.requestMatchers("/admin/**").authenticated()
                                        .anyRequest().denyAll()).build();
    }
}'''


class JavaTests(unittest.TestCase):
    def scan(self, **overrides):
        files = dict(Api=API, Service=SERVICE, Store=STORE, Config=CONFIG)
        files.update(overrides)
        return detect({k + '.java': v for k, v in files.items()})

    def test_cross_file_sql_and_admin_policy(self):
        hits, rows, partial = self.scan()
        sql, auth = hits
        self.assertEqual([t['method'] for t in sql.trace], ['users', 'search', 'read'])
        self.assertEqual((sql.file, sql.cwe, auth.file, auth.cwe), ('Store.java', 'CWE-89', 'Api.java', 'CWE-862'))
        self.assertEqual((rows[0]['path'], rows[0]['auth_guard']), ('/admin/users', 'authenticated'))
        self.assertFalse(partial)

    def test_binding_overwrite_and_ambiguous_dispatch(self):
        for files in [
            {'Store': STORE.replace('queryForList(query)', 'queryForList("select id from users where name=?", query)')},
            {'Service': SERVICE.replace('return store.read(sql);', 'sql = "select 1"; return store.read(sql);')},
            {'Other': 'package demo; class Other implements Service { public Object search(String x){return null;} }'},
        ]:
            with self.subTest(files=files.keys()):
                hits, _, partial = self.scan(**files)
                self.assertFalse(any(h.cwe == 'CWE-89' for h in hits))
                if 'Other' in files:
                    self.assertIn('Service.java', partial)

    def test_conditional_branches_and_helper_return(self):
        service = SERVICE.replace('return store.read(sql);', '''
            if (input == null) { return null; }
            return store.read(copy(sql));''').replace('public Object search', 'String copy(String q){return q;} public Object search')
        hits, _, _ = self.scan(Service=service)
        self.assertTrue(any(h.cwe == 'CWE-89' for h in hits))
        fixed = service.replace('return store.read(copy(sql));', '''
            if (input.isEmpty()) { sql = "select 1"; } else { sql = "select 2"; }
            return store.read(copy(sql));''')
        self.assertFalse(any(h.cwe == 'CWE-89' for h in self.scan(Service=fixed)[0]))

    def test_method_and_global_policies(self):
        guarded = API.replace('@GetMapping', '''@PreAuthorize("hasRole('ADMIN')") @GetMapping''')
        for api, config, expected in [
            (API, CONFIG.replace('.authenticated()', '.hasRole("ADMIN")'), 'admin'),
            (API, CONFIG.replace('a.requestMatchers', 'a.requestMatchers("/**").permitAll().requestMatchers'), 'permitAll'),
            (API, CONFIG.replace('"/admin/**"', 'settings.pattern()'), '수동 확인'),
            (guarded, CONFIG.replace('@Configuration', '@Configuration @EnableMethodSecurity'), 'admin'),
            (guarded.replace("hasRole('ADMIN')", 'isAuthenticated()'),
             CONFIG.replace('@Configuration', '@Configuration @EnableMethodSecurity').replace('.authenticated()', '.permitAll()'),
             'authenticated'),
            (guarded, CONFIG, '수동 확인'),
        ]:
            with self.subTest(expected=expected):
                hits, rows, _ = self.scan(Api=api, Config=config)
                self.assertEqual(rows[0]['auth_guard'], expected)
                self.assertEqual(any(h.cwe == 'CWE-862' for h in hits), expected in ('permitAll', 'authenticated'))

    def test_ordered_chains_and_duplicate_order(self):
        first = CONFIG.replace('class Config', 'class Early').replace('@Bean', '@Bean @Order(1)')
        first = first.replace('http.authorize', 'http.securityMatcher("/public/**").authorize')
        _, rows, _ = self.scan(Early=first)
        self.assertEqual(rows[0]['auth_guard'], 'authenticated')
        _, rows, partial = self.scan(Early=first.replace('@Order(1)', ''))
        self.assertIn('Api.java', partial)
        self.assertEqual(rows[0]['auth_guard'], '수동 확인')

    def test_offline_cli_report(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            repo = base / 'repo'
            repo.mkdir()
            for name, source in {'Api': API, 'Service': SERVICE, 'Store': STORE, 'Config': CONFIG}.items():
                (repo / (name + '.java')).write_text(source, encoding='utf-8')
            for args in (['init', '-q'], ['add', '.'], ['-c', 'user.name=Test', '-c',
                         'user.email=test@example.invalid', '-c', 'commit.gpgsign=false', 'commit', '-qm', 'fixture']):
                subprocess.run(['git', '-C', str(repo), *args], capture_output=True, check=True)
            env = dict(os.environ, LOCALAPPDATA=tmp, XDG_CONFIG_HOME=tmp, PYTHONUTF8='1')
            subprocess.run([sys.executable, '-m', 'vibescan', 'scan', str(repo), '--offline', '--output', str(base/'out')],
                           env=env, capture_output=True, check=True)
            data = json.loads(next((base/'out').glob('*/scan_result.json')).read_text(encoding='utf-8'))
            self.assertEqual({f['rule_id'] for f in data['findings']}, {'vs-java-sql-flow', 'vs-java-admin-policy'})
            self.assertIn('Service.java:', data['report_md'])
            self.assertIn('Config.java:', data['report_md'])
            self.assertEqual(data['partial_files'], [])
