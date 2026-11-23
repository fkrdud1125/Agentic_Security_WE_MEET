import unittest

from scanner.criteria import build_criteria, finding_codes
from scanner.kisa import catalog, checklist
from scanner.models import Change, Confidence, Finding, Location, Severity, Status


def finding(fid='F-001', cwe='CWE-89', kisa=('CI-02',), **extra):
    return Finding(fid, '검토 후보', cwe, extra.pop('owasp', ''), Severity.HIGH,
                   Confidence.POTENTIAL, Location('app.py', 7), '근거', ['static:rule'],
                   '영향', '조치', '', kisa=list(kisa), **extra)


def indexed(rows):
    return {(r['framework'], r['code']): r for r in rows}


class CriteriaTests(unittest.TestCase):
    def test_both_catalogs_are_complete_and_aliases_still_work(self):
        rows = build_criteria(phase='pending')
        self.assertEqual(len(rows), 31)
        self.assertEqual(len({(r['framework'], r['code']) for r in rows}), 31)
        self.assertEqual([r['code'] for r in rows if r['framework'] == 'kisa'],
                         'CI SI DI EP IL XS CF SF BF IA IN PR PV FU FD IS SN CC AE AU WM'.split())
        self.assertEqual([r['code'] for r in rows if r['framework'] == 'owasp'],
                         [f'A{i:02}:2025' for i in range(1, 11)])
        items = catalog()['items']
        self.assertEqual([r['code'] for r in items[:21]], [f'CI-{i:02}' for i in range(1, 22)])
        self.assertFalse(catalog()['source']['verified'])
        self.assertIn('독립 재검증하지 않았습니다', catalog()['source']['provenance'])

    def test_static_execution_and_finding_outcome_are_independent(self):
        sql = finding()
        rows = indexed(build_criteria(checklist([sql], {'python': 1}, []), [sql]))
        self.assertEqual(rows['kisa', 'SI']['execution'], 'completed')
        self.assertEqual(rows['kisa', 'SI']['outcome'], 'candidate')
        self.assertEqual(rows['kisa', 'SI']['findings'], ['F-001'])
        self.assertEqual(rows['kisa', 'XS']['outcome'], 'no_findings')
        self.assertEqual(rows['kisa', 'DI']['execution'], 'partial')
        self.assertEqual(rows['kisa', 'DI']['outcome'], 'no_findings')
        self.assertEqual(rows['owasp', 'A05:2025']['execution'], 'partial')
        self.assertEqual(rows['owasp', 'A05:2025']['findings'], ['F-001'])
        self.assertEqual(rows['owasp', 'A03:2025']['execution'], 'manual')
        self.assertTrue(all(rows['owasp', code]['execution'] == 'partial'
                            for code in ('A09:2025', 'A10:2025')))

    def test_unsupported_language_does_not_complete_static_checks(self):
        rows = indexed(build_criteria(checklist([], {'php': 2}, [])))
        self.assertEqual(rows['kisa', 'SI']['execution'], 'partial')
        self.assertIn('규칙이 없는 언어', rows['kisa', 'SI']['reason'])

    def test_legacy_result_without_execution_records_is_not_passed(self):
        sql = finding(kisa=(), owasp='A03:2021')
        rows = indexed(build_criteria(findings=[sql]))
        self.assertEqual(rows['kisa', 'SI']['execution'], 'unknown')
        self.assertEqual(rows['owasp', 'A05:2025']['execution'], 'unknown')
        self.assertEqual(rows['kisa', 'SI']['outcome'], 'candidate')
        self.assertEqual(rows['kisa', 'XS']['outcome'], 'unassessed')
        self.assertEqual(rows['kisa', 'SI']['ai']['state'], 'unknown')
        self.assertEqual(finding_codes(sql)['owasp'], ['A05:2025'])
        self.assertEqual(sql.owasp, 'A03:2021')

    def test_missing_single_record_does_not_invent_completion(self):
        recorded = [r for r in checklist([], {'python': 1}, []) if r['code'] != 'CI-02']
        rows = indexed(build_criteria(recorded))
        self.assertEqual(rows['kisa', 'SI']['execution'], 'unknown')
        self.assertEqual(rows['owasp', 'A05:2025']['execution'], 'unknown')

    def test_fixed_and_dismissed_candidates_do_not_become_open_findings(self):
        fixed = finding('F-old', change=Change.FIXED)
        dismissed = finding('F-dismissed', status=Status.DISMISSED)
        sql = finding()
        rows = indexed(build_criteria(checklist([fixed, dismissed, sql], {'python': 1}, []),
                                      [fixed, dismissed, sql],
                                      review_states={'F-001': 'completed', 'F-dismissed': 'completed'}))
        si = rows['kisa', 'SI']
        self.assertEqual(si['findings'], ['F-001'])
        self.assertEqual(si['dismissed'], ['F-dismissed'])
        self.assertEqual(si['ai'], {'state': 'completed', 'reviewed': 2, 'total': 2})
        rows = indexed(build_criteria(checklist([dismissed], {'python': 1}, []), [dismissed]))
        self.assertEqual(rows['kisa', 'SI']['outcome'], 'unassessed')
        self.assertEqual(rows['kisa', 'SI']['dismissed'], ['F-dismissed'])

    def test_review_state_is_per_finding_not_inferred_from_note(self):
        a, b = finding(), finding('F-002')
        rows = indexed(build_criteria(checklist([a, b], {'python': 1}, []), [a, b],
                                      review_states={'F-001': 'completed', 'F-002': 'skipped'}))
        self.assertEqual(rows['kisa', 'SI']['ai'], {'state': 'partial', 'reviewed': 1, 'total': 2})
        self.assertEqual(rows['owasp', 'A05:2025']['ai'], {'state': 'partial', 'reviewed': 1, 'total': 2})
        self.assertEqual(rows['kisa', 'XS']['ai']['state'], 'not_applicable')
        rows = indexed(build_criteria(findings=[a, b], review_states={'F-001': 'completed', 'F-002': 'failed'}))
        self.assertEqual(rows['kisa', 'SI']['ai'], {'state': 'failed', 'reviewed': 1, 'total': 2})

    def test_live_and_failed_states_only_mark_supported_slices(self):
        for phase in ('pending', 'running', 'failed'):
            with self.subTest(phase=phase):
                rows = indexed(build_criteria(phase=phase))
                self.assertEqual(rows['kisa', 'SI']['execution'], phase)
                self.assertEqual(rows['owasp', 'A05:2025']['execution'], phase)
                self.assertEqual(rows['kisa', 'DI']['execution'], phase)
                self.assertEqual(rows['kisa', 'PV']['execution'], phase)
                self.assertEqual(rows['owasp', 'A09:2025']['execution'], phase)
                self.assertEqual(rows['owasp', 'A03:2025']['execution'], 'manual')
                self.assertEqual(rows['kisa', 'SI']['outcome'], 'unassessed')

    def test_specific_cwe_takes_precedence_over_broad_category_crosswalk(self):
        ssrf = finding(cwe='CWE-918', kisa=('CI-08',))
        self.assertEqual(finding_codes(ssrf), {'kisa': ['SF'], 'owasp': ['A01:2025']})
        yaml = finding(cwe='CWE-502', kisa=('CI-01',))
        self.assertEqual(finding_codes(yaml), {'kisa': ['CI'], 'owasp': ['A08:2025']})
        official = finding(kisa=('SI',))
        self.assertEqual(finding_codes(official), {'kisa': ['SI'], 'owasp': ['A05:2025']})
        self.assertEqual(next(r for r in checklist([official], {'python': 1}, [])
                              if r['code'] == 'CI-02')['findings'], ['F-001'])


if __name__ == '__main__':
    unittest.main()
