"""The two standard views share evidence, never a claim of full compliance.

KISA codes remain compatible with the CI-01..21 aliases used by detector rules.
OWASP links are project-maintained reference classifications, not an official
one-to-one KISA crosswalk. Missing execution records never become passed checks.
"""

from .kisa import catalog
from .models import Change, Status


# These links describe related local checks, not complete OWASP test coverage.
OWASP_KISA = {
    'A01:2025': ('CF', 'SF', 'IN', 'FD', 'AE'),
    'A02:2025': ('DI', 'EP', 'IL', 'FU', 'WM'),
    'A03:2025': (),
    'A04:2025': ('IL', 'SN'),
    'A05:2025': ('CI', 'SI', 'XS'),
    'A06:2025': ('PV', 'AU'),
    'A07:2025': ('BF', 'IA', 'PR', 'IS', 'CC'),
    'A08:2025': ('CI', 'IS'),
    'A09:2025': (),
    'A10:2025': (),
}

# Prefer specific CWE classification when present; broad category aliases are a
# fallback for legacy data. Never reuse 2021 numbers as though they were 2025.
CWE_CODES = {
    'CWE-22': (('FD',), ('A01:2025',)),
    'CWE-78': (('CI',), ('A05:2025',)),
    'CWE-79': (('XS',), ('A05:2025',)),
    'CWE-89': (('SI',), ('A05:2025',)),
    'CWE-94': (('CI',), ('A05:2025',)),
    'CWE-209': (('EP',), ('A02:2025',)),
    'CWE-256': (('IL',), ('A04:2025',)),
    'CWE-284': (('IN',), ('A01:2025',)),
    'CWE-287': (('IA',), ('A07:2025',)),
    'CWE-602': (('PV',), ('A06:2025',)),
    'CWE-636': (('IA',), ('A10:2025',)),
    'CWE-640': (('PR',), ('A07:2025',)),
    'CWE-799': (('AU',), ('A06:2025',)),
    'CWE-319': (('SN',), ('A04:2025',)),
    'CWE-321': (('IL', 'IS'), ('A04:2025',)),
    'CWE-326': (('IL',), ('A04:2025',)),
    'CWE-327': (('IL',), ('A04:2025',)),
    'CWE-347': (('IS',), ('A08:2025',)),
    'CWE-352': (('CF',), ('A01:2025',)),
    'CWE-384': (('IS',), ('A07:2025',)),
    'CWE-434': (('FU',), ('A02:2025',)),
    'CWE-489': (('EP',), ('A02:2025',)),
    'CWE-502': (('CI',), ('A08:2025',)),
    'CWE-521': (('BF',), ('A07:2025',)),
    'CWE-548': (('DI',), ('A02:2025',)),
    'CWE-749': (('WM',), ('A02:2025',)),
    'CWE-532': (('IL',), ('A09:2025',)),
    'CWE-540': (('IL',), ('A02:2025',)),
    'CWE-614': (('CC',), ('A04:2025',)),
    'CWE-639': (('IN',), ('A01:2025',)),
    'CWE-770': (('AU',), ('A10:2025',)),
    'CWE-778': ((), ('A09:2025',)),
    'CWE-798': (('IL',), ('A07:2025',)),
    'CWE-862': (('IN',), ('A01:2025',)),
    'CWE-863': (('IN',), ('A01:2025',)),
    'CWE-918': (('SF',), ('A01:2025',)),
    'CWE-942': (('IL',), ('A01:2025',)),
    'CWE-1004': (('CC',), ('A02:2025',)),
    'CWE-1275': (('CC',), ('A02:2025',)),
}

EXECUTION = {
    '자동 점검 범위 내 미발견': 'completed',
    '부분 점검': 'partial',
    '해당 기능 없음(추정)': 'partial',
    '동적 점검 필요': 'manual',
    '수동 확인 필요': 'manual',
}


def finding_codes(finding):
    """Return normalized reference codes without mutating historical findings."""
    items = [item for item in catalog()['items'] if item.get('official_code')]
    aliases = {alias: item['official_code'] for item in items
               for alias in (item['code'], item['official_code'])}
    kisa = {aliases[code] for code in finding.kisa if code in aliases}
    cwe_kisa, cwe_owasp = CWE_CODES.get(finding.cwe, ((), ()))
    if not kisa:
        kisa.update(cwe_kisa)
    if cwe_owasp:
        owasp = set(cwe_owasp)
    else:
        owasp = {code for code, related in OWASP_KISA.items() if kisa.intersection(related)}
        # A valid 2025 assignment may have been stored by another detector.
        if finding.owasp in OWASP_KISA:
            owasp.add(finding.owasp)
        if 'V-02' in finding.kisa:
            owasp.add('A01:2025')
    return {'kisa': [item['official_code'] for item in items if item['official_code'] in kisa],
            'owasp': sorted(owasp)}


def _ai_state(matches, review_states):
    states = [review_states.get(f.id, 'unknown') for f in matches]
    reviewed = states.count('completed')
    if not states:
        state = 'not_applicable'
    elif reviewed == len(states):
        state = 'completed'
    elif 'running' in states:
        state = 'running'
    elif 'failed' in states:
        state = 'failed'
    elif 'pending' in states:
        state = 'pending'
    elif reviewed:
        state = 'partial'
    elif all(value == 'skipped' for value in states):
        state = 'skipped'
    else:
        state = 'unknown'
    return {'state': state, 'reviewed': reviewed, 'total': len(states)}


def _execution(item, recorded, phase):
    if phase in ('pending', 'running', 'failed'):
        return phase if item['detectors'] else 'manual'
    if recorded is None:
        return 'unknown'
    # Older records may only say "candidate". That is a finding outcome, not
    # proof that a detector completed all of its intended work.
    return EXECUTION.get(recorded.get('coverage_status', recorded.get('status')), 'unknown')


def build_criteria(kisa_rows=(), findings=(), *, phase='completed', review_states=None, assessments=None):
    """Build all 31 rows from engine evidence and explicit per-finding AI state.

    ``completed`` describes a completed run, not that every standard was tested.
    ``running`` covers the static engine's parallel rule evaluation; no fake
    criterion-by-criterion serial progress is generated.
    """
    if phase not in ('pending', 'running', 'completed', 'failed'):
        raise ValueError('unknown criteria phase')
    book = catalog()
    items = [item for item in book['items'] if item.get('official_code')]
    recorded = {row.get('official_code') or row['code']: row for row in kisa_rows}
    findings = [f for f in findings if f.change != Change.FIXED
                and f.status in (Status.OPEN, Status.DISMISSED)]
    mapped = {f.id: finding_codes(f) for f in findings}
    review_states = review_states or {}
    result = []

    def row(framework, code, name, execution, reason, criteria, source):
        matches = [f for f in findings if code in mapped[f.id][framework]]
        opened = [f.id for f in matches if f.status == Status.OPEN]
        dismissed = [f.id for f in matches if f.status == Status.DISMISSED]
        outcome = ('candidate' if opened else 'no_findings'
                   if execution in ('completed', 'partial') and not dismissed else 'unassessed')
        result = dict(framework=framework, code=code, name=name, execution=execution,
                    outcome=outcome, findings=opened, dismissed=dismissed, reason=reason,
                    ai=_ai_state(matches, review_states), criteria=criteria, source=source)
        if assessments is not None:
            assessment = assessments.get(framework + ':' + code)
            if assessment is not None:
                result['assessment'] = assessment
        return result

    for item in items:
        code = item['official_code']
        previous = recorded.get(code, recorded.get(item['code']))
        execution = _execution(item, previous, phase)
        reason = previous.get('note', '') if previous else ''
        if phase == 'pending' and item['detectors']:
            reason = '검사 대기 중입니다. 아직 판정하지 않았습니다.'
        elif phase == 'running' and item['detectors']:
            reason = '관련 정적 규칙을 함께 실행 중입니다. 기준별 실행 순서를 의미하지 않습니다.'
        elif phase == 'failed' and item['detectors']:
            reason = '검사 실행이 중단되어 이 항목의 완료 여부를 확인할 수 없습니다.'
        elif execution == 'unknown':
            reason = '이전 결과에 기준별 실행 기록이 없습니다. 재검사가 필요합니다.'
        elif not item['detectors']:
            reason = '현재 자동 정적 규칙이 없습니다. ' + item.get('limitations', item['criteria'])
        else:
            reason += ' ' + item.get('limitations', '')
        result.append(row('kisa', code, item['name'], execution, reason.strip(), item['criteria'],
                          f"사용자 제공 2026 주통기 상세가이드 웹 · PDF {item['page']}쪽 · 기존 추출 목록"))

    kisa = {item['code']: item for item in result}
    for item in book['owasp']:
        code = item['id']
        related = [kisa[key] for key in OWASP_KISA[code]]
        supported = [r for r in related if next(i for i in items if i['official_code'] == r['code'])['detectors']]
        direct = {'A09:2025': 'V-05', 'A10:2025': 'V-06'}.get(code)
        if direct:
            direct_item = next(i for i in book['items'] if i['code'] == direct)
            supported.append({'execution': _execution(direct_item, recorded.get(direct), phase)})
        if not supported:
            execution = 'manual'
            reason = '이 범주 전체를 평가하는 자동 규칙이 없습니다. 설계·운영 자료 또는 실행 환경의 수동 검토가 필요합니다.'
        elif phase in ('pending', 'running', 'failed'):
            execution = phase
            reason = {'pending': '관련 정적 검사 대기 중입니다.', 'running': '관련 정적 규칙 실행 중입니다.',
                      'failed': '관련 검사 실행이 중단되었습니다.'}[phase]
        elif any(r['execution'] == 'unknown' for r in supported):
            execution = 'unknown'
            reason = '관련 기준의 실행 기록이 없거나 불완전합니다. 재검사가 필요합니다.'
        elif all(r['execution'] == 'manual' for r in supported):
            execution = 'manual'
            reason = '이번 수집 범위에 지원하는 정적 검사 문맥이 없습니다. 기능·배포 설정의 추가 확인이 필요합니다.'
        else:
            execution = 'partial'
            reason = '관련 정적 규칙만 점검했습니다. OWASP 범주 전체의 점검 완료나 적합 판정을 의미하지 않습니다.'
        if related:
            reason += ' 관련 주통기: ' + ', '.join(r['code'] for r in related) + '.'
        reason += ' 기준 간 연결은 프로젝트의 참고 분류입니다.'
        result.append(row('owasp', code, item['title'], execution, reason, item['description'],
                          book['owasp_source']['url']))
    return result
