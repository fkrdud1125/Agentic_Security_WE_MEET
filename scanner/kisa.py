"""Coverage is engine-owned; model explanations cannot remove checklist items."""

import json
import sysconfig
from functools import lru_cache
from pathlib import Path

from .models import Change, Status


@lru_cache(maxsize=1)
def catalog():
    path = Path(__file__).resolve().parents[1] / 'rules/catalog/kisa-2026-web.yml'
    if not path.is_file():
        path = Path(sysconfig.get_path('data')) / 'share/vibescan/kisa-2026-web.yml'
    # JSON is a YAML subset; the catalog needs no additional runtime parser.
    return json.loads(path.read_text(encoding='utf-8'))


def checklist(findings, languages, partial_files):
    rows = []
    unsupported = set(languages) & {'php', 'rb', 'go', 'java', 'kt', 'vue', 'svelte', 'astro'}
    code_languages = set(languages) & {'python', 'javascript', 'typescript'}
    for item in catalog()['items']:
        matches = [f.id for f in findings if item['code'] in f.kisa and f.status == Status.OPEN and f.change != Change.FIXED]
        detectors = item['detectors']
        state = item['default_status']
        note = '자동 정적 검사로 전체 안전성을 판정할 수 없습니다.'
        if detectors:
            state = '자동 점검 범위 내 미발견'
            note = '자체 규칙에 한정. 함수·파일 간 흐름과 배포 환경은 수동 확인.'
            if partial_files or unsupported or (set(detectors) != {'secrets'} and not code_languages):
                state = '부분 점검'
                note = '파싱 실패 또는 자동 규칙이 없는 언어·기능이 포함됩니다.'
            if 'routes' in detectors or detectors == ['config']:
                state = '부분 점검'
                note = '지원하는 프레임워크의 정적 단서만 확인. 상위 미들웨어·배포 설정은 미확인.'
            if item['code'] == 'CI-14' and 'python' not in code_languages:
                state = '부분 점검'; note = '업로드 규칙은 현재 Flask만 지원합니다.'
            elif (item['code'] == 'CI-14' and code_languages == {'python'} and not unsupported
                  and not partial_files and getattr(findings, 'file_upload', True) is False):
                state = '해당 기능 없음(추정)'; note = '검사한 소스에서 업로드 API 단서를 찾지 못했습니다.'
            if item['code'] == 'CI-08' and code_languages & {'javascript', 'typescript'}:
                state = '부분 점검'; note = 'SSRF 규칙은 현재 Python만 지원합니다.'
        if matches:
            state = '취약 후보'
        rows.append({'code': item['code'], 'name': item['name'], 'status': state,
                     'findings': matches, 'detectors': detectors, 'note': note,
                     'criteria': item['criteria'], 'source_verified': False})
    return rows


def legacy_coverage(checks, rows):
    mapping = {'secrets': ['CI-05', 'V-01'], 'sql': ['CI-02'], 'xss': ['CI-06'],
               'auth': ['CI-10', 'CI-11', 'CI-19'], 'headers': ['CI-16', 'CI-17', 'CI-18', 'V-02']}
    for check in checks:
        related = [r for r in rows if r['code'] in mapping[check['id']]]
        check['execution'] = ('partial' if any(r['status'] in ('부분 점검', '동적 점검 필요', '수동 확인 필요') for r in related)
                              else 'completed')
    return checks
