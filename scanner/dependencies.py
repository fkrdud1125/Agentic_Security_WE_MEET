"""Exact-version inventory and opt-in OSV lookup. Never installs target code."""

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path

import requests

OSV_URL = 'https://api.osv.dev/v1/querybatch'
MAX_PACKAGES = 200


def inventory(directory, files):
    packages, omitted = {}, []

    def add(ecosystem, name, version, file):
        if (not isinstance(name, str) or not isinstance(version, str)
                or not re.fullmatch(r'[@A-Za-z0-9_./:-]{1,200}', name)
                or not re.fullmatch(r'[0-9][A-Za-z0-9.+!_-]{0,99}', version)):
            omitted.append(file + ': 고정 버전 없음')
            return
        if ecosystem == 'PyPI':
            name = re.sub(r'[-_.]+', '-', name).lower()
        key = (ecosystem, name, version)
        packages.setdefault(key, {'ecosystem': ecosystem, 'name': name, 'version': version, 'files': []})
        if file not in packages[key]['files']:
            packages[key]['files'].append(file)

    for file in files:
        name = Path(file).name
        try:
            if name.startswith('requirements') and name.endswith('.txt'):
                lines = (directory / file).read_text(encoding='utf-8-sig').splitlines()
                if any(re.match(r'\s*(?:--(?:extra-)?index-url|--find-links|-i\s|-f\s)', line) for line in lines):
                    omitted.append(file + ': 사용자 지정 패키지 인덱스 · 공개 DB 조회 제외')
                    continue
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    match = re.fullmatch(r'([A-Za-z0-9_.-]+)(?:\[[A-Za-z0-9_,.-]+\])?==([0-9][A-Za-z0-9.+!_-]*)(?:\s*#.*)?', line)
                    if match:
                        add('PyPI', *match.groups(), file)
                    else:
                        omitted.append(file + ': 버전 범위·환경 마커·include·해시 행 미해석')
            elif name in ('poetry.lock', 'uv.lock'):
                data = tomllib.loads((directory / file).read_text(encoding='utf-8-sig'))
                for package in data.get('package', []):
                    source = package.get('source', {})
                    if source and not (source.get('registry') in ('https://pypi.org/simple', 'https://pypi.org/simple/')
                                       or source.get('url') in ('https://pypi.org/simple', 'https://pypi.org/simple/')):
                        omitted.append(file + ': 로컬·Git·사설 패키지 제외')
                        continue
                    add('PyPI', package.get('name'), package.get('version'), file)
            elif name in ('package-lock.json', 'npm-shrinkwrap.json'):
                data = json.loads((directory / file).read_text(encoding='utf-8-sig'))
                if not isinstance(data.get('packages'), dict):
                    omitted.append(file + ': npm lockfile v2/v3 필요')
                    continue
                for path, package in data['packages'].items():
                    if not path or 'node_modules/' not in path:
                        continue
                    resolved = package.get('resolved', '')
                    if package.get('link') or not resolved.startswith('https://registry.npmjs.org/'):
                        omitted.append(file + ': 공개 npm 레지스트리 버전 미확인')
                        continue
                    add('npm', package.get('name') or path.rsplit('node_modules/', 1)[-1], package.get('version'), file)
            elif name == 'pom.xml':
                source = (directory / file).read_text(encoding='utf-8-sig')
                if '<!DOCTYPE' in source.upper() or '<!ENTITY' in source.upper():
                    raise ValueError('XML declarations unsupported')
                root = ET.fromstring(source)
                for element in root.iter():
                    element.tag = element.tag.rsplit('}', 1)[-1]
                urls = [e.text or '' for e in root.findall('./repositories/repository/url')]
                if any(url.rstrip('/') not in ('https://repo.maven.apache.org/maven2', 'https://repo1.maven.org/maven2') for url in urls):
                    omitted.append(file + ': 사용자 지정 Maven 저장소 · 공개 DB 조회 제외')
                    continue
                properties = {e.tag: e.text for e in root.findall('./properties/*')}
                for package in root.findall('./dependencies/dependency'):
                    group, artifact, version = (package.findtext(key) for key in ('groupId', 'artifactId', 'version'))
                    if version and re.fullmatch(r'\$\{[^{}]+\}', version):
                        version = properties.get(version[2:-1])
                    if not group or not artifact:
                        omitted.append(file + ': Maven 좌표 미해석')
                        continue
                    add('Maven', group + ':' + artifact, version, file)
                omitted.append(file + ': Maven 직접 의존성만 수집 · 부모 POM·BOM·전이 의존성 미해석')
            elif name in ('package.json', 'pyproject.toml', 'Pipfile', 'Pipfile.lock', 'yarn.lock', 'pnpm-lock.yaml', 'build.gradle'):
                # A sibling supported lock can resolve manifest version ranges.
                sibling = Path(file).parent
                locks = {str(sibling / n).replace('\\', '/') for n in ('package-lock.json', 'npm-shrinkwrap.json', 'uv.lock', 'poetry.lock')}
                if not locks.intersection(files):
                    omitted.append(file + ': 지원하는 잠금 파일 또는 고정 requirements 필요')
        except (ValueError, TypeError, AttributeError, OSError, ET.ParseError):
            omitted.append(file + ': 의존성 파일 해석 실패')
    return list(packages.values()), sorted(set(omitted))


def check(directory, files, enabled=False):
    packages, omitted = inventory(directory, files)
    row = {'id': 'dependencies', 'kind': 'dependencies', 'kisa': [], 'owasp': ['A03:2025'],
           'state': 'skipped', 'outcome': 'unassessed', 'reason': '외부 의존성 DB 조회 미선택',
           'evidence': [], 'inventory_count': len(packages), 'checked_count': 0, 'omitted': omitted}
    if not enabled:
        return row
    if not packages:
        row['reason'] = '조회할 공개 패키지의 고정 버전 없음 · 지원 범위 확인 필요'
        return row
    if len(packages) > MAX_PACKAGES:
        row['omitted'].append(f'패키지 상한 {MAX_PACKAGES}개 초과 · 나머지 미조회')
    selected = packages[:MAX_PACKAGES]
    failures = False
    with requests.Session() as session:
        session.trust_env = False
        for start in range(0, len(selected), 50):
            batch = selected[start:start + 50]
            payload = {'queries': [{'package': {'name': p['name'], 'ecosystem': p['ecosystem']}, 'version': p['version']} for p in batch]}
            try:
                with session.post(OSV_URL, json=payload, timeout=(5, 20), allow_redirects=False, stream=True) as response:
                    if response.status_code != 200:
                        raise ValueError('OSV HTTP failure')
                    chunks, size = [], 0
                    for chunk in response.iter_content(65536):
                        size += len(chunk)
                        if size > 2 * 1024 * 1024:
                            raise ValueError('OSV response too large')
                        chunks.append(chunk)
                    results = json.loads(b''.join(chunks))['results']
                if not isinstance(results, list) or len(results) != len(batch):
                    raise ValueError('incomplete OSV result')
                validated = []
                for package, result in zip(batch, results):
                    vulns = result.get('vulns', [])
                    if not isinstance(vulns, list):
                        raise ValueError('invalid OSV vulnerabilities')
                    ids = [v['id'] for v in vulns]
                    if not all(isinstance(v, str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,150}', v) for v in ids):
                        raise ValueError('invalid OSV ID')
                    validated.append((package, result, ids))
                for package, result, ids in validated:
                    row['checked_count'] += 1
                    if result.get('next_page_token') or len(ids) > 50:
                        row['omitted'].append(package['name'] + ': 취약점 결과 일부만 수신')
                    for vid in ids[:50]:
                        row['evidence'].append(f"{package['ecosystem']} {package['name']}@{package['version']} · {vid} · {', '.join(package['files'])} · https://osv.dev/vulnerability/{vid}")
            except (requests.RequestException, ValueError, KeyError, TypeError, AttributeError):
                failures = True
                break
    row['state'] = ('partial' if row['checked_count'] else 'failed') if failures else 'partial' if row['omitted'] else 'completed'
    row['outcome'] = 'candidate' if row['evidence'] else 'no_findings' if row['state'] == 'completed' else 'unassessed'
    row['reason'] = f"OSV 고정 버전 조회 {row['checked_count']}/{len(packages)}개 · 실제 호출 가능성·패치 적용 여부는 미검증"
    if failures:
        row['reason'] += ' · 조회 실패, 미조회 패키지는 판정 보류'
    return row
