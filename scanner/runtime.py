"""Opt-in, bounded HTTP scenarios. Target code and config expressions never execute."""

import json
import os
import re
import time
from urllib.parse import urlsplit, urljoin, unquote

import requests

from .criteria import OWASP_KISA
from .kisa import catalog

MAX_REQUESTS = 40
MAX_BODY = 256 * 1024


def validate(config):
    if config is None:
        return None
    if not isinstance(config, dict) or set(config) - {'base_url', 'allow_mutations', 'allow_http_credentials', 'profiles', 'checks'}:
        raise ValueError('실행 검증 설정 형식이 잘못되었습니다.')
    if len(json.dumps(config)) > 65536:
        raise ValueError('실행 검증 설정은 64KB 이하여야 합니다.')
    url = config.get('base_url', '')
    if not isinstance(url, str) or len(url) > 2048 or any(ord(c) < 33 for c in url):
        raise ValueError('테스트 base_url을 확인하세요.')
    parsed = urlsplit(url)
    if (parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path not in ('', '/') or '\\' in url):
        raise ValueError('base_url은 인증정보·경로·쿼리가 없는 http(s) 원점이어야 합니다.')
    try:
        parsed.port
    except ValueError:
        raise ValueError('테스트 포트가 잘못되었습니다.') from None
    for flag in ('allow_mutations', 'allow_http_credentials'):
        if flag in config and type(config[flag]) is not bool:
            raise ValueError('실행 허용 설정은 true/false여야 합니다.')
    profiles = config.get('profiles', {})
    if not isinstance(profiles, dict) or len(profiles) > 5:
        raise ValueError('인증 프로필은 최대 5개입니다.')
    env_pattern = r'[A-Z_][A-Z0-9_]{0,99}'
    for name, headers in profiles.items():
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,50}', name) or not isinstance(headers, dict) or len(headers) > 8:
            raise ValueError('인증 프로필 형식이 잘못되었습니다.')
        for header, env in headers.items():
            if (not isinstance(header, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9-]{0,63}', header)
                    or header.lower() in ('host', 'content-length', 'transfer-encoding', 'connection', 'proxy-authorization')
                    or not isinstance(env, str) or not re.fullmatch(env_pattern, env)):
                raise ValueError('인증 헤더는 허용된 헤더명과 환경변수 이름으로 설정하세요.')
    checks = config.get('checks')
    if not isinstance(checks, list) or not 1 <= len(checks) <= 21:
        raise ValueError('검증 시나리오는 1~21개여야 합니다.')
    codes = {row['official_code'] for row in catalog()['items'] if row.get('official_code')}
    ids, count = set(), 0
    for check in checks:
        if not isinstance(check, dict) or set(check) != {'id', 'criteria', 'steps'}:
            raise ValueError('시나리오는 id, criteria, steps가 필요합니다.')
        name = check['id']
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,60}', name) or name in ids:
            raise ValueError('시나리오 id는 중복 없는 영문·숫자 이름이어야 합니다.')
        ids.add(name)
        if not isinstance(check['criteria'], list) or not check['criteria'] or not all(isinstance(c, str) and c in codes for c in check['criteria']):
            raise ValueError('시나리오에 주통기 공식 코드를 지정하세요.')
        steps = check['steps']
        if not isinstance(steps, list) or not steps:
            raise ValueError('시나리오 요청이 없습니다.')
        for step in steps:
            if not isinstance(step, dict) or set(step) - {'method', 'path', 'profile', 'json_env', 'expect'}:
                raise ValueError('검증 요청 형식이 잘못되었습니다.')
            method = step.get('method', 'GET')
            if method not in ('GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'):
                raise ValueError('지원하지 않는 검증 메소드입니다.')
            if method not in ('GET', 'HEAD', 'OPTIONS') and not config.get('allow_mutations'):
                raise ValueError('상태 변경 요청에는 allow_mutations: true가 필요합니다.')
            path = step.get('path', '')
            if (not isinstance(path, str) or len(path) > 2048 or not path.startswith('/') or path.startswith('//')
                    or any(ord(c) < 33 for c in path) or '\\' in unquote(path)
                    or urlsplit(path).netloc or urlsplit(path).scheme or urlsplit(path).fragment):
                raise ValueError('검증 경로는 지정 원점 안의 절대 경로여야 합니다.')
            if step.get('profile') is not None and (not isinstance(step['profile'], str) or step['profile'] not in profiles):
                raise ValueError('없는 인증 프로필입니다.')
            if 'json_env' in step and (method in ('GET', 'HEAD', 'OPTIONS') or not isinstance(step['json_env'], str)
                                       or not re.fullmatch(env_pattern, step['json_env'])):
                raise ValueError('요청 데이터는 상태 변경 요청의 json_env로 지정하세요.')
            expect = step.get('expect')
            if (not isinstance(expect, dict) or set(expect) - {'status', 'contains_env', 'absent_env'}
                    or not isinstance(expect.get('status'), list) or not expect['status']
                    or not all(type(s) is int and 100 <= s <= 599 for s in expect['status'])):
                raise ValueError('요청별 기대 HTTP 상태 목록이 필요합니다.')
            for key in ('contains_env', 'absent_env'):
                if key in expect and (not isinstance(expect[key], str) or not re.fullmatch(env_pattern, expect[key])):
                    raise ValueError('응답 비교 문자열은 환경변수로 지정하세요.')
            count += 1
    if count > MAX_REQUESTS:
        raise ValueError('실행 검증 요청은 최대 40개입니다.')
    return config


def run(config):
    config = validate(config)
    if config is None:
        return []
    rows = []
    deadline = time.monotonic() + 120
    for check in config['checks']:
        row = {'id': 'runtime-' + check['id'], 'kind': 'runtime', 'kisa': check['criteria'],
               'owasp': [code for code, related in OWASP_KISA.items() if set(related).intersection(check['criteria'])],
               'state': 'skipped', 'outcome': 'unassessed', 'reason': '필수 환경변수 또는 요청 조건 미확인', 'evidence': []}
        rows.append(row)
        prepared = []
        try:
            # Resolve every credential/assertion before any step in this scenario.
            for step in check['steps']:
                headers = {header: os.environ[env] for header, env in config.get('profiles', {}).get(step.get('profile'), {}).items()}
                if any(not value or '\r' in value or '\n' in value or len(value) > 8192 for value in headers.values()):
                    raise ValueError('invalid credential')
                payload = None
                if 'json_env' in step:
                    raw = os.environ[step['json_env']]
                    if len(raw) > 16384:
                        raise ValueError('request too large')
                    payload = json.loads(raw)
                markers = {key: os.environ[step['expect'][key]] for key in ('contains_env', 'absent_env') if key in step['expect']}
                if any(not value or len(value) > 4096 for value in markers.values()):
                    raise ValueError('invalid marker')
                if config['base_url'].startswith('http:') and (headers or payload is not None) and not config.get('allow_http_credentials'):
                    raise ValueError('plaintext credentials not allowed')
                prepared.append((step, headers, payload, markers))
        except (KeyError, ValueError, TypeError):
            continue
        mismatch = False
        with requests.Session() as session:
            session.trust_env = False
            for index, (step, headers, payload, markers) in enumerate(prepared, 1):
                if time.monotonic() >= deadline:
                    row.update(state='partial', reason='전체 검증 시간 상한 도달 · 남은 요청 미수행')
                    break
                try:
                    session.cookies.clear()
                    kwargs = {'headers': headers, 'timeout': (3, 5), 'allow_redirects': False, 'stream': True}
                    if payload is not None:
                        kwargs['json'] = payload
                    with session.request(step.get('method', 'GET'), urljoin(config['base_url'], step['path']), **kwargs) as response:
                        chunks, size = [], 0
                        if markers:
                            for chunk in response.iter_content(1):
                                size += len(chunk)
                                if size > MAX_BODY or time.monotonic() >= deadline:
                                    raise ValueError('body/time limit')
                                chunks.append(chunk)
                        body = b''.join(chunks).decode('utf-8', errors='replace')
                        status = response.status_code
                        matched = status in step['expect']['status']
                        if 'contains_env' in markers:
                            matched = matched and markers['contains_env'] in body
                        if 'absent_env' in markers:
                            matched = matched and markers['absent_env'] not in body
                    row['evidence'].append(f"단계 {index}: {step.get('method', 'GET')} · HTTP {status} · 기대 조건 {'일치' if matched else '불일치'}")
                    if not matched:
                        mismatch = True
                        row.update(state='partial', reason='기대 조건 불일치 · 이후 단계 중단 · 원인 수동 확인 필요')
                        break
                except (requests.RequestException, ValueError, OSError):
                    row.update(state='failed' if not row['evidence'] else 'partial', reason='요청·TLS·응답 제한 오류 · 이후 단계 미수행')
                    break
            else:
                row.update(state='completed', reason='설정한 요청의 기대 조건 확인 · 전체 기준 충족이나 악용 가능성 확정 아님')
        row['outcome'] = 'candidate' if mismatch else 'no_findings' if row['state'] == 'completed' else 'unassessed'
    return rows
