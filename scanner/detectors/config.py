"""Inspect literal framework settings without evaluating application code."""

import ast

from ..normalize import RawHit, code_identity
from ..models import Severity


def detect(name, content):
    hits, summary = [], []
    if not name.endswith('.py'):
        return hits, summary
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError):
        return hits, summary

    def add(node, key, codes, cwe, title, fix, value):
        summary.append({'file': name, 'line': node.lineno, 'setting': key, 'value': value})
        hits.append(RawHit('config', 'vs-config-' + key, name, node.lineno, cwe, codes, title, fix,
                           identity=code_identity(content, node.lineno, True)))

    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                key = ast.unparse(target)
                if isinstance(node.value, ast.Constant):
                    value = node.value.value
                    if key == 'DEBUG' and value is True:
                        add(node, 'debug', ['CI-04'], 'CWE-489', '디버그 설정 활성화', '배포 환경에서는 디버그를 끄세요.', True)
                    elif any(k in key for k in ('SESSION_COOKIE_SECURE', 'SESSION_COOKIE_HTTPONLY', 'CSRF_COOKIE_SECURE')) and value is False:
                        add(node, 'cookie-flags', ['CI-16', 'CI-18'], 'CWE-614', '쿠키 보호 속성 비활성화',
                            '인증 쿠키에 Secure·HttpOnly·SameSite 정책을 적용하세요.', False)
        if not isinstance(node, ast.Call):
            continue
        function = ast.unparse(node.func)
        kwargs = {k.arg: k.value for k in node.keywords if k.arg}
        literal = {k: v.value for k, v in kwargs.items() if isinstance(v, ast.Constant)}
        if function.endswith(('.run', 'FastAPI', 'Starlette')) and literal.get('debug') is True:
            add(node, 'debug', ['CI-04'], 'CWE-489', '디버그 모드 활성화', '배포 환경에서는 디버그를 끄세요.', True)
        if function.endswith(('CORS', 'add_middleware')):
            cors = function.endswith('CORS') or any('CORSMiddleware' in ast.unparse(a) for a in node.args)
            origin = kwargs.get('allow_origins', kwargs.get('origins'))
            try:
                origin = ast.literal_eval(origin) if origin is not None else '*' if function.endswith('CORS') else None
            except (ValueError, TypeError):
                origin = None
            if cors and (origin == '*' or isinstance(origin, list) and '*' in origin):
                add(node, 'cors', ['V-02', 'CI-05'], 'CWE-942', '와일드카드 CORS 설정',
                    '공개 API인지 확인하고 인증 응답은 신뢰한 Origin만 허용하세요.', '*')
        if function.endswith('.set_cookie'):
            # Explicit **kwargs may contain the flags; absence cannot be established there.
            if any(k.arg is None for k in node.keywords):
                continue
            missing = [k for k in ('secure', 'httponly') if k not in kwargs or literal.get(k) is False]
            if 'samesite' not in kwargs or literal.get('samesite') in (None, 'None', 'none'):
                missing.append('samesite')
            if missing:
                add(node, 'cookie-flags', ['CI-16', 'CI-18'], 'CWE-614', '쿠키 보호 속성 확인 필요',
                    '인증 쿠키인지 확인하고 Secure·HttpOnly·SameSite 속성을 명시하세요.', ', '.join(missing))
                hits[-1].severity = Severity.MEDIUM
    return hits, summary
