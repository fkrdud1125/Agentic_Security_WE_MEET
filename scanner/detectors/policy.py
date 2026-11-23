"""Explicit insecure policy settings; absence of a keyword is never a finding."""

import ast
import re
from pathlib import Path

from ..models import Severity
from ..normalize import RawHit, code_identity


def detect(name, content):
    hits = []

    def add(line, rule, code, cwe, title, remedy):
        hits.append(RawHit('policy', rule, name, line, cwe, [code], title, remedy,
                           Severity.MEDIUM, identity=code_identity(content, line, name.endswith('.py'))))

    if name.endswith('.py'):
        try:
            tree = ast.parse(content)
        except (SyntaxError, ValueError):
            return hits
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    key = (target.id if isinstance(target, ast.Name) else
                           target.slice.value if isinstance(target, ast.Subscript)
                           and isinstance(target.slice, ast.Constant) else None)
                    try:
                        value = ast.literal_eval(node.value)
                    except (ValueError, TypeError):
                        continue
                    if key == 'WTF_CSRF_ENABLED' and value is False:
                        add(node.lineno, 'vs-policy-csrf-disabled', 'CI-07', 'CWE-352',
                            'CSRF 보호 명시적 비활성화', '쿠키 인증의 상태 변경 요청에 CSRF 보호를 적용하고 예외 경로를 검토하세요.')
                    if key == 'AUTH_PASSWORD_VALIDATORS' and value == []:
                        add(node.lineno, 'vs-policy-password-validators', 'CI-09', 'CWE-521',
                            'Django 비밀번호 검증기 목록이 비어 있음', '가입·변경 흐름에 서버 측 비밀번호 검증을 적용하세요. 별도 검증 여부를 확인하세요.')
                    if key == 'LOGIN_DISABLED' and value is True:
                        add(node.lineno, 'vs-policy-login-disabled', 'CI-10', 'CWE-287',
                            'Flask 로그인 보호 비활성화', '운영 설정에서 LOGIN_DISABLED를 해제하고 중요 기능의 비로그인 접근을 검증하세요.')
                    if key == 'REST_FRAMEWORK' and isinstance(value, dict):
                        permissions = value.get('DEFAULT_PERMISSION_CLASSES')
                        if isinstance(permissions, (list, tuple)) and 'rest_framework.permissions.AllowAny' in permissions:
                            add(node.lineno, 'vs-policy-default-allowany', 'CI-10', 'CWE-287',
                                'DRF 기본 권한 정책이 AllowAny', '공개 API 의도와 각 중요 뷰의 인증 정책 재정의를 확인하세요. 기본 정책만으로 실제 우회를 확정하지 않습니다.')
                        if value.get('DEFAULT_THROTTLE_CLASSES') == []:
                            add(node.lineno, 'vs-policy-throttle-disabled', 'CI-20', 'CWE-799',
                                'DRF 기본 요청 제한 목록이 비어 있음', '로그인·복구·고비용 API의 뷰별 제한과 프록시 제한을 확인하세요.')
                    if key == 'RATELIMIT_ENABLED' and value is False:
                        add(node.lineno, 'vs-policy-ratelimit-disabled', 'CI-20', 'CWE-799',
                            '요청 속도 제한 명시적 비활성화', '운영 환경의 속도 제한을 활성화하고 계정·클라이언트별 제한을 확인하세요.')
                    if key == 'PASSWORD_RESET_TIMEOUT' and type(value) in (int, float) and value > 86400:
                        add(node.lineno, 'vs-policy-reset-timeout', 'CI-12', 'CWE-640',
                            '비밀번호 재설정 토큰 유효기간이 24시간 초과', '업무 정책에 맞게 유효기간을 줄이고 일회성·대상 계정 바인딩을 검증하세요. 24시간은 이 도구의 검토 임계값입니다.')
                    if key == 'LOGGING' and isinstance(value, dict) and value.get('disable_existing_loggers') is True:
                        add(node.lineno, 'vs-policy-security-logging', 'V-05', 'CWE-778',
                            '기존 로거 비활성화 설정', '인증 실패·권한 오류 등 보안 이벤트 로거가 별도로 구성되는지 확인하세요.')
                    if key in ('MIDDLEWARE', 'MIDDLEWARE_CLASSES') and isinstance(value, (list, tuple)):
                        if ('django.contrib.sessions.middleware.SessionMiddleware' in value
                                and 'django.middleware.csrf.CsrfViewMiddleware' not in value):
                            add(node.lineno, 'vs-policy-csrf-middleware', 'CI-07', 'CWE-352',
                                '세션 미들웨어 설정에서 CSRF 미들웨어 미확인', '개별 뷰의 대체 보호를 확인하고 쿠키 인증 경로에 CSRF 검증을 적용하세요.')
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for decorator in node.decorator_list:
                    expression = decorator.func if isinstance(decorator, ast.Call) else decorator
                    if ast.unparse(expression).split('.')[-1] == 'csrf_exempt':
                        add(decorator.lineno, 'vs-policy-csrf-exempt', 'CI-07', 'CWE-352',
                            'CSRF 검증 예외 뷰', '웹훅 서명 등 대체 보호와 쿠키 인증 여부를 확인하세요. 예외 자체로 악용이 확정되지는 않습니다.')
                # A clear fail-open return in an authentication helper is reviewable
                # without guessing whether an absent decorator is an auth bypass.
                if re.search(r'(auth|permission|access|authorize)', node.name, re.I):
                    for handler in (n for n in ast.walk(node) if isinstance(n, ast.ExceptHandler)):
                        if any(isinstance(n, ast.Return) and isinstance(n.value, ast.Constant)
                               and n.value.value is True for n in handler.body):
                            add(handler.lineno, 'vs-policy-auth-fail-open', 'CI-10', 'CWE-636',
                                '인증·권한 함수가 예외 발생 시 True 반환', '오류 시 접근을 거부하고 예외 원인을 기록하세요. True가 허용을 의미하는지 호출자를 확인하세요.')
                            hits[-1].kisa.append('V-06')
                if re.search(r'(checkout|payment|purchase|order|refund)', node.name, re.I):
                    for call in (n for n in ast.walk(node) if isinstance(n, ast.Call)):
                        if ast.unparse(call.func).split('.')[-1] not in ('charge', 'create', 'pay', 'refund'):
                            continue
                        for kw in call.keywords:
                            if kw.arg in ('amount', 'price', 'total') and re.search(r'\brequest\.(?:args|form|json|data)\b', ast.unparse(kw.value)):
                                add(call.lineno, 'vs-policy-client-payment-amount', 'CI-13', 'CWE-602',
                                    '요청 금액을 결제·주문 호출에 직접 전달', '서버에서 상품·수량·할인 정책으로 금액을 계산하고 요청값과 대조하세요. 상위 검증은 추가 확인해야 합니다.')
            if isinstance(node, ast.Call):
                function = ast.unparse(node.func)
                if function in ('requests.post', 'requests.put', 'httpx.post', 'httpx.put') and node.args:
                    url = node.args[0]
                    sensitive = any(kw.arg in ('data', 'json', 'auth', 'headers') and
                                    re.search(r'(password|token|secret|authorization|credential)', ast.unparse(kw.value), re.I)
                                    for kw in node.keywords)
                    if isinstance(url, ast.Constant) and isinstance(url.value, str) and url.value.startswith('http://') and sensitive:
                        add(node.lineno, 'vs-policy-cleartext-credentials', 'CI-17', 'CWE-319',
                            '민감정보를 HTTP URL로 전송하는 코드', '수신 서버와 전체 전송 구간에 HTTPS를 적용하세요. 개발 전용 코드인지도 확인하세요.')
    # Only deployment configuration, never matching quoted strings in source code.
    if Path(name).suffix.lower() == '.conf' or Path(name).name in ('nginx.conf', 'httpd.conf'):
        for line, text in enumerate(content.splitlines(), 1):
            text = text.split('#', 1)[0].strip()
            tokens = text.lower().split()
            index_flags = [token for token in tokens[1:] if token in ('indexes', '+indexes', '-indexes')]
            indexes = bool(tokens and tokens[0] == 'options' and index_flags and index_flags[-1] != '-indexes')
            if re.fullmatch(r'autoindex\s+on\s*;', text, re.I) or indexes:
                add(line, 'vs-policy-directory-index', 'CI-03', 'CWE-548',
                    '디렉터리 목록 공개 설정', '해당 서버·경로에 적용되는 설정인지 확인하고 의도하지 않은 목록 공개를 비활성화하세요.')
            if re.fullmatch(r'TraceEnable\s+on', text, re.I):
                add(line, 'vs-policy-trace-enabled', 'CI-21', 'CWE-749',
                    'HTTP TRACE 명시적 활성화', '운영 환경에서 TRACE 필요성과 접근 통제를 확인하고 불필요하면 비활성화하세요.')
    return hits
