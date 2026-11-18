"""Bounded route inventory; missing guards are review candidates, never proof."""

import ast
import re

from ..normalize import RawHit, code_identity

GUARD = re.compile(r'\b(?:login_required|jwt_required|permission_classes|get_current_user|require_auth|requireAuth|isAuthenticated|authenticate|authMiddleware)\b')
OWNER = re.compile(r'\b(?:current_user|user_id|owner_id|request\.user|req\.user)\b')
DB = re.compile(r'\.(?:execute|query|filter|get_or_404|findOne|findUnique|findById|raw)\s*\(')
ADMIN = re.compile(r'/(?:admin|internal|manage|dashboard)(?:/|$)', re.I)
JS_TOKENS = re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|\x27(?:\\.|[^\x27\\])*\x27|`(?:\\.|[^`\\])*`')


def detect(name, content):
    rows = []
    if name.endswith('.py'):
        try:
            tree = ast.parse(content)
        except (SyntaxError, ValueError):
            return [], []
        prefixes = {}
        global_guard = any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and
            any(isinstance(d, ast.Attribute) and d.attr == 'before_request' for d in n.decorator_list)
            for n in ast.walk(tree))
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                for kw in node.value.keywords:
                    if kw.arg in ('prefix', 'url_prefix') and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                        for target in node.targets:
                            prefixes[ast.unparse(target)] = kw.value.value
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ('register_blueprint', 'include_router') and node.args:
                for kw in node.keywords:
                    if kw.arg in ('prefix', 'url_prefix') and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                        prefixes[ast.unparse(node.args[0])] = kw.value.value
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            decorators = ' '.join(ast.unparse(d) for d in node.decorator_list)
            # Do not let comments/docstrings pretend to be guards.
            body = ast.unparse(ast.Module(body=[n for n in node.body if not isinstance(n, ast.Expr)
                           or not isinstance(n.value, ast.Constant) or not isinstance(n.value.value, str)], type_ignores=[]))
            guard = bool(GUARD.search(decorators + ' ' + ast.unparse(node.args)))
            guard = guard or any(isinstance(n, ast.If) and
                re.search(r'not (?:current_user|user\.is_authenticated)', ast.unparse(n.test)) and
                any(isinstance(x, (ast.Return, ast.Raise)) for x in n.body) for n in node.body)
            for d in node.decorator_list:
                if not isinstance(d, ast.Call) or not isinstance(d.func, ast.Attribute) or d.func.attr not in ('route', 'get', 'post', 'put', 'patch', 'delete'):
                    continue
                if not d.args or not isinstance(d.args[0], ast.Constant) or not isinstance(d.args[0].value, str):
                    continue
                path = prefixes.get(ast.unparse(d.func.value), '') + d.args[0].value
                methods = [d.func.attr.upper()] if d.func.attr != 'route' else ['GET']
                for kw in d.keywords:
                    if kw.arg == 'methods' and isinstance(kw.value, (ast.List, ast.Tuple)):
                        methods = [x.value.upper() for x in kw.value.elts if isinstance(x, ast.Constant) and isinstance(x.value, str)]
                for method in methods:
                    rows.append(row(name, node.lineno, path, method, node.name, body,
                                    '가드 참조' if guard else '전역 훅 확인 필요' if global_guard else None))
    elif name.endswith(('.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs')):
        # shortcut: literal Express handlers only; mounted routers/cross-file middleware remain unknown.
        masked = JS_TOKENS.sub(lambda m: ''.join('\n' if c == '\n' else ' ' for c in m.group()), content)
        comments = re.compile(r'//[^\n]*|/\*[\s\S]*?\*/')
        for match in re.finditer(r'''\b(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*(["'])([^"']+)\2\s*,''', content):
            if not masked[match.start():match.start()+3].strip():
                continue
            start = masked.find('{', match.end())
            if start < 0:
                continue
            depth, end = 1, start + 1
            while end < len(masked) and depth:
                depth += (masked[end] == '{') - (masked[end] == '}'); end += 1
            if depth:
                continue
            body = comments.sub('', content[start:end])
            before = masked[:match.start()]
            local = masked[match.end():start]
            guard = bool(GUARD.search(local))
            global_guard = bool(re.search(r'\bapp\.use\s*\([^;]*\b(?:auth|authenticate|requireAuth|authMiddleware)\b', before))
            rows.append(row(name, content.count('\n', 0, match.start())+1, match.group(3), match.group(1).upper(),
                            'Express handler', body, '가드 참조' if guard else '전역 미들웨어 확인 필요' if global_guard else None))
    hits = []
    for route in rows:
        if ADMIN.search(route['path']) and route['auth_guard'] is None:
            hits.append(RawHit('routes', 'vs-route-admin', name, route['line'], 'CWE-862', ['CI-19'],
                '관리자 라우트의 인증 가드 미확인', '서버 인증·권한 검사를 적용하고 상위 미들웨어까지 확인하세요.'))
        if route['path_params'] and route['db_access'] and not route['ownership_check']:
            hits.append(RawHit('routes', 'vs-route-idor', name, route['line'], 'CWE-639', ['CI-11'],
                '객체 조회의 소유자 조건 미확인', '조회 대상과 현재 사용자·테넌트의 권한을 서버에서 대조하세요.'))
    for hit in hits:
        hit.identity = code_identity(content, hit.line, name.endswith('.py'))
    return hits, rows


def row(name, line, path, method, handler, body, guard):
    return {'file': name, 'line': line, 'method': method, 'path': path, 'handler': handler,
            'auth_guard': guard, 'path_params': [next(x for x in match if x) for match in
                re.findall(r'<(?:\w+:)?(\w+)>|\{(\w+)\}|:(\w+)', path)],
            'db_access': bool(DB.search(body)), 'ownership_check': bool(OWNER.search(body)),
            'state_changing': method in ('POST', 'PUT', 'PATCH', 'DELETE'),
            'rate_limited': bool(re.search(r'limit|throttle', body)),
            'note': '정적 단서 · 상위 미들웨어와 실제 권한 정책은 수동 확인'}
