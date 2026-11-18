"""Local read-only checks and evidence normalization for committed web sources."""

import ast
import io
import re
import tokenize

from .models import AppProfile
from .detectors import secrets, config, routes
from .detectors.semgrep import convert, semgrep
from .normalize import RawHit, normalize, code_identity


# Only structural syntax from a matched line enters reports or model input.
VISIBLE_NAMES = {"return", "def", "if", "else", "execute", "fetchone", "Markup", "True", "False", "None"}


def masked_line(line):
    try:
        tokens = tokenize.generate_tokens(io.StringIO(line.strip()).readline)
        return " ".join(t.string if (t.type == tokenize.OP or t.string in VISIBLE_NAMES)
                        else "[가림]" for t in tokens if t.type in
                        (tokenize.OP, tokenize.NAME, tokenize.NUMBER, tokenize.STRING))[:350]
    except (IndentationError, tokenize.TokenError):
        return "[코드 생략]"


def profile(directory, files):
    frameworks = set()
    routes = 0
    auth_signals = set()
    for name in files:
        if not name.endswith(".py"):
            if name.endswith(('.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs')) and re.search(
                r'''\b(?:from\s*['"]express['"]|require\(\s*['"]express['"]\s*\))''',
                (directory / name).read_text(encoding='utf-8-sig')):
                frameworks.add('Express')
            continue
        try:
            tree = ast.parse((directory / name).read_text(encoding="utf-8-sig"))
        except (SyntaxError, ValueError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                modules = [node.module or ""] if isinstance(node, ast.ImportFrom) else [a.name for a in node.names]
                for module in modules:
                    package = module.split(".")[0]
                    if package in {"flask_login", "flask_jwt_extended", "jwt", "authlib"}:
                        auth_signals.add(package)
                    label = {"flask": "Flask", "fastapi": "FastAPI", "django": "Django"}.get(module.split(".")[0])
                    if label:
                        frameworks.add(label)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                routes += sum(isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
                              and d.func.attr in {"route", "get", "post", "put", "patch", "delete"}
                              for d in node.decorator_list)
    auth = "인증 관련 모듈 참조: " + ", ".join(sorted(auth_signals)) if auth_signals else None
    return AppProfile(", ".join(sorted(frameworks)) or None, routes, auth)


class Inspection(list):
    def __init__(self, findings, partial_files, route_rows, settings):
        super().__init__(findings)
        self.partial_files = sorted(set(partial_files))
        self.routes = route_rows
        self.config_summary = settings


def inspect(directory, files):
    allowed = set(files)
    matched = semgrep(directory) if files else []
    raw = [convert(hit, allowed) for hit in matched]
    partial = list(getattr(matched, 'partial_files', []))
    if any(name not in allowed for name in partial):
        raise ValueError('부분 실패 파일이 검사 범위 밖입니다.')
    contents = {name: (directory / name).read_text(encoding='utf-8-sig') for name in files}
    for hit in raw:
        lines = contents[hit.file].splitlines()
        if hit.line > len(lines):
            raise ValueError('검사 근거 줄이 파일 범위 밖입니다.')
        hit.evidence = masked_line(lines[hit.line - 1])
        hit.identity = code_identity(contents[hit.file], hit.line, hit.file.endswith('.py'))
    route_rows, settings = [], []
    for name, content in contents.items():
        raw.extend(secrets.detect(name, content))
        found, summary = config.detect(name, content)
        raw.extend(found); settings.extend(summary)
        found, rows = routes.detect(name, content)
        raw.extend(found); route_rows.extend(rows)
        if name.endswith('.py'):
            try:
                ast.parse(content)
            except (SyntaxError, ValueError):
                partial.append(name)
    for entry in getattr(files, 'sensitive_files', []):
        raw.append(RawHit('secrets', 'vs-secret-file', entry['path'], 1, 'CWE-540', ['CI-05', 'V-01'],
            '민감 파일이 Git HEAD에 포함됨', '실제 자격증명이면 교체하고 추적을 해제하세요. .gitignore 추가만으로 과거 커밋에서 삭제되지 않습니다.',
            evidence='[파일 존재만 기록 · 내용 저장/전송 없음]', identity=entry['kind']))
    settings.extend({'file': h.file, 'line': h.line, 'setting': h.rule_id, 'value': '확인 필요'}
                    for h in raw if h.detector == 'semgrep' and h.rule_id in
                    {'vs-js-cors', 'vs-js-cookie', 'vs-js-error'})
    result = Inspection(normalize(raw), partial, route_rows, settings)
    result.file_upload = any('request.files' in text or 'UploadFile' in text or 'multer' in text
                             for text in contents.values())
    return result
