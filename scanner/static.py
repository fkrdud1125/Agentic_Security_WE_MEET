"""Local read-only checks and evidence normalization for committed web sources."""

import ast
import io
import json
import os
import re
import shutil
import subprocess
import sysconfig
import tokenize
from pathlib import Path

from .models import AppProfile, Confidence, Finding, Location, Severity


# Only structural syntax from a matched line enters reports or model input.
VISIBLE_NAMES = {"return", "def", "if", "else", "execute", "fetchone", "Markup", "True", "False", "None"}
SECRET = re.compile(r"""(?ix)["']?\b[\w.-]*(?:api[_-]?key|secret|password|token)\b["']?\s*[:=]\s*["']([^"'\r\n]{8,})["']""")
KEY = re.compile(r"\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,})")
SENSITIVE = re.compile(r"api.?key|secret|password|token|credential|authorization|private.?key", re.I)
DETAILS = {
    "literal-token": ("소스에 포함된 인증정보 후보", "CWE-798", "A07:2021", Severity.HIGH,
                      "코드 열람자에게 인증정보가 노출될 수 있습니다.",
                      "실제 값인지 확인한 뒤 키를 교체하고 환경변수에서 읽으세요.",
                      '- API_TOKEN = "[가림]"\n+ API_TOKEN = os.environ["API_TOKEN"]'),
    "concatenated-select": ("문자열을 결합한 SQL 실행", "CWE-89", "A03:2021", Severity.HIGH,
                            "외부 입력이 연결되면 쿼리의 의미가 달라질 수 있습니다.",
                            "DB 드라이버가 제공하는 매개변수 바인딩을 사용하세요. 아래는 SQLite 예시입니다.",
                            '- connection.execute(query)\n+ connection.execute("SELECT title FROM notes WHERE title = ?", (title,))'),
    "unescaped-markup": ("이스케이프를 생략한 마크업", "CWE-79", "A03:2021", Severity.MEDIUM,
                         "외부 입력이 HTML 응답에 도달하면 브라우저가 마크업을 해석할 수 있습니다.",
                         "템플릿의 자동 이스케이프를 유지하거나 값을 HTML 문맥에 맞게 이스케이프하세요.",
                         "- return Markup(title)\n+ return markupsafe.escape(title)"),
}


def sensitive_literals(tree):
    """Find literal values under credential assignments, dict keys and keyword arguments."""
    literals = []
    for node in ast.walk(tree):
        values = []
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(SENSITIVE.search(ast.unparse(t)) for t in targets) and node.value is not None:
                values.append(node.value)
        if isinstance(node, ast.keyword) and node.arg and SENSITIVE.search(node.arg):
            values.append(node.value)
        if isinstance(node, ast.Dict):
            values.extend(v for k, v in zip(node.keys, node.values)
                          if isinstance(k, ast.Constant) and isinstance(k.value, str) and SENSITIVE.search(k.value))
        for value in values:
            pending = [value]
            while pending:
                candidate = pending.pop()
                if isinstance(candidate, ast.Constant) and isinstance(candidate.value, str):
                    literals.append(candidate)
                elif isinstance(candidate, ast.JoinedStr):
                    literals.append(candidate)
                    pending.extend(candidate.values)
                elif isinstance(candidate, (ast.BinOp, ast.Tuple, ast.List)):
                    pending.extend(ast.iter_child_nodes(candidate))
                elif (isinstance(candidate, ast.Call) and isinstance(candidate.func, ast.Attribute)
                      and (candidate.func.attr == "getenv" or
                           candidate.func.attr == "get" and ast.unparse(candidate.func.value).endswith("environ"))):
                    pending.extend(candidate.args[1:2])
                    pending.extend(k.value for k in candidate.keywords if k.arg == "default")
    return literals


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


def semgrep(directory):
    scripts = Path(sysconfig.get_path("scripts"))
    binary = shutil.which("semgrep", path=str(scripts)) or shutil.which("semgrep")
    if not binary:
        raise RuntimeError("Semgrep을 찾을 수 없습니다. VibeScan 설치 환경을 확인하세요.")
    rules = Path(__file__).resolve().parents[1] / "rules" / "sample.yml"
    if not rules.is_file():
        rules = Path(sysconfig.get_path("data")) / "share/vibescan/sample.yml"
    command = [binary, "scan", "--metrics=off", "--disable-version-check", "--no-git-ignore",
               "--no-rewrite-rule-ids", "--strict", "--config", str(rules), "--json", "."]
    run = subprocess.run(command, cwd=directory, capture_output=True, timeout=180,
                         env={**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"})
    if run.returncode:
        raise RuntimeError(f"Semgrep 실행 실패 (종료 코드 {run.returncode}).")
    data = json.loads(run.stdout)
    if data["errors"] or data.get("skipped_rules"):
        raise RuntimeError("Semgrep이 소스 또는 규칙 일부를 분석하지 못했습니다.")
    return data["results"]


def inspect(directory, files):
    indexed = {}
    allowed = set(files)
    hits = semgrep(directory) if any(f.endswith(".py") for f in files) else []
    for hit in hits:
        name = Path(hit["path"]).as_posix()
        if name not in allowed or hit["check_id"] not in DETAILS:
            raise ValueError("Semgrep 결과의 파일 또는 규칙이 검사 범위 밖입니다.")
        indexed[(name, hit["start"]["line"], hit["check_id"])] = ["static:semgrep"]
    matched_lines = {(name, line) for name, line, _ in indexed}
    excerpts = {}
    for name in files:
        content = (directory / name).read_text(encoding="utf-8")
        secret_lines = set()
        if name.endswith(".py"):
            try:
                secret_lines = {n.lineno for n in sensitive_literals(ast.parse(content))
                                if isinstance(n, ast.Constant) and len(n.value) >= 8}
            except (SyntaxError, ValueError):
                pass
        for number, line in enumerate(content.splitlines(), 1):
            if (name, number) in matched_lines:
                excerpts[(name, number)] = masked_line(line)
            if number in secret_lines or SECRET.search(line) or KEY.search(line):
                indexed.setdefault((name, number, "literal-token"), []).append("static:secret")
    findings = []
    for number, ((name, line, rule), methods) in enumerate(sorted(indexed.items()), 1):
        title, cwe, owasp, severity, impact, fix, diff = DETAILS[rule]
        evidence = "[인증정보 값 가림]" if rule == "literal-token" else excerpts[(name, line)]
        findings.append(Finding(f"F-{number:03}", title, cwe, owasp, severity, Confidence.POTENTIAL,
                                Location(file=name, line=line), evidence, methods, impact, fix, diff))
    return findings
