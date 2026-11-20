"""Shared credential recognition for detection and model redaction."""
import ast
import base64
import json
import re

from ..normalize import RawHit, code_identity
from ..models import Severity

SECRET = re.compile(r"""(?ix)["']?\b[\w.-]*(?:api[_-]?key|secret|password|token)\b["']?\s*[:=]\s*["']([^"'\r\n]{8,})["']""")
KEY = re.compile(r"(?:sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,}"
                 r"|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|[sr]k_live_[A-Za-z0-9]{16,}"
                 r"|xox[baprs]-[A-Za-z0-9-]{16,}|eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
                 r"|[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/'\"]+:[^\s@'\"]+@[^\s'\"]+"
                 r"|-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----)")
SENSITIVE = re.compile(r"api.?key|secret|password|token|credential|authorization|private.?key|(?:^|_)key$|(?:^|_)(?:pwd|dsn)$", re.I)
ASSIGNMENT = re.compile(r'''["']?([\w.-]+)["']?\s*[:=]\s*["']([^"'\r\n]*)["']''')
PLACEHOLDER = re.compile(r"^(?:your[-_ ].*|x{3,}|example|test|dummy|changeme|placeholder|<.*>|\$\{.*\})$", re.I)
SIGNING = re.compile(r"secret_key|jwt_secret|session_secret", re.I)
# A lowercase slug ("family-lounge", "esg_strategy") is an identifier unless the line names a real credential.
SLUG = re.compile(r"[a-z][a-z0-9]*(?:[-_.][a-z0-9]+)+")
STRONG = re.compile(r"pass(?:word|wd)?|pwd|secret|token|credential|api.?key|private.?key|auth", re.I)
# Tests, examples and seed data hold throwaway values; they stay visible but do not raise the risk score.
SAMPLE_PATH = re.compile(r"(?:^|/)(?:tests?|__tests__|specs?|fixtures?|seeds?|examples?|samples?|mocks?|__mocks__)/"
                         r"|(?:^|/)(?:test_[^/]*|[^/]*_test\.py|[^/]*\.(?:test|spec)\.[jt]sx?)$", re.I)


def hidden_values(source):
    values = set(KEY.findall(source))
    values.update(m.group(2) for m in ASSIGNMENT.finditer(source)
                  if SENSITIVE.search(m.group(1)) and m.group(2))
    return values


def service_role(value):
    try:
        payload = value.split('.')[1]
        return json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4))).get('role') == 'service_role'
    except (ValueError, IndexError, UnicodeError, AttributeError):
        return False


def detect(name, content):
    hits = {}
    lines = content.splitlines()
    sample = bool(SAMPLE_PATH.search(name))

    def add(line, value, signing=False, known=False):
        """known: the value has a vendor key format (sk-live…, AKIA…), which is a leak wherever it sits."""
        if not value or (PLACEHOLDER.fullmatch(value) and not signing):
            return
        if not signing and len(value) < 8:
            return
        if not (known or signing) and SLUG.fullmatch(value) and not STRONG.search(lines[line - 1]):
            return
        weak = signing and len(value) < 32
        rule = 'weak-signing-key' if weak else 'literal-token'
        codes = ['CI-16'] if weak else ['CI-05']
        title = '약한 고정 서명키' if weak else '소스에 포함된 인증정보 후보'
        critical = service_role(value)
        severity = Severity.CRITICAL if critical else Severity.HIGH
        if critical:
            codes += ['V-04']; title = '권한이 높은 service_role 키 노출'
        elif sample and not known:
            severity, title = Severity.INFO, '테스트·예제 파일의 인증정보 후보'
        previous = hits.get((line, rule))
        if previous and list(Severity).index(previous.severity) <= list(Severity).index(severity):
            return  # keep the stronger reading of the same line
        hits[(line, rule)] = RawHit('secrets', rule, name, line, 'CWE-321' if weak else 'CWE-798',
            codes, title, '노출된 키를 교체하고 서버 환경변수 또는 비밀 저장소에서 읽으세요. 서명키는 충분한 난수를 사용하세요.',
            severity, evidence='[인증정보 값 가림]',
            identity=code_identity(content, line, name.endswith('.py')))
    for line, text in enumerate(content.splitlines(), 1):
        for match in KEY.finditer(text):
            add(line, match.group(), known=True)
        for match in ASSIGNMENT.finditer(text):
            if SENSITIVE.search(match.group(1)):
                add(line, match.group(2), bool(SIGNING.search(match.group(1))))
    if name.endswith('.py'):
        try:
            tree = ast.parse(content)
            for node in sensitive_literals(tree):
                if isinstance(node, ast.Constant):
                    add(node.lineno, node.value)
            for node in ast.walk(tree):
                if isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(node.value, ast.Constant):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    if isinstance(node.value.value, str) and any(SIGNING.search(ast.unparse(t)) for t in targets):
                        add(node.value.lineno, node.value.value, True)
        except (SyntaxError, ValueError):
            pass
    # A weak signing key is the more specific explanation for the same literal.
    for line, rule in list(hits):
        if rule == 'weak-signing-key':
            hits.pop((line, 'literal-token'), None)
    return list(hits.values())
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
