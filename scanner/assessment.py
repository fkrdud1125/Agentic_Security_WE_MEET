"""Bounded, criterion-oriented evidence independent of static findings.

Evidence is a sampling of relevant code, never a claim that a feature is absent.
Non-Python code is deliberately conservative: literals/comments are removed;
ambiguous templates, regex/division and text blocks keep the file local.
"""

import re
from pathlib import Path

from .criteria import OWASP_KISA

SIGNALS = {
    'CI': r'\b(eval|exec|system|Popen|pickle|yaml|render_template_string|execSync)\b',
    'SI': r'\b(execute|executemany|query|raw|createStatement|prepareStatement)\b',
    'DI': r'\b(autoindex|Indexes|directory|StaticFiles|serveIndex)\b',
    'EP': r'\b(debug|DEBUG|traceback|exception_handler|printStackTrace|stack)\b',
    'IL': r'\b(logger|logging|serialize|jsonify|model_dump|toJSON)\b',
    'XS': r'\b(innerHTML|outerHTML|dangerouslySetInnerHTML|mark_safe|Markup|render_template)\b',
    'CF': r'\b(csrf|csrf_exempt|WTF_CSRF_ENABLED|CsrfViewMiddleware|csrfProtection)\b',
    'SF': r'\b(requests|httpx|fetch|axios|HttpClient|RestTemplate|WebClient|urlopen)\b',
    'BF': r'\b(password|validate_password|AUTH_PASSWORD_VALIDATORS|set_password)\b',
    'IA': r'\b(login|authenticate|login_required|Depends|Security|AllowAny|permitAll)\b',
    'IN': r'\b(owner_id|user_id|tenant_id|ownerId|userId|tenantId|hasRole|hasAuthority)\b',
    'PR': r'\b(reset_password|password_reset|resetToken|forgotPassword|PasswordResetTokenGenerator)\b',
    'PV': r'\b(checkout|payment|transaction|atomic|commit|rollback|order|refund)\b',
    'FU': r'\b(upload|UploadFile|multer|MultipartFile|secure_filename)\b',
    'FD': r'\b(send_file|send_from_directory|download|FileResponse|sendFile|readFile)\b',
    'IS': r'\b(session|jwt|logout|refresh_token|refreshToken|expires|verify)\b',
    'SN': r'\b(ssl|tls|https|redirect|SECURE_SSL_REDIRECT|verify)\b',
    'CC': r'\b(set_cookie|cookie|cookies|signedCookies|SESSION_COOKIE_SECURE)\b',
    'AE': r'\b(admin|is_admin|is_staff|isAdmin|SecurityFilterChain|PreAuthorize)\b',
    'AU': r'\b(limiter|rate_limit|ratelimit|throttle|RateLimiter|login|send_otp)\b',
    'WM': r'\b(methods|TraceEnable|doTrace|methodOverride|requestMatchers)\b',
}
EXTRA = {
    'A03:2025': r'\b(dependencies|devDependencies|requirements|subprocess|install|plugins)\b',
    'A04:2025': r'\b(hashlib|md5|sha1|random|secrets|encrypt|Cipher|bcrypt|scrypt|argon2)\b',
    'A06:2025': SIGNALS['PV'] + '|' + SIGNALS['AU'],
    'A08:2025': r'\b(pickle|yaml|deserialize|webhook|signature|hmac|compare_digest)\b',
    'A09:2025': r'\b(logger|logging|audit|alert|printStackTrace)\b',
    'A10:2025': r'\b(except|catch|finally|rollback|timeout|retry|raise|throw)\b',
}
MAX_EVIDENCE = 4
MAX_TOTAL = 60000


def structural_source(source):
    """Fail closed rather than send literals through an incomplete JS/Java lexer."""
    if '\\u' in source:
        return ''  # Java Unicode escapes precede comment/string tokenization.
    out, i = [], 0
    while i < len(source):
        if source.startswith('//', i):
            end = source.find('\n', i)
            i = len(source) if end < 0 else end
        elif source.startswith('/*', i):
            end = source.find('*/', i + 2)
            if end < 0:
                return ''
            out.append('\n' * source[i:end + 2].count('\n'))
            i = end + 2
        elif source[i] in ('`', '/') or source.startswith('"""', i):
            return ''
        elif source[i] in ('"', "'"):
            quote, end = source[i], i + 1
            while end < len(source):
                if source[end] == '\\':
                    end += 2
                elif source[end] == quote:
                    break
                else:
                    end += 1
            if end >= len(source):
                return ''
            out.append(quote + '[LITERAL]' + quote + '\n' * source[i:end + 1].count('\n'))
            i = end + 1
        else:
            out.append(source[i])
            i += 1
    return ''.join(out)


def prepare(context, directory, files, criteria):
    sources = dict(context.sources)
    for name in files:
        if Path(name).suffix.lower() in {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.java'}:
            clean = structural_source((directory / name).read_text(encoding='utf-8-sig'))
            if clean:
                sources[name] = context.clean(clean)
        elif Path(name).suffix.lower() == '.conf':
            # Only known directive values; paths, hosts, keys and comments stay local.
            lines = (directory / name).read_text(encoding='utf-8-sig').splitlines()
            clean_lines = []
            for line in lines:
                text = line.split('#', 1)[0].strip()
                allowed = re.fullmatch(r'(?:autoindex\s+(?:on|off)\s*;|TraceEnable\s+(?:on|off)|Options\s+[+-]?Indexes)', text, re.I)
                clean_lines.append(text if allowed else '')
            if any(clean_lines):
                sources[name] = '\n'.join(clean_lines)
    # Python's existing secret/comment sanitization is shared with finding review.
    source_lines = {name: source.splitlines() for name, source in sources.items()}
    prepared, budget = {}, 0
    criterion_budget = MAX_TOTAL // max(1, len(criteria))
    for criterion in criteria:
        code = criterion['code']
        patterns = ([SIGNALS[code]] if criterion['framework'] == 'kisa' else
                    [SIGNALS[key] for key in OWASP_KISA[code]] + ([EXTRA[code]] if code in EXTRA else []))
        pattern = re.compile('|'.join(patterns)) if patterns else None
        matches = []
        for name, lines in source_lines.items():
            for line, text in enumerate(lines, 1):
                if pattern and pattern.search(text):
                    matches.append((name, line))
        # Round-robin files: one large file must not consume every context slot.
        grouped = {}
        for name, line in matches:
            grouped.setdefault(name, []).append(line)
        ordered = [(name, points[index]) for index in range(max(map(len, grouped.values()), default=0))
                   for name, points in sorted(grouped.items()) if index < len(points)]
        evidence, spans, spent = [], [], 0
        for name, line in ordered:
            if len(evidence) >= MAX_EVIDENCE:
                break
            if any(n == name and start <= line <= end for n, start, end in spans):
                continue
            lines = source_lines[name]
            start, end = max(1, line - 6), min(len(lines), line + 6)
            code_text = '\n'.join(lines[start - 1:end])
            if len(code_text) > criterion_budget:
                start, end = line, line
                code_text = lines[line - 1]
            if spent + len(code_text) > criterion_budget or budget + len(code_text) > MAX_TOTAL:
                continue
            evidence.append({'id': f'E{len(evidence) + 1}', 'file': context.aliases[name],
                             'start': start, 'end': end, 'code': code_text, 'path': name})
            spans.append((name, start, end))
            budget += len(code_text)
            spent += len(code_text)
        covered = sum(any(n == name and start <= line <= end for n, start, end in spans)
                      for name, line in matches)
        prepared[criterion['framework'] + ':' + criterion['code']] = {
            'state': 'pending' if evidence else 'skipped',
            'outcome': 'unassessed', 'reason': '관련 코드 발췌 검토 대기' if evidence else '전송 가능한 관련 코드 문맥 없음 · 기능 부재나 안전을 뜻하지 않습니다.',
            'feature': 'signals' if matches else 'unknown',
            'dynamic': 'not_run', 'evidence': [], 'candidates': [],
            'matched_locations': len(matches), 'omitted_locations': len(matches) - covered,
            'source_files': len(sources), 'unavailable_files': len(files) - len(sources),
            'packet': evidence,
        }
    return prepared


def public_assessments(prepared):
    return {key: {k: v for k, v in row.items() if k != 'packet'} for key, row in prepared.items()}


def select_findings(findings, maximum=30):
    """Give each reference category a slot before filling by original priority."""
    from .criteria import finding_codes
    selected, covered = [], set()
    for finding in findings:
        codes = finding_codes(finding)
        keys = {(framework, code) for framework, values in codes.items() for code in values}
        if keys - covered and len(selected) < maximum:
            selected.append(finding)
            covered.update(keys)
    selected_ids = {f.id for f in selected}
    selected.extend(f for f in findings if f.id not in selected_ids)
    return selected[:maximum]
