"""VibeScan manual full-scan and local-login entry points."""

import argparse
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

import requests

from scanner.history import compare, evidence_files, list_scans, save_scan
from scanner.context import Context
from scanner.ingest import git, snapshot, languages
from scanner.kisa import checklist, legacy_coverage
from scanner.criteria import build_criteria, finding_codes
from scanner.models import Change, ScanResult, Severity, Status, Target, Trigger
from scanner.static import inspect, profile
from . import analysis, inference
from .register import data_dir
from .session import SessionError, access_token

MANUAL = ["인증·인가 정책 확인", "응답 헤더·쿠키 확인"]


def render_criteria(criteria):
    execution = {"pending": "대기", "running": "검사 중", "completed": "정적 범위 완료",
                 "partial": "부분 점검", "manual": "추가 확인 필요", "unknown": "실행 기록 없음", "failed": "검사 중단"}
    outcomes = {"candidate": "취약 후보", "no_findings": "점검 범위 내 미발견", "unassessed": "판정 보류"}
    ai_states = {"pending": "대기", "running": "검토 중", "completed": "검토 완료", "partial": "일부 검토",
                 "skipped": "미수행", "failed": "검토 실패", "unknown": "기록 없음", "not_applicable": "검토 대상 없음"}
    def cell(value):
        return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")
    rows = ["## 기준별 점검 현황", "",
            "OWASP Top 10 2025 10개 + 주통기 웹 21개 = 총 31개 분류 항목입니다. AI 호출 횟수나 개별 검사 횟수가 아닙니다.",
            "같은 발견이 두 기준에 연결될 수 있으므로 항목별 발견 수를 합산하지 않습니다. 기준 간 연결은 프로젝트의 분류이며 공식 일대일 대응표가 아닙니다.",
            "정적 범위 완료·미발견은 적용한 규칙에 한정됩니다. 실행 환경·업무 정책을 포함한 전체 기준의 충족이나 안전을 뜻하지 않습니다.", ""]
    for framework, title in (("owasp", "OWASP Top 10 2025 · 10개"), ("kisa", "주통기 웹 취약점 · 21개")):
        checks = [c for c in criteria if c["framework"] == framework]
        rows.extend(["### " + title, "", "| 코드 · 항목 | 검사 상태 | 발견 결과 · 근거 ID | AI 검토 | 범위·남은 확인 |",
                     "| --- | --- | --- | --- | --- |"])
        for c in checks:
            ai = c["ai"]
            ai_text = (f"기준별 기록 없음 · 연결된 발견 {ai['total']}건" if ai["state"] == "unknown" else
                       f"{ai_states.get(ai['state'], '기록 없음')} {ai['reviewed']}/{ai['total']}건")
            ids = ", ".join(c["findings"]) or "없음"
            if c.get("dismissed"):
                ids += " / 오탐 후보: " + ", ".join(c["dismissed"])
            values = [f"{c['code']} · {c['name']}", execution.get(c["execution"], "실행 기록 없음"),
                      f"{outcomes.get(c['outcome'], '판정 보류')} · {ids}",
                      ai_text,
                      c["reason"]]
            rows.append("| " + " | ".join(cell(v) for v in values) + " |")
        rows.append("")
    rows.extend(["출처: [OWASP Top 10 2025](https://top10.owasp.org/2025/) · OWASP Top 10 Team, CC BY 3.0, 한국어명은 프로젝트 번역.",
                 "주통기 목록: 사용자 제공 2026 주요정보통신기반시설 상세가이드, 웹 애플리케이션 장의 21항목. 판단 설명과 자동 검사 범위는 프로젝트의 요약입니다.", ""])
    return "\n".join(rows)


def render(result):
    fixed = [f for f in result.findings if f.change == Change.FIXED]
    opened = [f for f in result.findings if f.status == Status.OPEN and f.change != Change.FIXED]
    dismissed = [f for f in result.findings if f.status == Status.DISMISSED and f.change != Change.FIXED]
    rows = [f"# 보안 진단 보고서 — {result.app_name}", "",
            f"- 커밋: `{result.commit}`", f"- 진단 일시: {result.scanned_at.isoformat()}",
            f"- 위험 점수: {result.risk_score}/100 · 검토 대상 {len(opened)}건 · 오탐 후보 {len(dismissed)}건",
            "- 진단 범위: 수집한 소스의 정적 패턴 및 시크릿 검사",
            f"- 앱 프로파일: {result.profile.framework or '프레임워크 미확인'} · "
            f"라우트 데코레이터 {result.profile.routes}개 · {result.profile.auth or '인증 방식 미확인'}",
            f"- AI 2차 검토: {result.analysis_note}",
            f"- 직전 스캔 대비: 새로 생김 {sum(f.change == Change.NEW for f in result.findings)}건 · 해결 {len(fixed)}건 "
            f"(기준 커밋 `{result.baseline_commit}`)" if result.baseline_commit else "- 직전 스캔 대비: 비교할 이전 결과 없음", "",
            "## 코드 구조 분석", result.profile.analysis_ko or "로컬 구조 분석만 수행했습니다."]
    rows.extend(f"- {p['file']}:{p['line']} · {p['kind']}: {p['note']}" for p in result.profile.surfaces)
    rows.extend("- " + s for s in result.profile.limitations)
    rows.extend(["", render_criteria(result.criteria or build_criteria(result.kisa_checklist, result.findings)),
                 "", "## 검사 엔진별 범위 (참고)"])
    for check in result.coverage:
        mode = {"completed": "정적 검사 완료", "unsupported": "지원 Python 소스 없음 · 미검사",
                "manual": "수동 확인 필요 · 미검사", "partial": "부분 점검 · 수동 확인 포함"}[check["execution"]]
        rows.append(f"- {check['name']} [{mode}]: {check['reason']}")
    rows.extend(["", "## 발견 및 수정 방법"])
    for f in sorted(opened, key=lambda item: list(Severity).index(item.severity)):
        codes = finding_codes(f)
        rows.extend(["", f"### {f.id} · {f.severity} · {f.title}", "",
                     f"- 위치: `{f.location.file}:{f.location.line}`",
                     f"- 탐지 방식: {', '.join(f.how_found)}",
                     f"- 분류: {f.cwe} · {f.confidence}",
                     f"- 주통기: {', '.join(codes['kisa']) or '매핑 없음'} · OWASP 2025: {', '.join(codes['owasp']) or '매핑 없음'}",
                     f"- 판정 근거: {f.triage_reason or '로컬 규칙 탐지 · 모델 검토 없음'}",
                     f"- 최초 규칙 심각도: {f.original_severity or f.severity}",
                     f"- 영향: {f.impact_ko}", f"- 수정 방법: {f.remediation_ko}",
                     "", "근거 코드:", "", "```", f.evidence, "```",
                     "", f.fix_note, "", "```diff", f.fix_diff, "```"])
        if f.rule_id == 'vs-java-sql-flow' and f.trace:
            rows.append("호출 경로: " + " → ".join(f"{p['file']}:{p['line']} ({p['method']})" for p in f.trace))
        if f.rule_id == 'vs-java-admin-policy' and f.trace:
            rows.append(f"필터 체인 설정: {f.trace[0]['file']}:{f.trace[0]['line']}")
    if not opened:
        rows.append("적용한 규칙에서 발견된 항목이 없습니다.")
        if dismissed:
            rows[-1] = "모델이 모든 발견을 오탐 후보로 분류했습니다. 아래 근거를 직접 확인하세요."
    if dismissed:
        rows.extend(["", "## 오탐 후보 — 원래 발견을 보존하며 개발자 확인 필요"])
        for f in dismissed:
            rows.extend([f"- {f.id} · {f.title} · {f.location.file}:{f.location.line}",
                         f"  최초 심각도: {f.original_severity} · 근거: {f.triage_reason}"])
    if fixed:
        rows.extend(["", "## 직전 스캔 이후 해결됨"])
        rows.extend(f"- {f.title} · {f.location.file}:{f.location.line}" for f in fixed)
    java_routes = [r for r in result.routes if 'policy_source' in r]
    if java_routes:
        rows.extend(["", "## Spring MVC 경로별 정적 인가 단서"])
        rows.extend(f"- {r['method']} `{r['path']}` · {r['auth_guard']} · {r['file']}:{r['line']}" for r in java_routes)
    rows.extend(["", "## 추가 확인", *["- " + s for s in MANUAL],
                 "- 외부 입력 도달 여부와 제시한 수정 예시는 실제 호출 문맥에서 검토하세요."])
    rows.extend(["", "## 점검 한계", *['- ' + x for x in result.profile.limitations],
                 '- 부분 실패 파일: ' + (', '.join(result.partial_files) or '없음'),
                 '- 규칙팩: ' + result.engine.get('rulepack', '미기록'),
                 '- 점수: 열린 발견의 Critical 40 / High 20 / Medium 10 / Low 3 합계, 최대 100 (기존 방식).'])
    return "\n".join(rows) + "\n"


def baseline(database, repo, output, branch, commit):
    """Use the latest available scan on this branch that HEAD actually descends from."""
    if not database.is_file():
        return None
    for row in list_scans(database, str(repo)):
        if row["branch"] != branch or not row["commit_sha"]:
            continue
        try:
            if row["commit_sha"] != commit:
                git(repo, "merge-base", "--is-ancestor", row["commit_sha"], commit)
            result = ScanResult.from_json((output / row["scan_id"] / "scan_result.json").read_text(encoding="utf-8"))
            if result.branch == branch and result.commit == row["commit_sha"]:
                return result
        except (OSError, ValueError, KeyError, TypeError):
            continue  # moved or damaged result: fall back to an older one, its commit is recorded as the baseline
    return None


class ScanInputError(ValueError):
    """A scan the user can fix; its message is safe to show in the dashboard."""


# Languages whose files are collected but have no vulnerability rules: only credential checks run on them.
UNSUPPORTED = {"php": "PHP", "rb": "Ruby", "go": "Go", "kt": "Kotlin"}
STAGES = ["코드 수집", "구조 분석", "정적 검사", "AI 2차 검토", "결과·보고서 저장"]


def scan(repo, output, directory, offline=False, trigger=Trigger.MANUAL, progress=lambda stage, text: None,
         new_high_only=False, folder_source=None, criteria_progress=lambda rows: None):
    """progress(stage, text) reports STAGES[stage] and one log line; text never carries source code.

    Static inspection always precedes optional AI review; no model planning call is made.
    new_high_only (background scans with consent): review only findings that are
    new since the previous scan and High or above, to spare the user's ChatGPT quota.
    """
    repo = repo.expanduser().resolve()
    output = output.expanduser().resolve()
    if output.is_relative_to(repo) or directory.resolve().is_relative_to(repo):
        raise ScanInputError("결과와 이력은 검사 대상 저장소 밖에 저장해야 합니다.")
    scan_id = uuid.uuid4().hex
    coverage = analysis.default_coverage()
    note = "로컬 정적 검사 · AI 미사용 (오프라인)"
    issue = None  # first model problem, so the dashboard can point to its fix
    active = None
    review_states = {}
    criteria_progress(build_criteria(phase="pending"))
    progress(0, "검사할 파일을 임시 폴더에 수집하는 중")
    with tempfile.TemporaryDirectory() as temp:
        source = Path(temp)
        commit, branch, files = snapshot(repo, source, folder_source=folder_source)
        progress(0, f"파일 {len(files)}개 수집 · 커밋 {commit[:12]}")
        previous = baseline(directory / "scan-history.sqlite3", repo, output, branch, commit)
        exclusions = getattr(files, 'excluded', set())
        excluded_previous = {name for f in previous.findings if f.change != Change.FIXED
                             for name in evidence_files(f) if name and
                             any(p.as_posix() in exclusions for p in (Path(name), *Path(name).parents))} if previous else set()
        if not (files or getattr(files, 'sensitive_files', []) or getattr(files, 'skipped', []) or excluded_previous):
            raise ScanInputError("제외 규칙 적용 후 검사 가능한 텍스트 파일이 없습니다.")
        app = profile(source, files)
        progress(1, f"구조 분석 완료 · {app.framework or '프레임워크 미확인'} · 라우트 {app.routes}개")
        context = Context(source, files)
        app.limitations = ["언어별로 지원하는 정적 규칙을 적용합니다. 실행 중 동작은 수동 확인 대상입니다."]
        app.limitations.extend([
            "AI 2차 검토는 정적 검사에서 발견한 후보와 관련 코드를 검토합니다. 미탐 여부나 실제 악용 가능성을 보증하지 않습니다.",
            "AI 검토는 마스킹 후 문맥을 추출할 수 있는 Python 발견사항만 지원하며, 심각도순 최대 30건을 5건씩 검토합니다.",
        ])
        counts = languages(files)
        if counts.get("java"):
            app.limitations.append("Java는 JDBC SQL 호출 경로와 Spring MVC 관리자 경로의 명시적 인가 정책을 점검합니다. 동적 호출·복잡한 조건·운영 권한은 수동 확인 대상입니다.")
        others = {UNSUPPORTED[k]: n for k, n in counts.items() if k in UNSUPPORTED}
        mostly_unsupported = sum(others.values()) > sum(counts.get(k, 0) for k in ("python", "javascript", "typescript", "java"))
        if others:
            names = ", ".join(f"{label} {n}개" for label, n in others.items())
            app.limitations.insert(0, f"탐지 규칙이 없는 언어의 파일({names})은 인증정보 노출만 확인했고 다른 취약점은 검사하지 않았습니다.")
        progress(2, "정적 규칙·시크릿·설정 검사 중")
        criteria_progress(build_criteria(phase="running"))
        findings = inspect(source, files)
        if any('policy_source' in route for route in getattr(findings, 'routes', [])):
            app.framework = ', '.join(filter(None, [app.framework, 'Spring MVC']))
        progress(2, f"발견 후보 {len(findings)}건")
        findings.sort(key=lambda f: (list(Severity).index(f.severity), f.confidence != "Likely", f.id))
        partial = sorted(set(getattr(findings, 'partial_files', [])) | excluded_previous)
        # Compare before the model review, so a background scan can send only what this commit introduced.
        progress(2, "직전 스캔과 비교하는 중")
        matched = compare(findings, previous, commit, partial, getattr(findings, 'credential_files', ())) if previous else None
        kept, gone = matched or ([], [])
        targets = [f for f in findings if not new_high_only or
                   (f.change == Change.NEW and f.severity in (Severity.CRITICAL, Severity.HIGH))]
        reviewable = [f for f in targets
                      if context.excerpt(f.location.file, f.location.line) is not None]
        review_states = {f.id: "skipped" for f in findings}
        if not offline:
            review_states.update({f.id: "pending" for f in reviewable[:30]})
        def publish_criteria():
            # Carry-over IDs are renumbered at save time; don't mix them with this run's IDs here.
            criteria_progress(build_criteria(checklist(findings, counts, partial), findings,
                                             review_states=review_states))
        publish_criteria()
        count = 0
        if not offline:
            if not targets:
                note = "로컬 정적 검사 · AI 검토 생략 (검토 대상 없음)"
                if new_high_only:
                    note += " · 새 High 이상만 검토"
            elif not reviewable:
                note = "로컬 정적 검사 · AI 검토 불가 (지원하는 Python 코드 문맥 없음)"
            else:
                progress(3, "정적 검사 완료 · AI 2차 검토 연결 중")
                try:
                    token = access_token(directory)
                    active = token, inference.model_for(token)
                    note = "로컬 정적 검사"
                except SessionError as exc:
                    note, issue = f"로컬 정적 검사 · AI 연결 실패 ({exc})", exc.kind
                except (OSError, ValueError, KeyError, TypeError, sqlite3.Error, requests.RequestException):
                    note, issue = "로컬 정적 검사 · AI 연결 실패 · 정적 결과 유지", "error"
        if active:
            for start in range(0, min(len(reviewable), 30), 5):
                batch = reviewable[start:start + 5]
                review_states.update({f.id: "running" for f in batch})
                publish_criteria()
                progress(3, f"AI 2차 검토 중 {count}/{len(targets)}건")
                try:
                    count += analysis.review(context, batch, *active)
                    review_states.update({f.id: "completed" for f in batch})
                except SessionError as exc:
                    review_states.update({f.id: "failed" for f in batch})
                    note += f" · AI 검토 중단 ({exc}) · 미검토 항목은 로컬 판정 유지"
                    issue = exc.kind
                    break
                except (ValueError, KeyError, TypeError, requests.RequestException):
                    review_states.update({f.id: "failed" for f in batch})
                    note += " · 모델 검토 확인 실패 · 남은 항목은 로컬 수정안 사용"
                    issue = "error"
                    break
                publish_criteria()
            note += f" · AI 2차 검토 {count}/{len(targets)}건" + (" (새 High 이상만)" if new_high_only else "")
            if len(reviewable) < len(targets):
                note += " · 모델용 소스 문맥이 없는 항목은 로컬 판정 유지"
            if len(reviewable) > 30:
                note += " · 모델 검토 상한 30건, 나머지는 로컬 규칙 결과"
        review_states = {fid: ("failed" if issue else "skipped") if state in ("pending", "running") else state
                         for fid, state in review_states.items()}
        publish_criteria()
        progress(3, note)

    weights = {Severity.CRITICAL: 40, Severity.HIGH: 20, Severity.MEDIUM: 10,
               Severity.LOW: 3, Severity.INFO: 0}
    if mostly_unsupported:
        note += f" · 주 언어({', '.join(others)})의 탐지 규칙이 없어 결과가 불완전합니다"
    progress(4, "보고서 저장 중")
    current = list(findings) + kept
    for number, f in enumerate(kept + gone, len(findings) + 1):
        f.id = f"F-{number:03}"
    kisa_rows = checklist(findings, languages(files), partial, carried=kept)
    coverage = legacy_coverage(coverage, kisa_rows)
    app.routes = len(getattr(findings, 'routes', [])) or app.routes
    result = ScanResult(scan_id, repo.name, datetime.now(timezone.utc), Target(str(repo)),
                        min(100, sum(weights[f.severity] for f in current if f.status == Status.OPEN)), app, current + gone, "",
                        branch=branch, commit=commit, baseline_commit=previous.commit if matched else None, trigger=trigger,
                        checklist=[c['name'] for c in coverage],
                        analysis_note=note, coverage=coverage,
                        engine={'version': '0.2.0', 'rulepack': 'vibescan-2026.11.4', 'semgrep': '1.185.0'},
                        languages=languages(files), partial_files=partial,
                        sensitive_files=getattr(files, 'sensitive_files', []), routes=getattr(findings, 'routes', []),
                        config_summary=getattr(findings, 'config_summary', []), kisa_checklist=kisa_rows,
                        criteria=build_criteria(kisa_rows, current + gone, review_states=review_states))
    criteria_progress(result.criteria)
    result.report_md = render(result)
    output.mkdir(parents=True, exist_ok=True)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    final = output / scan_id
    with tempfile.TemporaryDirectory(dir=output) as staging:
        ready = Path(staging) / "result"
        ready.mkdir()
        (ready / "scan_result.json").write_text(result.to_json(), encoding="utf-8")
        (ready / "report.md").write_text(result.report_md, encoding="utf-8")
        os.rename(ready, final)
    try:
        save_scan(directory / "scan-history.sqlite3", result)
    except Exception:
        shutil.rmtree(final)
        raise
    return final, note, issue


def main():
    if sys.platform == "win32":
        for stream in (sys.stdout, sys.stderr):
            if not stream.isatty() and hasattr(stream, "reconfigure"):
                stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(prog="vibescan")
    commands = parser.add_subparsers(dest="command")
    dashboard = commands.add_parser("dashboard", help="저장된 진단 결과를 로컬 대시보드에서 확인")
    dashboard.add_argument("--results", type=Path, help="scan --output으로 지정한 결과 상위 폴더")
    commands.add_parser("login", help="ChatGPT 로컬 로그인")
    run = commands.add_parser("scan", help="로컬 Git 저장소 전체 검사")
    run.add_argument("repo", type=Path)
    run.add_argument("--offline", action="store_true", help="로컬 규칙만 사용")
    run.add_argument("--output", type=Path, help="실행별 결과 폴더의 상위 경로")
    hook = commands.add_parser("hook-trigger", help="git post-commit hook이 호출하는 백그라운드 검사")
    hook.add_argument("commit")
    args = parser.parse_args()
    try:
        directory = data_dir()
        if args.command in (None, "dashboard"):
            from .dashboard import serve
            serve(getattr(args, "results", None) or directory / "scans")
        elif args.command == "hook-trigger":
            from .hook import trigger
            trigger(Path.cwd(), args.commit, directory)
        elif args.command == "login":
            from .login import login
            print(login(directory))
        else:
            folder, note, _ = scan(args.repo, args.output or directory / "scans", directory, args.offline)
            print(f"{folder}\n{note}")
    except (ValueError, RuntimeError, OSError, sqlite3.Error, subprocess.TimeoutExpired) as exc:
        parser.exit(1, f"VibeScan: {exc}\n")
