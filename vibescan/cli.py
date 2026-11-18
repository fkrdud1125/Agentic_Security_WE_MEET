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

from scanner.history import save_scan
from scanner.context import Context
from scanner.ingest import snapshot
from scanner.models import ScanResult, Severity, Status, Target
from scanner.static import inspect, profile
from . import analysis, inference
from .register import data_dir
from .session import SessionError, access_token

MANUAL = ["인증·인가 정책 확인", "응답 헤더·쿠키 확인"]


def render(result):
    opened = [f for f in result.findings if f.status == Status.OPEN]
    dismissed = [f for f in result.findings if f.status == Status.DISMISSED]
    rows = [f"# 보안 진단 보고서 — {result.app_name}", "",
            f"- 커밋: `{result.commit}`", f"- 진단 일시: {result.scanned_at.isoformat()}",
            f"- 위험 점수: {result.risk_score}/100 · 검토 대상 {len(opened)}건 · 오탐 후보 {len(dismissed)}건",
            f"- 진단 범위: 커밋된 소스의 정적 패턴 및 시크릿 검사",
            f"- 앱 프로파일: {result.profile.framework or '프레임워크 미확인'} · "
            f"라우트 데코레이터 {result.profile.routes}개 · {result.profile.auth or '인증 방식 미확인'}",
            f"- 모델 분석: {result.analysis_note}", "",
            "## 정찰 결과", result.profile.analysis_ko or "로컬 구조 분석만 수행했습니다."]
    rows.extend(f"- {p['file']}:{p['line']} · {p['kind']}: {p['note']}" for p in result.profile.surfaces)
    rows.extend("- " + s for s in result.profile.limitations)
    rows.extend(["", "## 점검 계획과 범위"])
    for check in result.coverage:
        mode = {"completed": "정적 검사 완료", "unsupported": "지원 Python 소스 없음 · 미검사",
                "manual": "수동 확인 필요 · 미검사"}[check["execution"]]
        rows.append(f"- {check['name']} [{mode}]: {check['reason']}")
    rows.extend(["", "## 발견 및 수정 방법"])
    for f in sorted(opened, key=lambda item: list(Severity).index(item.severity)):
        rows.extend(["", f"### {f.id} · {f.severity} · {f.title}", "",
                     f"- 위치: `{f.location.file}:{f.location.line}`",
                     f"- 근거: `{f.evidence}` ({', '.join(f.how_found)})",
                     f"- 분류: {f.cwe} · {f.owasp} · {f.confidence}",
                     f"- 판정 근거: {f.triage_reason or '로컬 규칙 탐지 · 모델 검토 없음'}",
                     f"- 최초 규칙 심각도: {f.original_severity or f.severity}",
                     f"- 영향: {f.impact_ko}", f"- 수정 방법: {f.remediation_ko}",
                     "", f.fix_note, "", "```diff", f.fix_diff, "```"])
    if not opened:
        rows.append("적용한 규칙에서 발견된 항목이 없습니다.")
        if dismissed:
            rows[-1] = "모델이 모든 발견을 오탐 후보로 분류했습니다. 아래 근거를 직접 확인하세요."
    if dismissed:
        rows.extend(["", "## 오탐 후보 — 원래 발견을 보존하며 개발자 확인 필요"])
        for f in dismissed:
            rows.extend([f"- {f.id} · {f.title} · {f.location.file}:{f.location.line}",
                         f"  최초 심각도: {f.original_severity} · 근거: {f.triage_reason}"])
    rows.extend(["", "## 추가 확인", *["- " + s for s in MANUAL],
                 "- 외부 입력 도달 여부와 제시한 수정 예시는 실제 호출 문맥에서 검토하세요."])
    return "\n".join(rows) + "\n"


class ScanInputError(ValueError):
    """A scan the user can fix; its message is safe to show in the dashboard."""


def scan(repo, output, directory, offline=False):
    repo = repo.expanduser().resolve()
    output = output.expanduser().resolve()
    if output.is_relative_to(repo) or directory.resolve().is_relative_to(repo):
        raise ScanInputError("결과와 이력은 검사 대상 저장소 밖에 저장해야 합니다.")
    scan_id = uuid.uuid4().hex
    coverage = analysis.default_coverage()
    note = "로컬 규칙으로 작성"
    issue = None  # first model problem, so the dashboard can point to its fix
    active = None
    with tempfile.TemporaryDirectory() as temp:
        source = Path(temp)
        commit, branch, files = snapshot(repo, source)
        if not files:
            raise ScanInputError("제외 규칙 적용 후 검사 가능한 텍스트 파일이 없습니다.")
        app = profile(source, files)
        context = Context(source, files)
        app.limitations = ["Python 소스 정찰 및 제한된 정적 규칙 검사입니다. 동적 검사는 수행하지 않았습니다."]
        if not offline:
            try:
                token = access_token(directory)
                model = inference.model_for(token)
                active = token, model
                coverage = analysis.plan(context, app, *active)
                note = "코드 문맥 기반 정찰·점검 계획 적용"
            except SessionError as exc:
                active = None
                note, issue = f"로컬 규칙으로 작성 · {exc}", exc.kind
            except (OSError, ValueError, KeyError, TypeError, sqlite3.Error, requests.RequestException):
                note, issue = "모델 정찰·계획 확인 실패 · 고정 점검 계획 적용", "error"
        findings = inspect(source, files)
        for check in coverage:
            check["execution"] = ("manual" if check["mode"] == "manual" else
                                  "unsupported" if check["id"] in ("sql", "xss") and not context.sources
                                  else "completed")
        priority = {'CWE-798': 'secrets', 'CWE-89': 'sql', 'CWE-79': 'xss'}
        order = [c['id'] for c in coverage]
        findings.sort(key=lambda f: (list(Severity).index(f.severity), order.index(priority[f.cwe])))
        if active and findings:
            count = 0
            for start in range(0, min(len(findings), 30), 5):
                try:
                    count += analysis.review(context, findings[start:start + 5], *active)
                except SessionError as exc:
                    note += f" · 남은 검토는 로컬 수정안 사용 ({exc})"
                    issue = exc.kind
                    break
                except (ValueError, KeyError, TypeError, requests.RequestException):
                    note += " · 모델 검토 확인 실패 · 남은 항목은 로컬 수정안 사용"
                    issue = "error"
                    break
            note += f" · 한국어 상세 검토 {count}/{len(findings)}건"
            if len(findings) > 30:
                note += " · 모델 검토 상한 30건, 나머지는 로컬 규칙 결과"

    weights = {Severity.CRITICAL: 40, Severity.HIGH: 20, Severity.MEDIUM: 10,
               Severity.LOW: 3, Severity.INFO: 0}
    result = ScanResult(scan_id, repo.name, datetime.now(timezone.utc), Target(str(repo)),
                        min(100, sum(weights[f.severity] for f in findings if f.status == Status.OPEN)), app, findings, "",
                        branch=branch, commit=commit, checklist=[c['name'] for c in coverage],
                        analysis_note=note, coverage=coverage)
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
    args = parser.parse_args()
    try:
        directory = data_dir()
        if args.command in (None, "dashboard"):
            from .dashboard import serve
            serve(getattr(args, "results", None) or directory / "scans")
        elif args.command == "login":
            from .login import login
            print(login(directory))
        else:
            folder, note, _ = scan(args.repo, args.output or directory / "scans", directory, args.offline)
            print(f"{folder}\n{note}")
    except (ValueError, RuntimeError, OSError, sqlite3.Error, subprocess.TimeoutExpired) as exc:
        parser.exit(1, f"VibeScan: {exc}\n")
