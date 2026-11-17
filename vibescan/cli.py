"""VibeScan manual full-scan and local-login entry points."""

import argparse
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import uuid
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

import requests

from scanner.history import save_scan
from scanner.ingest import snapshot
from scanner.models import Confidence, ScanResult, Severity, Target
from scanner.static import inspect, profile
from . import inference
from .register import data_dir
from .session import SessionError, access_token

CHECKS = ["하드코딩 시크릿", "SQL 문자열 결합", "HTML 이스케이프 생략"]
MANUAL = ["인증·인가 정책 확인", "응답 헤더·쿠키 확인"]


def render(result):
    rows = [f"# 보안 진단 보고서 — {result.app_name}", "",
            f"- 커밋: `{result.commit}`", f"- 진단 일시: {result.scanned_at.isoformat()}",
            f"- 위험 점수: {result.risk_score}/100 · 발견 {len(result.findings)}건",
            f"- 진단 범위: 커밋된 소스의 정적 패턴 및 시크릿 검사",
            f"- 앱 프로파일: {result.profile.framework or '프레임워크 미확인'} · "
            f"라우트 데코레이터 {result.profile.routes}개 · {result.profile.auth or '인증 방식 미확인'}",
            f"- 모델 분석: {result.analysis_note}", "",
            "## 점검 목록", *["- " + s for s in result.checklist], "",
            "## 발견 및 수정 방법"]
    for f in sorted(result.findings, key=lambda item: list(Severity).index(item.severity)):
        rows.extend(["", f"### {f.id} · {f.severity} · {f.title}", "",
                     f"- 위치: `{f.location.file}:{f.location.line}`",
                     f"- 근거: `{f.evidence}` ({', '.join(f.how_found)})",
                     f"- 분류: {f.cwe} · {f.owasp} · {f.confidence}",
                     f"- 영향: {f.impact_ko}", f"- 수정 방법: {f.remediation_ko}",
                     "", "수정 예시", "", "```diff", f.fix_diff, "```"])
    if not result.findings:
        rows.append("적용한 규칙에서 발견된 항목이 없습니다.")
    rows.extend(["", "## 추가 확인", *["- " + s for s in MANUAL],
                 "- 외부 입력 도달 여부와 제시한 수정 예시는 실제 호출 문맥에서 검토하세요."])
    return "\n".join(rows) + "\n"


def review(findings, token, model):
    selected = sorted(findings, key=lambda f: list(Severity).index(f.severity))[:30]
    data = [{"id": f.id, "type": f.title, "evidence": f.evidence,
             "severity": f.severity.value} for f in selected]
    answer = inference.ask(token, model, "각 발견의 영향과 수정 방법을 한국어로 작성하라. "
                           "reviews 배열의 각 객체는 id, impact, fix, confidence(Likely/Potential)를 갖는다. "
                           "실제 입력 경로를 알 수 없으므로 단정하지 마라.", data)
    allowed = {f.id: f for f in selected}
    validated = {}
    for item in answer["reviews"]:
        fid = item["id"]
        if fid not in allowed or fid in validated or item["confidence"] not in ("Likely", "Potential"):
            raise ValueError("invalid review")
        if not all(isinstance(item[k], str) and 0 < len(item[k].strip()) <= 1200 for k in ("impact", "fix")):
            raise ValueError("invalid explanation")
        validated[fid] = item
    if set(validated) != set(allowed):
        raise ValueError("incomplete review")
    for fid, item in validated.items():
        f = allowed[fid]
        f.impact_ko, f.remediation_ko = item["impact"], item["fix"]
        f.confidence = Confidence(item["confidence"])
    return len(selected)


def scan(repo, output, directory, offline=False):
    repo = repo.expanduser().resolve()
    output = output.expanduser().resolve()
    if output.is_relative_to(repo) or directory.resolve().is_relative_to(repo):
        raise ValueError("결과와 이력은 검사 대상 저장소 밖에 저장해야 합니다.")
    scan_id = uuid.uuid4().hex
    checklist = CHECKS.copy()
    note = "로컬 규칙으로 작성"
    active = None
    with tempfile.TemporaryDirectory() as temp:
        source = Path(temp)
        commit, branch, files = snapshot(repo, source)
        app = profile(source, files)
        if not offline:
            try:
                token = access_token(directory)
                model = inference.model_for(token)
                facts = {"profile": asdict(app), "file_types": dict(Counter(Path(p).suffix for p in files)),
                         "layout": [{"depth": len(Path(p).parts), "ext": Path(p).suffix} for p in files[:80]],
                         "checks": CHECKS}
                answer = inference.ask(token, model, "프로파일을 보고 checks 세 항목을 권장 점검 순으로 정렬하고 "
                                       "원래 이름 그대로 checks 배열로 반환하라. profile_note에는 확인된 프레임워크, "
                                       "라우트 수와 인증 방식의 확인 한계를 한국어 한 문장으로 요약하라.", facts)
                ordered = answer["checks"]
                if not isinstance(ordered, list) or sorted(ordered) != sorted(CHECKS):
                    raise ValueError("invalid plan")
                summary = answer.get("profile_note", "")
                if not isinstance(summary, str) or len(summary) > 400:
                    raise ValueError("invalid profile")
                checklist = ordered
                active = token, model
                note = "모델 점검 계획 적용" + (" · " + summary.strip() if summary.strip() else "")
            except SessionError as exc:
                note = f"로컬 규칙으로 작성 · {exc}"
            except (OSError, ValueError, KeyError, TypeError, sqlite3.Error, requests.RequestException):
                note = "모델 연결 또는 응답 확인 실패 · 로컬 규칙으로 작성"
        findings = inspect(source, files)
        priority = dict(zip(('CWE-798', 'CWE-89', 'CWE-79'), CHECKS))
        findings.sort(key=lambda f: checklist.index(priority[f.cwe]))
        if active and findings:
            try:
                count = review(findings, *active)
                note += f" · 한국어 상세 검토 {count}/{len(findings)}건"
            except SessionError as exc:
                note += f" · 상세 검토는 로컬 수정안 사용 ({exc})"
            except (ValueError, KeyError, TypeError, requests.RequestException):
                note += " · 상세 검토는 로컬 수정안 사용"

    weights = {Severity.CRITICAL: 40, Severity.HIGH: 20, Severity.MEDIUM: 10,
               Severity.LOW: 3, Severity.INFO: 0}
    result = ScanResult(scan_id, repo.name, datetime.now(timezone.utc), Target(str(repo)),
                        min(100, sum(weights[f.severity] for f in findings)), app, findings, "",
                        branch=branch, commit=commit, checklist=checklist, analysis_note=note)
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
    return final, note


def main():
    if sys.platform == "win32":
        for stream in (sys.stdout, sys.stderr):
            if not stream.isatty() and hasattr(stream, "reconfigure"):
                stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(prog="vibescan")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("login", help="ChatGPT 로컬 로그인")
    run = commands.add_parser("scan", help="로컬 Git 저장소 전체 검사")
    run.add_argument("repo", type=Path)
    run.add_argument("--offline", action="store_true", help="로컬 규칙만 사용")
    run.add_argument("--output", type=Path, help="실행별 결과 폴더의 상위 경로")
    args = parser.parse_args()
    try:
        directory = data_dir()
        if args.command == "login":
            from .login import login
            print(login(directory))
        else:
            folder, note = scan(args.repo, args.output or directory / "scans", directory, args.offline)
            print(f"{folder}\n{note}")
    except (ValueError, RuntimeError, OSError, sqlite3.Error, subprocess.TimeoutExpired) as exc:
        parser.exit(1, f"VibeScan: {exc}\n")
