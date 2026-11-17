"""진단 엔진과 대시보드가 공유하는 데이터 모델."""

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import StrEnum


class Severity(StrEnum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class Confidence(StrEnum):
    CONFIRMED = "Confirmed"
    LIKELY = "Likely"
    POTENTIAL = "Potential"


class Status(StrEnum):
    OPEN = "open"
    FIXED = "fixed"
    DISMISSED = "dismissed"


class Change(StrEnum):
    NEW = "new"
    EXISTING = "existing"
    FIXED = "fixed"


class ScanType(StrEnum):
    FULL = "full"
    DIFF = "diff"


class Trigger(StrEnum):
    MANUAL = "manual"
    GIT_HOOK = "git-hook"
    WATCHER = "watcher"


@dataclass
class Location:
    file: str | None = None
    line: int | None = None
    endpoint: str | None = None


@dataclass
class Finding:
    id: str
    title: str
    cwe: str
    owasp: str
    severity: Severity
    confidence: Confidence
    location: Location
    evidence: str
    how_found: list[str]
    impact_ko: str
    remediation_ko: str
    fix_diff: str
    status: Status = Status.OPEN
    change: Change | None = None
    introduced_in: str | None = None


@dataclass
class Target:
    source: str
    url: str | None = None


@dataclass
class AppProfile:
    framework: str | None
    routes: int
    auth: str | None


@dataclass
class ScanResult:
    scan_id: str
    app_name: str
    scanned_at: datetime
    target: Target
    risk_score: int
    profile: AppProfile
    findings: list[Finding]
    report_md: str

    branch: str | None = None
    commit: str | None = None
    baseline_commit: str | None = None
    scan_type: ScanType = ScanType.FULL
    trigger: Trigger = Trigger.MANUAL

    @classmethod
    def from_json(cls, raw: str):
        data = json.loads(raw)
        repo = data.get("repo", {})
        target = data.get("target") or {"source": repo["path"]}
        findings = []
        for item in data["findings"]:
            fields = dict(item)
            fields.update(
                location=Location(**item["location"]),
                severity=Severity(item["severity"]),
                confidence=Confidence(item["confidence"]),
                status=Status(item.get("status", "open")),
                change=Change(item["change"]) if item.get("change") is not None else None,
            )
            findings.append(Finding(**fields))
        return cls(
            scan_id=data["scan_id"], app_name=repo["name"] if repo else data["app_name"],
            scanned_at=datetime.fromisoformat(data["scanned_at"]), target=Target(**target),
            risk_score=data["risk_score"], profile=AppProfile(**data["profile"]),
            findings=findings, report_md=data["report_md"], branch=repo.get("branch"),
            commit=data.get("commit"), baseline_commit=data.get("baseline_commit"),
            scan_type=ScanType(data.get("scan_type", "full")),
            trigger=Trigger(data.get("trigger", "manual")),
        )

    def to_dict(self) -> dict:
        if self.scanned_at.utcoffset() is None:
            raise ValueError("scanned_at에는 시간대가 필요합니다.")
        if not 0 <= self.risk_score <= 100:
            raise ValueError("risk_score는 0~100 범위여야 합니다.")

        if self.scan_type == ScanType.DIFF and not (self.commit and self.baseline_commit):
            raise ValueError("변경분 스캔에는 대상 커밋과 기준 커밋이 필요합니다.")
        if self.scan_type == ScanType.FULL and self.baseline_commit is not None:
            raise ValueError("기준 커밋은 변경분 스캔에만 지정합니다.")

        summary = {severity.value: 0 for severity in Severity}
        delta = {"new": 0, "fixed": 0}
        for finding in self.findings:
            if finding.change != Change.FIXED:
                summary[finding.severity] += 1
            if finding.change in delta:
                delta[finding.change] += 1

        data = asdict(self)
        data["repo"] = {"name": self.app_name, "path": self.target.source, "branch": data.pop("branch")}
        data["delta"] = delta
        data["scanned_at"] = self.scanned_at.isoformat()
        data["mode"] = "graybox" if self.target.url else "source-only"
        data["summary"] = summary
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)
