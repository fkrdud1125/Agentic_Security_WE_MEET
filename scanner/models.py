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

    def to_json(self) -> str:
        if self.scanned_at.utcoffset() is None:
            raise ValueError("scanned_at에는 시간대가 필요합니다.")
        if not 0 <= self.risk_score <= 100:
            raise ValueError("risk_score는 0~100 범위여야 합니다.")

        summary = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            summary[finding.severity] += 1

        data = asdict(self)
        data["scanned_at"] = self.scanned_at.isoformat()
        data["mode"] = "graybox" if self.target.url else "source-only"
        data["summary"] = summary
        return json.dumps(data, ensure_ascii=False, indent=2)
