import json
import unittest
from datetime import datetime, timezone

from scanner.models import (
    AppProfile, Confidence, Finding, Location, ScanResult, Severity, Target,
)


class ScanResultTests(unittest.TestCase):
    def setUp(self):
        self.result = ScanResult(
            scan_id="example-001",
            app_name="샘플 앱",
            scanned_at=datetime(2026, 11, 17, 9, tzinfo=timezone.utc),
            target=Target(source="./vulnapp"),
            risk_score=0,
            profile=AppProfile(framework="Flask", routes=1, auth=None),
            findings=[],
            report_md="# 진단 보고서",
        )

    def test_empty_source_scan(self):
        data = json.loads(self.result.to_json())
        self.assertEqual(data["mode"], "source-only")
        self.assertEqual(data["target"], {"source": "./vulnapp", "url": None})
        self.assertEqual(data["scanned_at"], "2026-11-17T09:00:00+00:00")
        self.assertEqual(data["summary"], {
            "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0,
        })
        self.assertEqual(data["findings"], [])

    def test_graybox_finding(self):
        self.result.target.url = "http://localhost:5000"
        self.result.findings.append(Finding(
            id="F-001", title="쿠키 설정 확인", cwe="CWE-1004",
            owasp="A05:2021", severity=Severity.LOW, confidence=Confidence.LIKELY,
            location=Location(endpoint="/"), evidence="설정 검토 필요",
            how_found=["static:configuration"], impact_ko="세션 쿠키 노출 가능",
            remediation_ko="HttpOnly 옵션을 확인하세요.", fix_diff="",
        ))
        raw = self.result.to_json()
        data = json.loads(raw)
        self.assertIn("쿠키 설정 확인", raw)
        self.assertEqual(data["mode"], "graybox")
        self.assertEqual(data["summary"]["Low"], 1)
        finding = data["findings"][0]
        self.assertEqual(finding["severity"], "Low")
        self.assertEqual(finding["confidence"], "Likely")
        self.assertEqual(finding["status"], "open")
        self.assertEqual(finding["location"]["endpoint"], "/")

    def test_invalid_risk_score(self):
        for score in (-1, 101):
            with self.subTest(score=score), self.assertRaises(ValueError):
                self.result.risk_score = score
                self.result.to_json()

    def test_timestamp_requires_timezone(self):
        self.result.scanned_at = self.result.scanned_at.replace(tzinfo=None)
        with self.assertRaises(ValueError):
            self.result.to_json()
