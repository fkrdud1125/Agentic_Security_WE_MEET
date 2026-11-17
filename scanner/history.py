"""커밋별 스캔과 발견 메타데이터를 로컬 SQLite 파일에 보관한다."""

import sqlite3
from contextlib import closing
from datetime import timezone
from pathlib import Path

from .models import ScanResult


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY NOT NULL,
    repo_name TEXT NOT NULL,
    repo_path TEXT NOT NULL,
    branch TEXT,
    commit_sha TEXT,
    baseline_commit TEXT,
    scan_type TEXT NOT NULL CHECK (scan_type IN ('full', 'diff')),
    scan_trigger TEXT NOT NULL CHECK (scan_trigger IN ('manual', 'git-hook', 'watcher')),
    scanned_at TEXT NOT NULL,
    risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    new_count INTEGER NOT NULL,
    fixed_count INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS scans_by_repo_time ON scans(repo_path, scanned_at DESC);
CREATE TABLE IF NOT EXISTS findings (
    scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    finding_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    status TEXT NOT NULL,
    change TEXT CHECK (change IN ('new', 'existing', 'fixed')),
    introduced_in TEXT,
    cwe TEXT NOT NULL,
    file TEXT,
    line INTEGER,
    PRIMARY KEY (scan_id, finding_id)
);
"""


def save_scan(database: Path, result: ScanResult) -> None:
    data = result.to_dict()
    repo = data["repo"]
    with closing(sqlite3.connect(database)) as db:
        db.execute("PRAGMA foreign_keys = ON")
        db.executescript(SCHEMA)
        with db:
            db.execute("""
                INSERT INTO scans (scan_id, repo_name, repo_path, branch, commit_sha,
                    baseline_commit, scan_type, scan_trigger, scanned_at, risk_score,
                    new_count, fixed_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (result.scan_id, repo["name"], repo["path"], repo["branch"], result.commit,
                  result.baseline_commit, result.scan_type, result.trigger,
                  result.scanned_at.astimezone(timezone.utc).isoformat(timespec="microseconds"),
                  result.risk_score, data["delta"]["new"], data["delta"]["fixed"]))
            db.executemany("""
                INSERT INTO findings (scan_id, finding_id, severity, confidence, status,
                    change, introduced_in, cwe, file, line)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, ((result.scan_id, f.id, f.severity, f.confidence, f.status,
                   f.change, f.introduced_in, f.cwe, f.location.file, f.location.line)
                  for f in result.findings))


def list_scans(database: Path, repo_path: str) -> list[dict]:
    with closing(sqlite3.connect(database)) as db:
        db.executescript(SCHEMA)
        db.row_factory = sqlite3.Row
        rows = db.execute("""
            SELECT * FROM scans WHERE repo_path IN (?, ?)
            ORDER BY scanned_at DESC, scan_id DESC
        """, (repo_path, str(Path(repo_path).expanduser().resolve())))
        return [dict(row) for row in rows]
