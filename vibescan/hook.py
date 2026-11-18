"""git post-commit hook that rescans a connected repository in the background after each commit."""

import shlex
import sqlite3
import subprocess
import sys
import time
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from scanner.ingest import git
from scanner.models import Trigger

MARKER = "# vibescan-hook"
DEBOUNCE = 3  # seconds a hook waits so a burst of commits (rebase, amend) is scanned once, at its last commit


def connected(database):
    if not database.exists():
        return []
    with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as db:
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='connected_repos'").fetchone():
            return []
        return [row[0] for row in db.execute("SELECT path FROM connected_repos ORDER BY path")]


def hook_file(repo):
    """The repository's own post-commit hook; None when core.hooksPath points elsewhere (shared or tool-managed)."""
    try:
        git(repo, "config", "--get", "core.hooksPath")
        return None
    except ValueError:  # unset: hooks live in the repository's own git directory
        return (repo / git(repo, "rev-parse", "--git-path", "hooks").decode().strip() / "post-commit").resolve()


def command():
    # Git runs hooks with sh (Git for Windows too); forward slashes keep Windows paths intact there.
    python = shlex.quote(Path(sys.executable).as_posix())
    # Pin the code that installed the hook, even when it runs from a checkout rather than an installed package.
    source = shlex.quote(Path(__file__).resolve().parents[1].as_posix())
    return f'PYTHONPATH={source} {python} -m vibescan hook-trigger "$(git rev-parse HEAD)" >/dev/null 2>&1 &'


def installed(repo):
    path = hook_file(repo)
    return bool(path and path.is_file() and MARKER in path.read_text(encoding="utf-8", errors="replace"))


def install(repo):
    path = hook_file(repo)
    if path is None:
        raise ValueError(f"core.hooksPath를 사용하는 저장소입니다. 그 폴더의 post-commit hook에 다음 줄을 직접 추가하세요: {command()}")
    if path.exists() and MARKER not in path.read_text(encoding="utf-8", errors="replace"):
        raise ValueError(f"이미 다른 post-commit hook이 있어 덮어쓰지 않았습니다. 그 파일에 다음 줄을 직접 추가하세요: {command()}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"#!/bin/sh\n{MARKER}: 커밋 후 백그라운드 보안 검사. 대시보드에서 끄거나 이 파일을 지우면 해제됩니다.\n"
                    f"{command()}\n", encoding="utf-8", newline="\n")
    path.chmod(0o755)


def uninstall(repo):
    path = hook_file(repo)
    if path and path.is_file() and MARKER in path.read_text(encoding="utf-8", errors="replace"):
        path.unlink()


def trigger(repo, commit, directory, wait=DEBOUNCE):
    """Entry point of the hook: static-only scan of HEAD, skipped when a newer commit's hook will run."""
    from .cli import scan  # deferred: keeps `import vibescan.hook` light for the dashboard

    repo = repo.resolve()
    log = directory / "hook.log"
    try:
        if str(repo) not in connected(directory / "scan-history.sqlite3"):
            return None  # e.g. a shared hooks folder firing in a repository the user never connected
        time.sleep(wait)
        if git(repo, "rev-parse", "HEAD").decode().strip() != commit:
            return None
        folder, _, _ = scan(repo, directory / "scans", directory, offline=True, trigger=Trigger.GIT_HOOK)
        return folder
    except Exception as exc:
        # Nobody watches a background hook, so leave one line the user can find; engine messages hold no source text.
        directory.mkdir(parents=True, exist_ok=True)
        with log.open("a", encoding="utf-8") as file:
            file.write(f"{datetime.now(timezone.utc).isoformat()} {repo} {commit[:12]} {type(exc).__name__}: {exc}\n")
        return None
