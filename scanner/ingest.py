"""Materialize eligible regular Git blobs at one commit without executing repo code."""

import os
import subprocess
from pathlib import Path, PureWindowsPath

from pathspec import GitIgnoreSpec


EXCLUDED = {".git", ".venv", "venv", "node_modules", "vendor", "dist", "build", "__pycache__"}
EXTENSIONS = {".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".html", ".toml",
              ".json", ".yaml", ".yml", ".ini", ".cfg", ".properties", ".txt"}
MAX_FILE = 1024 * 1024
MAX_TOTAL = 64 * MAX_FILE


def git(repo, *args):
    run = subprocess.run(["git", "--no-replace-objects", "-C", str(repo), *args],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60)
    if run.returncode:
        raise ValueError("커밋이 있는 로컬 Git 저장소를 지정하세요.")
    return run.stdout


def snapshot(repo, destination):
    root = Path(os.fsdecode(git(repo, "rev-parse", "--show-toplevel").rstrip(b"\r\n"))).resolve()
    if repo.resolve() != root:
        raise ValueError("검사할 Git 저장소의 루트 폴더를 지정하세요.")
    commit = git(root, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    branch = git(root, "rev-parse", "--abbrev-ref", "HEAD").decode().strip()
    entries = []
    ignores = {}
    for record in git(root, "ls-tree", "-rlz", commit).split(b"\0"):
        if not record:
            continue
        meta, raw = record.split(b"\t", 1)
        mode, _, oid, size = meta.split()
        if mode not in (b"100644", b"100755") or int(size) > MAX_FILE:
            continue
        try:
            name = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        path = Path(name)
        parts = name.split("/")
        if any(part in ("", ".", "..") or part.casefold() in EXCLUDED
               or part.endswith((" ", ".")) or PureWindowsPath(part).is_reserved()
               or any(ord(c) < 32 or c in ':\\*?"<>|' for c in part) for part in parts):
            continue
        if path.name in (".gitignore", ".vibescanignore"):
            ignores[path] = GitIgnoreSpec.from_lines(git(root, "cat-file", "blob", oid.decode())
                                                     .decode("utf-8", "replace").splitlines())
        elif (path.suffix.lower() in EXTENSIONS and not any(p.lower().startswith(".env") for p in parts)
              and not path.name.lower().endswith((".min.js", ".min.css"))
              and not path.name.startswith(".")):
            entries.append((path, oid.decode(), int(size)))

    files = []
    total = 0
    for path, oid, size in entries:
        excluded = False
        for parent in reversed(path.parents):
            spec = ignores.get(parent / ".gitignore")
            if spec:
                include = spec.check_file(path.relative_to(parent).as_posix()).include
                if include is not None:
                    excluded = include
        custom = ignores.get(Path(".vibescanignore"))
        if excluded or (custom and custom.match_file(path.as_posix())):
            continue
        total += size
        if total > MAX_TOTAL:
            raise ValueError("검사 대상이 64 MiB를 초과합니다. .vibescanignore로 범위를 줄이세요.")
        blob = git(root, "cat-file", "blob", oid)
        try:
            blob.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if b"\0" in blob:
            continue
        target = destination / path
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as output:
            output.write(blob)
        files.append(path.as_posix())
    return commit, None if branch == "HEAD" else branch, files
