"""Loopback dashboard for saved results and explicit local repository scans."""

import asyncio
import os
import re
import secrets
import socket
import sqlite3
import subprocess
import threading
import webbrowser
from contextlib import asynccontextmanager, closing
from datetime import timezone
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field

from scanner.ingest import git
from scanner.models import ScanResult
from .cli import scan
from .register import data_dir

ASSETS = Path(__file__).with_name("web")


class RepoInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str = Field(min_length=1, max_length=4096)


class ScanInput(RepoInput):
    offline: bool = Field(default=True, strict=True)


def dashboard_app(results: Path, address: str, ticket: str, directory: Path | None = None):
    root = results.expanduser().resolve()
    directory = (directory or data_dir()).expanduser().resolve()
    database = directory / "scan-history.sqlite3"
    lock = threading.Lock()
    job = {"state": "idle"}
    worker = None

    @asynccontextmanager
    async def lifespan(app):
        yield
        if worker is not None:
            await asyncio.to_thread(worker.join)

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)

    def repository(raw):
        try:
            path = Path(raw).expanduser().resolve()
            top = Path(os.fsdecode(git(path, "rev-parse", "--show-toplevel").rstrip(b"\r\n"))).resolve()
            if path != top:
                raise ValueError("Not repository root")
            commit = git(path, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
            branch = git(path, "rev-parse", "--abbrev-ref", "HEAD").decode().strip()
            if root.is_relative_to(path) or directory.is_relative_to(path):
                raise ValueError("Output inside repository")
            return {"path": str(path), "name": path.name, "commit": commit,
                    "branch": None if branch == "HEAD" else branch}
        except (ValueError, OSError, subprocess.TimeoutExpired):
            raise HTTPException(422, "커밋이 있는 로컬 Git 저장소의 루트를 지정하세요. 결과·설정 폴더는 저장소 밖에 있어야 합니다.") from None

    def connected():
        if not database.exists():
            return []
        with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as db:
            if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='connected_repos'").fetchone():
                return []
            return [row[0] for row in db.execute("SELECT path FROM connected_repos ORDER BY path")]

    @app.get("/api/repos")
    def repos():
        try:
            return {"repos": [{"path": path, "name": Path(path).name} for path in connected()]}
        except (OSError, sqlite3.Error):
            raise HTTPException(503, "연결된 레포 목록을 읽을 수 없습니다.") from None

    @app.post("/api/repos")
    def connect_repo(body: RepoInput):
        repo = repository(body.path)
        try:
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            with closing(sqlite3.connect(database)) as db, db:
                db.execute("CREATE TABLE IF NOT EXISTS connected_repos(path TEXT PRIMARY KEY NOT NULL)")
                db.execute("INSERT OR IGNORE INTO connected_repos VALUES (?)", (repo["path"],))
        except (OSError, sqlite3.Error):
            raise HTTPException(503, "레포 연결을 저장할 수 없습니다.") from None
        return repo

    def run_scan(repo, offline):
        nonlocal job
        try:
            folder, note = scan(Path(repo), root, directory, offline=offline)
            completed = {"state": "completed", "repo": repo, "scan_id": folder.name, "message": note}
        except subprocess.TimeoutExpired:
            completed = {"state": "failed", "repo": repo, "message": "검사 시간이 초과되었습니다. 기존 결과는 유지됩니다."}
        except Exception:
            # Engine/provider exceptions must not expose source text or credentials through HTTP.
            completed = {"state": "failed", "repo": repo,
                         "message": "스캔에 실패했습니다. Git 저장소·Semgrep 설치·저장 경로를 확인하세요. 기존 결과는 유지됩니다."}
        with lock:
            job = completed

    @app.post("/api/scan", status_code=202)
    def start_scan(body: ScanInput):
        nonlocal job, worker
        # shortcut: one scan per dashboard process; use a DB lease if multiple servers are supported.
        with lock:
            if job["state"] == "running":
                raise HTTPException(409, "이미 스캔 중입니다. 완료 후 다시 실행하세요.")
            repo = repository(body.path)
            try:
                if repo["path"] not in connected():
                    raise HTTPException(404, "먼저 레포를 연결하세요.")
            except (OSError, sqlite3.Error):
                raise HTTPException(503, "레포 연결 정보를 읽을 수 없습니다.") from None
            job = {"state": "running", "repo": repo["path"], "offline": body.offline}
            worker = threading.Thread(target=run_scan, args=(repo["path"], body.offline))
            try:
                worker.start()
            except RuntimeError:
                worker = None
                job = {"state": "failed", "message": "스캔을 시작할 수 없습니다. 다시 시도하세요."}
                raise HTTPException(503, job["message"]) from None
            return dict(job)

    @app.get("/api/scan")
    def scan_status():
        with lock:
            return dict(job)

    @app.middleware("http")
    async def local_only(request, call_next):
        origin = request.headers.get("origin")
        if request.headers.get("host") != address:
            response = PlainTextResponse("Invalid host", 400)
        elif origin is not None and origin != f"http://{address}":
            response = PlainTextResponse("Invalid origin", 403)
        elif request.url.path.startswith("/api/") and not secrets.compare_digest(
            request.headers.get("x-vibescan-token", "").encode(), ticket.encode()
        ):
            response = PlainTextResponse("대시보드를 실행한 창에서 다시 접속하세요.", 403)
        else:
            response = await call_next(request)
        response.headers.update({
            "Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; "
                                       "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
        })
        return response

    def read_result(scan_id):
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", scan_id):
            raise HTTPException(404, "결과를 찾을 수 없습니다.")
        path = root / scan_id / "scan_result.json"
        if path.resolve() != path or not path.is_file():
            raise HTTPException(404, "결과 파일이 없거나 허용된 폴더 밖에 있습니다.")
        try:
            # shortcut: whole JSON files are read, index results when histories become large.
            with path.open("rb") as file:
                raw = file.read(16 * 1024 * 1024 + 1)
            if len(raw) > 16 * 1024 * 1024:
                raise ValueError("Result too large")
            result = ScanResult.from_json(raw.decode("utf-8"))
            if result.scan_id != scan_id:
                raise ValueError("Mismatched scan ID")
            data = result.to_dict()
            data["scanned_at"] = result.scanned_at.astimezone(timezone.utc).isoformat()
            return data
        except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
            raise HTTPException(422, "결과 파일을 읽을 수 없습니다. JSON 형식과 파일 크기를 확인하세요.") from None

    @app.get("/")
    def index():
        return FileResponse(ASSETS / "index.html")

    @app.get("/assets/{name}")
    def asset(name: str):
        if name not in ("dashboard.css", "dashboard.js"):
            raise HTTPException(404)
        return FileResponse(ASSETS / name)

    @app.get("/api/scans")
    def scans():
        rows, unavailable = [], 0
        try:
            folders = list(root.iterdir()) if root.exists() else []
            for folder in folders:
                if not folder.is_dir():
                    continue
                try:
                    data = read_result(folder.name)
                except HTTPException:
                    unavailable += 1
                    continue
                rows.append({key: data[key] for key in ("scan_id", "repo", "commit", "scanned_at", "risk_score")})
        except OSError:
            raise HTTPException(503, "결과 폴더에 접근할 수 없습니다.") from None
        rows.sort(key=lambda row: (row["scanned_at"], row["scan_id"]), reverse=True)
        return {"scans": rows, "unavailable": unavailable, "results_path": str(root)}

    @app.get("/api/scans/{scan_id}")
    def detail(scan_id: str):
        return read_result(scan_id)

    return app


def serve(results: Path):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        address = f"127.0.0.1:{sock.getsockname()[1]}"
        ticket = secrets.token_urlsafe(32)
        app = dashboard_app(results, address, ticket)
        url = f"http://{address}/#{ticket}"

        def open_browser():
            print(f"VibeScan 대시보드: {url}\n종료: Ctrl+C", flush=True)
            webbrowser.open(url)

        # The socket is already listening, so early browser requests can wait for startup.
        server = uvicorn.Server(uvicorn.Config(app, access_log=False, log_level="warning", proxy_headers=False))
        timer = threading.Timer(0.5, open_browser)
        timer.start()
        try:
            server.run(sockets=[sock])
        finally:
            timer.cancel()
