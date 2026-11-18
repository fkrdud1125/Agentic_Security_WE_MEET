"""Loopback dashboard for saved results and explicit local repository scans."""

import asyncio
import os
import re
import secrets
import shutil
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
from .cli import ScanInputError, scan
from .login import login
from .register import data_dir
from .session import logout, status

ASSETS = Path(__file__).with_name("web")
GITHUB = re.compile(r"(?:https://github\.com/|git@github\.com:)([A-Za-z0-9][A-Za-z0-9-]{0,38})/([A-Za-z0-9._-]{1,100}?)(?:\.git)?/?")


def run_git(*args, cwd=None):
    # No prompts: private repos rely on the PC's existing Git credentials (SSH key or credential helper).
    subprocess.run(["git", *args], cwd=cwd, check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, timeout=300, env=os.environ | {"GIT_TERMINAL_PROMPT": "0"})


class RepoInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str = Field(min_length=1, max_length=4096)


class ScanInput(RepoInput):
    offline: bool = Field(default=True, strict=True)


def dashboard_app(results: Path, address: str, ticket: str, directory: Path | None = None):
    root = results.expanduser().resolve()
    directory = (directory or data_dir()).expanduser().resolve()
    database = directory / "scan-history.sqlite3"
    clones = directory / "github"
    lock = threading.Lock()
    cloning = threading.Lock()
    job = {"state": "idle"}
    sign_in = {"state": "idle"}
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
            exists = path.is_dir()
        except (ValueError, OSError):
            exists = False
        if not exists:
            raise HTTPException(422, "폴더를 찾을 수 없습니다. 경로가 맞는지 확인하세요.")
        try:
            top = Path(os.fsdecode(git(path, "rev-parse", "--show-toplevel").rstrip(b"\r\n"))).resolve()
            commit = git(path, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
            branch = git(path, "rev-parse", "--abbrev-ref", "HEAD").decode().strip()
        except (ValueError, OSError, subprocess.TimeoutExpired):
            raise HTTPException(422, "Git 저장소가 아니거나 커밋이 없습니다. git init 후 첫 커밋을 만드세요.") from None
        if path != top:
            raise HTTPException(422, f"저장소의 하위 폴더입니다. 저장소 루트를 지정하세요: {top}")
        if root.is_relative_to(path) or directory.is_relative_to(path):
            raise HTTPException(422, "결과·설정 폴더가 이 저장소 안에 있습니다. 저장소 밖의 폴더를 사용하세요.")
        return {"path": str(path), "name": path.name, "commit": commit,
                "branch": None if branch == "HEAD" else branch}

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

    def clone(url):
        match = GITHUB.fullmatch(url)
        if not match or match[2] in (".", ".."):
            raise HTTPException(422, "GitHub 주소는 https://github.com/소유자/저장소 형식이어야 합니다.")
        dest = clones / match[1] / match[2]
        if dest.exists():
            return dest  # already cloned: reconnect, rescans fetch the latest commit
        if not cloning.acquire(blocking=False):
            raise HTTPException(409, "다른 저장소를 복제하는 중입니다. 완료 후 다시 시도하세요.")
        try:
            dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            run_git("clone", "--depth", "1", "--no-tags", "--", url, str(dest))
        except subprocess.TimeoutExpired:
            shutil.rmtree(dest, ignore_errors=True)
            raise HTTPException(504, "복제 시간(5분)이 초과되었습니다. 저장소 크기와 네트워크를 확인하세요.") from None
        except (subprocess.CalledProcessError, OSError):
            shutil.rmtree(dest, ignore_errors=True)
            raise HTTPException(422, "GitHub 저장소를 복제하지 못했습니다. 주소와 네트워크를 확인하세요. "
                                     "비공개 저장소는 이 PC의 Git 인증(SSH 키·자격 증명)이 필요합니다.") from None
        finally:
            cloning.release()
        return dest

    @app.post("/api/repos")
    def connect_repo(body: RepoInput):
        raw = body.path.strip()
        repo = repository(clone(raw) if raw.startswith(("https://", "http://", "git@")) else raw)
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
            if Path(repo).is_relative_to(clones):
                # VibeScan owns these clones, so a hard reset to the remote HEAD discards nothing of the user's.
                run_git("fetch", "--depth", "1", "--no-tags", "origin", "HEAD", cwd=repo)
                run_git("reset", "--hard", "--quiet", "FETCH_HEAD", cwd=repo)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            with lock:
                job = {"state": "failed", "repo": repo, "message": "GitHub에서 최신 커밋을 가져오지 못했습니다. "
                       "네트워크와 저장소 접근 권한을 확인하세요. 기존 결과는 유지됩니다."}
            return
        try:
            folder, note, issue = scan(Path(repo), root, directory, offline=offline)
            completed = {"state": "completed", "repo": repo, "scan_id": folder.name, "message": note, "issue": issue}
        except subprocess.TimeoutExpired:
            completed = {"state": "failed", "repo": repo, "message": "검사 시간이 초과되었습니다. 기존 결과는 유지됩니다."}
        except ScanInputError as exc:
            completed = {"state": "failed", "repo": repo, "message": f"{exc} 기존 결과는 유지됩니다."}
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

    def run_login():
        nonlocal sign_in
        try:
            done = {"state": "completed", "message": login(directory)}
        except RuntimeError as exc:
            # login() and SessionError messages are written by VibeScan and hold no tokens.
            done = {"state": "failed", "message": str(exc)}
        except Exception:
            done = {"state": "failed", "message": "로그인에 실패했습니다. 다시 시도하세요."}
        with lock:
            sign_in = done

    @app.get("/api/auth")
    def auth():
        try:
            state = status(directory)
        except Exception:
            # Unreadable or undecryptable session files must not leak details over HTTP.
            state = {"state": "login", "message": "로그인 정보를 읽을 수 없습니다. 다시 로그인하세요."}
        with lock:
            return state | {"login": dict(sign_in)}

    @app.post("/api/logout")
    def sign_out():
        with lock:
            if sign_in["state"] == "running":
                raise HTTPException(409, "로그인 진행 중에는 로그아웃할 수 없습니다.")
        try:
            logout(directory)
        except Exception:
            raise HTTPException(503, "로그아웃하지 못했습니다. 다시 시도하세요.") from None
        return auth()

    @app.post("/api/login", status_code=202)
    def start_login():
        nonlocal sign_in
        with lock:
            if sign_in["state"] == "running":
                raise HTTPException(409, "이미 로그인 창이 열려 있습니다. 브라우저에서 승인을 마치세요.")
            sign_in = {"state": "running",
                       "message": "브라우저에서 ChatGPT 로그인과 구독 사용 승인을 진행하세요. 5분 안에 완료해야 합니다."}
            # Daemon: an abandoned login window must not keep the dashboard from exiting.
            threading.Thread(target=run_login, daemon=True).start()
            return dict(sign_in)

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
