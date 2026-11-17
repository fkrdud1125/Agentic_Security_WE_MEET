"""Read-only loopback dashboard for the engine's saved JSON results."""

import re
import secrets
import socket
import threading
import webbrowser
from datetime import timezone
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse

from scanner.models import ScanResult

ASSETS = Path(__file__).with_name("web")


def dashboard_app(results: Path, address: str, ticket: str):
    root = results.expanduser().resolve()
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

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
