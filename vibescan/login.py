"""Short-lived FastAPI loopback listener for an explicit CLI login."""

import secrets
import socket
import threading
import time
import webbrowser

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, RedirectResponse

from .register import authorization_url
from .session import complete_login, read_record, registration, transaction


def login_app(directory, address, ticket):
    host, client = registration(directory)
    redirect = f"http://{address}/auth/callback"
    pending = None
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.result = None

    @app.middleware("http")
    async def local_only(request, call_next):
        if request.headers.get("host") != address:
            return PlainTextResponse("Invalid host", 400)
        response = await call_next(request)
        response.headers.update({"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})
        return response

    @app.get("/auth/login")
    async def begin(key: str = ""):
        nonlocal pending
        if not secrets.compare_digest(key.encode(), ticket.encode()) or pending is not None:
            return PlainTextResponse("Invalid login attempt", 403)
        state, nonce, verifier = (secrets.token_urlsafe(n) for n in (32, 32, 64))
        with transaction(directory) as db:
            hint = read_record(db, client).get("id_token")
        pending = (state, nonce, verifier, time.monotonic())
        return RedirectResponse(authorization_url(host, client, redirect, state, nonce, verifier, hint))

    @app.get("/auth/callback")
    async def callback(request: Request):
        nonlocal pending
        q = request.query_params
        if not pending or q.getlist("state") != [pending[0]] or time.monotonic() - pending[3] > 300:
            return PlainTextResponse("Invalid or expired login attempt", 400)
        _, nonce, verifier, _ = pending
        pending = None
        codes = q.getlist("code")
        if "error" in q or len(codes) != 1 or not codes[0] or q.getlist("client_id") not in ([], [client]):
            app.state.result = (False, "로그인 요청이 거절되었거나 응답이 올바르지 않습니다.")
        else:
            try:
                enabled = complete_login(directory, client, codes[0], verifier, redirect, nonce)
                app.state.result = (True, "로그인 완료 · " + ("구독 사용 가능" if enabled else "구독 사용 권한 없음"))
            except Exception:
                # Provider exceptions may contain a URL, token, or authorization code.
                app.state.result = (False, "토큰 교환 또는 계정 검증에 실패했습니다. 다시 로그인하세요.")
        ok, message = app.state.result
        return PlainTextResponse(message, 200 if ok else 400)

    return app


def login(directory):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        address = f"127.0.0.1:{sock.getsockname()[1]}"
        ticket = secrets.token_urlsafe(32)
        app = login_app(directory, address, ticket)
        server = uvicorn.Server(uvicorn.Config(app, access_log=False, log_level="critical",
                                              proxy_headers=False))
        sock.listen()
        worker = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
        worker.start()
        try:
            deadline = time.monotonic() + 300
            while not server.started and worker.is_alive() and time.monotonic() < deadline:
                time.sleep(0.05)
            if not server.started or not webbrowser.open(f"http://{address}/auth/login?key={ticket}"):
                raise RuntimeError("로컬 로그인 창을 열 수 없습니다.")
            while not app.state.result and worker.is_alive() and time.monotonic() < deadline:
                time.sleep(0.1)
            ok, message = app.state.result or (False, "로그인 대기 시간이 만료되었습니다.")
            if not ok:
                raise RuntimeError(message)
            return message
        finally:
            server.should_exit = True
            worker.join(timeout=5)
