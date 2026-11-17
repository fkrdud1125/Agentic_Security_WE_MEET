"""Register this installation with ChatGPT. Run with python -m vibescan.register."""

import base64
import hashlib
import os
import secrets
import sqlite3
import sys
import time
import uuid
import webbrowser
from contextlib import closing
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit


def request_registration(host_id):
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    client_id = None
    failure = None

    class Callback(BaseHTTPRequestHandler):
        timeout = 3

        def log_message(self, *args):
            pass  # The callback URL contains a one-time authorization code.

        def do_GET(self):
            nonlocal client_id, failure
            parts = urlsplit(self.path)
            if self.headers.get("Host") != address or parts.path != "/auth/callback":
                self.send_error(404)
                return
            query = parse_qs(parts.query, keep_blank_values=True)
            if query.get("state") != [state]:
                self.send_error(400, "Invalid state")
                return
            ids = query.get("client_id", [])
            codes = query.get("code", [])
            if "error" in query:
                failure = "등록 요청이 승인되지 않았습니다."
            elif len(ids) != 1 or not ids[0] or ids[0] == "dynamic_agent_client":
                failure = "발급된 클라이언트 ID를 확인할 수 없습니다."
            elif len(codes) != 1 or not codes[0]:
                failure = "인증 코드가 누락되었거나 중복되었습니다."
            else:
                client_id = ids[0]

            self.send_response(400 if failure else 200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write("터미널에서 등록 결과를 확인하세요.".encode())

    with HTTPServer(("127.0.0.1", 0), Callback) as server:
        address = f"127.0.0.1:{server.server_port}"
        params = {
            "client_id": "dynamic_agent_client",
            "agent_name_hint": "VibeScan",
            "ext_agent_host_id": host_id,
            "redirect_uri": f"http://{address}/auth/callback",
            "response_type": "code",
            "scope": "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct",
            "resource": "https://api.openai.com/v1",
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        url = "https://auth.openai.com/api/accounts/authorize?" + urlencode(params)
        if not webbrowser.open(url):
            raise RuntimeError("기본 브라우저를 열 수 없습니다.")
        deadline = time.monotonic() + 300
        while client_id is None and failure is None:
            server.timeout = deadline - time.monotonic()
            if server.timeout <= 0:
                raise RuntimeError("등록 대기 시간이 만료되었습니다.")
            server.handle_request()
    if failure:
        raise RuntimeError(failure)
    return client_id


def register(directory):
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    with closing(sqlite3.connect(directory / "registration.sqlite3", timeout=2)) as db:
        with db:
            db.execute("CREATE TABLE IF NOT EXISTS installation "
                       "(id INTEGER PRIMARY KEY CHECK (id = 1), host TEXT NOT NULL, client TEXT)")
            db.execute("INSERT OR IGNORE INTO installation (id, host) VALUES (1, ?)",
                       (uuid.uuid4().urn,))

        # Only one browser may register this installation's first profile at a time.
        with db:
            db.execute("BEGIN IMMEDIATE")
            host, client = db.execute("SELECT host, client FROM installation WHERE id = 1").fetchone()
            if client:
                return False
            issued = request_registration(host)
            db.execute("UPDATE installation SET client = ? WHERE id = 1", (issued,))
        return True


def main():
    if sys.platform == "win32":
        root = Path(os.environ["LOCALAPPDATA"])
    else:
        root = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    try:
        created = register(root / "vibescan")
    except (OSError, sqlite3.Error, RuntimeError) as exc:
        sys.exit(f"등록 실패: {exc}")
    print("클라이언트 ID를 저장했습니다." if created else "이미 등록된 설치입니다.")


if __name__ == "__main__":
    main()
