"""ChatGPT OAuth credentials for the local installation's registered profile."""

import json
import os
import sqlite3
import sys
import time
from contextlib import closing, contextmanager

import jwt
import requests


ISSUER = "https://auth.openai.com"
RESOURCE = "https://api.openai.com/v1"
PLAN = "chatgpt.tokens.use.direct"
JWKS = jwt.PyJWKClient(ISSUER + "/.well-known/jwks.json", timeout=10)


class SessionError(RuntimeError):
    pass


def registration(directory):
    path = directory / "registration.sqlite3"
    if path.is_file():
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
            row = db.execute("SELECT host, client FROM installation WHERE id=1").fetchone()
            if row and row[1]:
                return row
    raise SessionError("먼저 python -m vibescan.register 로 이 PC를 등록하세요.")


@contextmanager
def transaction(directory):
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = directory / "session.sqlite3"
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    os.close(fd)
    if sys.platform != "win32":
        path.chmod(0o600)
    with closing(sqlite3.connect(path, timeout=35)) as db, db:
        db.execute("CREATE TABLE IF NOT EXISTS sessions(client TEXT PRIMARY KEY, payload BLOB NOT NULL)")
        db.execute("BEGIN IMMEDIATE")
        yield db


def read_record(db, client):
    row = db.execute("SELECT payload FROM sessions WHERE client=?", (client,)).fetchone()
    if not row:
        return {}
    blob = row[0]
    if sys.platform == "win32":
        import win32crypt
        blob = win32crypt.CryptUnprotectData(blob, None, None, None, 1)[1]
    return json.loads(blob)


def save(db, client, data):
    blob = json.dumps(data).encode()
    if sys.platform == "win32":
        import win32crypt
        blob = win32crypt.CryptProtectData(blob, "VibeScan", None, None, None, 1)
    db.execute("INSERT OR REPLACE INTO sessions VALUES (?,?)", (client, blob))


def token_request(client, **form):
    response = requests.post(ISSUER + "/api/accounts/oauth/token",
                             data={"client_id": client, "resource": RESOURCE, **form},
                             timeout=20, allow_redirects=False)
    if response.status_code != 200:
        if response.status_code in (400, 401) and response.json().get("error") == "invalid_grant":
            raise InvalidGrant("승인이 만료되었습니다. vibescan login 으로 다시 연결하세요.")
        raise SessionError(f"토큰 요청 실패 (HTTP {response.status_code}).")
    return response.json()


class InvalidGrant(SessionError):
    pass


def checked_identity(raw, client, nonce=None):
    key = JWKS.get_signing_key_from_jwt(raw).key
    claims = jwt.decode(raw, key, algorithms=["RS256"], issuer=ISSUER, audience=client,
                        options={"require": ["sub", "exp", "iat"]})
    if nonce is not None and claims.get("nonce") != nonce:
        raise SessionError("로그인 응답의 nonce가 일치하지 않습니다.")
    return claims["sub"]


def updated_record(tokens, previous, subject):
    access = tokens.get("access_token")
    scope = tokens.get("scope", previous.get("scope", ""))
    if PLAN in scope.split() and not access:
        raise SessionError("구독 사용 권한에 필요한 토큰이 없습니다.")
    return {"sub": subject, "scope": scope, "access_token": access,
            "expires_at": time.time() + int(tokens.get("expires_in", 0)),
            "id_token": tokens.get("id_token", previous.get("id_token")),
            "refresh_token": tokens.get("refresh_token", previous.get("refresh_token"))}


def complete_login(directory, client, code, verifier, redirect, nonce):
    tokens = token_request(client, grant_type="authorization_code", code=code,
                           code_verifier=verifier, redirect_uri=redirect)
    subject = checked_identity(tokens["id_token"], client, nonce)
    with transaction(directory) as db:
        old = read_record(db, client)
        if old and old["sub"] != subject:
            raise SessionError("등록된 계정과 일치하지 않습니다.")
        data = updated_record(tokens, {}, subject)
        save(db, client, data)
    return PLAN in data["scope"].split()


def access_token(directory):
    _, client = registration(directory)
    with transaction(directory) as db:
        record = read_record(db, client)
        if not record or PLAN not in record["scope"].split():
            raise SessionError("구독 사용을 연결하려면 vibescan login 을 실행하세요.")
        if record["expires_at"] > time.time() + 60:
            return record["access_token"]
        if not record.get("refresh_token"):
            raise SessionError("세션이 만료되었습니다. 다시 로그인하세요.")
        try:
            tokens = token_request(client, grant_type="refresh_token", refresh_token=record["refresh_token"])
        except InvalidGrant:
            save(db, client, {"sub": record["sub"], "scope": ""})
        else:
            if tokens.get("id_token") and checked_identity(tokens["id_token"], client) != record["sub"]:
                raise SessionError("갱신된 계정 정보가 일치하지 않습니다.")
            record = updated_record(tokens, record, record["sub"])
            save(db, client, record)
            if PLAN in record["scope"].split():
                return record["access_token"]
    raise SessionError("구독 사용을 다시 승인하려면 vibescan login 을 실행하세요.")
