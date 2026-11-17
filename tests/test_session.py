import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from vibescan import session
from vibescan.login import login_app


class SessionTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)
        install = patch("vibescan.session.registration", return_value=("host", "issued"))
        install.start()
        self.addCleanup(install.stop)
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        keys = patch.object(session.JWKS, "get_signing_key_from_jwt",
                            return_value=Mock(key=self.key.public_key()))
        keys.start()
        self.addCleanup(keys.stop)

    def identity(self, nonce="nonce", issuer=session.ISSUER, audience="issued"):
        now = int(time.time())
        return jwt.encode({"iss": issuer, "aud": audience, "sub": "subject", "nonce": nonce,
                           "iat": now, "exp": now + 3600}, self.key, algorithm="RS256")

    def test_loopback_exchange_once(self):
        with patch("vibescan.login.registration", return_value=("host", "issued")):
            app = login_app(self.directory, "127.0.0.1:8765", "ticket")
        with TestClient(app, base_url="http://127.0.0.1:8765", follow_redirects=False) as http:
            self.assertEqual(http.get("/auth/login?key=ticket", headers={"host": "outside"}).status_code, 400)
            response = http.get("/auth/login?key=ticket")
            args = parse_qs(urlsplit(response.headers["location"]).query)
            self.assertEqual(args["client_id"], ["issued"])
            callback = {"state": args["state"][0], "code": "sample"}
            self.assertEqual(http.get("/auth/callback", params={**callback, "state": "bad"}).status_code, 400)
            tokens = {"id_token": self.identity(args["nonce"][0]), "access_token": "access",
                      "refresh_token": "refresh", "scope": session.PLAN, "expires_in": 3600}
            with patch.object(session, "token_request", return_value=tokens) as exchange:
                self.assertEqual(http.get("/auth/callback", params=callback).status_code, 200)
                self.assertEqual(http.get("/auth/callback", params=callback).status_code, 400)
                self.assertEqual(exchange.call_count, 1)
                self.assertEqual(exchange.call_args.kwargs["redirect_uri"], args["redirect_uri"][0])
            self.assertEqual(session.access_token(self.directory), "access")

    def test_identity_rejections(self):
        for token in (self.identity("other"), self.identity(issuer="bad"), self.identity(audience="bad")):
            with self.assertRaises((session.SessionError, jwt.InvalidTokenError)):
                session.checked_identity(token, "issued", "nonce")

    def test_rotation_and_revoked_grant(self):
        data = {"sub": "subject", "scope": session.PLAN, "access_token": "old",
                "refresh_token": "one", "id_token": None, "expires_at": 0}
        with session.transaction(self.directory) as db:
            session.save(db, "issued", data)
        with patch.object(session, "token_request", return_value={
                "access_token": "next", "refresh_token": "two", "expires_in": 3600}) as refresh:
            self.assertEqual(session.access_token(self.directory), "next")
            self.assertEqual(session.access_token(self.directory), "next")
            self.assertEqual(refresh.call_count, 1)
        with session.transaction(self.directory) as db:
            data = session.read_record(db, "issued")
            self.assertEqual(data["refresh_token"], "two")
            data["expires_at"] = 0
            session.save(db, "issued", data)
        with patch.object(session, "token_request", side_effect=session.InvalidGrant()) as refresh:
            for _ in range(2):
                with self.assertRaises(session.SessionError):
                    session.access_token(self.directory)
            self.assertEqual(refresh.call_count, 1)
