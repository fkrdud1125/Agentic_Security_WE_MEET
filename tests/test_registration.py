import sqlite3
import unittest
from contextlib import closing
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlencode, urlsplit

from vibescan.register import register


class RegistrationTests(unittest.TestCase):
    def run_attempt(self, path, reply):
        query = {}
        statuses = []

        def open_browser(url):
            parsed = urlsplit(url)
            self.assertEqual((parsed.scheme, parsed.netloc, parsed.path),
                             ("https", "auth.openai.com", "/api/accounts/authorize"))
            query.update(parse_qs(parsed.query))
            self.assertEqual(query["client_id"], ["dynamic_agent_client"])
            self.assertEqual(query["code_challenge_method"], ["S256"])
            self.assertEqual(len(query["code_challenge"][0]), 43)
            self.assertNotIn("code_verifier", query)
            return True

        def handle_request(server):
            redirect = urlsplit(query["redirect_uri"][0])
            self.assertEqual(redirect.hostname, "127.0.0.1")
            state = query["state"][0] if statuses else "wrong-state"
            values = urlencode({"state": state, **reply})
            raw = f"GET {redirect.path}?{values} HTTP/1.0\r\nHost: {redirect.netloc}\r\n\r\n"
            client = Mock()
            client.makefile.return_value = BytesIO(raw.encode())
            server.finish_request(client, ("127.0.0.1", 8000))
            headers = client.sendall.call_args_list[0].args[0]
            statuses.append(int(headers.split()[1]))
            self.assertLessEqual(len(statuses), 2)
            if len(statuses) == 1:
                self.assertEqual(statuses[0], 400)

        with patch("vibescan.register.webbrowser.open", side_effect=open_browser), \
             patch("vibescan.register.HTTPServer.handle_request", handle_request):
            return register(path), query["ext_agent_host_id"][0]

    def test_register_once_after_denial(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp)
            with self.assertRaises(RuntimeError):
                self.run_attempt(path, {"error": "access_denied"})
            with closing(sqlite3.connect(path / "registration.sqlite3")) as db:
                host, client = db.execute("SELECT host, client FROM installation").fetchone()
            self.assertIsNone(client)
            created, reused_host = self.run_attempt(path, {"code": "test-code", "client_id": "test-id"})
            self.assertTrue(created)
            self.assertEqual(host, reused_host)
            with patch("vibescan.register.webbrowser.open") as browser:
                self.assertFalse(register(path))
                browser.assert_not_called()
            with closing(sqlite3.connect(path / "registration.sqlite3")) as db:
                self.assertEqual(db.execute("SELECT client FROM installation").fetchone(), ("test-id",))

    def test_incomplete_callbacks(self):
        for reply in ({"code": "test-code"}, {"client_id": "test-id"},
                      {"code": "test-code", "client_id": "dynamic_agent_client"}):
            with self.subTest(reply=reply), TemporaryDirectory() as tmp, self.assertRaises(RuntimeError):
                self.run_attempt(Path(tmp), reply)
