import unittest

from vulnapp.app import app


class SampleAppTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_home_exposes_expected_header_and_cookie_baseline(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("Content-Security-Policy", response.headers)
        cookie = response.headers["Set-Cookie"]
        self.assertIn("demo_session=fixture-only", cookie)
        self.assertNotIn("httponly", cookie.lower())

    def test_reviewer_fixture_allows_anonymous_read(self):
        response = self.client.get("/review")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"title": "검토용 샘플 메모"})
