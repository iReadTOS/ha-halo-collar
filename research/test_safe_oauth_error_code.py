"""Synthetic tests only: no network, OAuth login, or Halo account involved."""

from __future__ import annotations

import io
import json
import unittest
import urllib.error

from live_sso_feasibility import TOKEN_URL, ProbeError, https_json
from safe_oauth_error_code import MAX_ERROR_BYTES, safe_oauth_error_code


class RejectingOpener:
    def __init__(self, status: int, data: bytes, *, content_type="application/json"):
        self.status = status
        self.data = data
        self.content_type = content_type
        self.calls = 0

    def open(self, request, timeout):
        self.calls += 1
        assert request.full_url == TOKEN_URL
        assert request.get_method() == "POST"
        assert timeout == 15
        raise urllib.error.HTTPError(
            TOKEN_URL,
            self.status,
            "private reason not for logs",
            {"Content-Type": self.content_type, "Server": "cloudflare"},
            io.BytesIO(self.data),
        )


class OAuthErrorCodeTests(unittest.TestCase):
    def _diagnose(self, body: bytes, *, status=403, content_type="application/json"):
        opener = RejectingOpener(status, body, content_type=content_type)
        with self.assertRaises(ProbeError) as cm:
            https_json(TOKEN_URL, post={"grant_type": "synthetic"}, opener=opener)
        self.assertEqual(opener.calls, 1)
        return str(cm.exception)

    def test_known_oauth_codes_only(self):
        for code in (
            "invalid_client",
            "invalid_grant",
            "unauthorized_client",
            "unsupported_grant_type",
            "invalid_request",
            "access_denied",
        ):
            with self.subTest(code=code):
                body = json.dumps(
                    {
                        "error": code,
                        "error_description": "private access token and account details",
                        "error_uri": "https://private.invalid/secret",
                        "refresh_token": "never-show-this-token",
                    }
                ).encode()
                result = self._diagnose(body)
                self.assertIn("oauth_error=" + code, result)
                for secret in (
                    "private",
                    "never-show",
                    "access token",
                    "error_description",
                    "error_uri",
                ):
                    self.assertNotIn(secret, result)

    def test_nonstandard_error_and_raw_text_are_never_echoed(self):
        result = self._diagnose(b'{"error":"top-secret-internal-error","message":"sensitive"}')
        self.assertIn("oauth_error=unrecognized", result)
        self.assertNotIn("top-secret", result)
        self.assertNotIn("sensitive", result)

    def test_html_is_not_parsed_or_displayed(self):
        result = self._diagnose(b"<html>private cookies and code</html>", content_type="text/html")
        self.assertIn("oauth_error=not_json", result)
        self.assertNotIn("cookies", result)

    def test_bounded_body_never_reaches_parser(self):
        result = self._diagnose(b"X" * (MAX_ERROR_BYTES + 100))
        self.assertIn("oauth_error=unavailable", result)

    def test_invalid_json_and_missing_error_are_not_guessed(self):
        for body in (b"not-json", b"[]", b"{}", b'{"error": {"private": 1}}'):
            with self.subTest(body_length=len(body)):
                self.assertIn("oauth_error=unrecognized", self._diagnose(body))

    def test_unreadable_body_fails_closed(self):
        class UnreadableBody:
            headers = {"Content-Type": "application/json"}

            def read(self, _n):
                raise OSError("private-transport-error")

        self.assertEqual(safe_oauth_error_code(UnreadableBody()), "unavailable")


if __name__ == "__main__":
    unittest.main()
