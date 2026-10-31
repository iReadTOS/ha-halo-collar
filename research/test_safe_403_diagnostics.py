"""Privacy-preserving HTTP rejection diagnostics; synthetic, never online."""

import io
import unittest
import urllib.error

from live_sso_feasibility import (
    TOKEN_URL,
    ProbeError,
    _safe_rejection_hints,
    https_json,
)


class FakeRejectingOpener:
    def __init__(self, status, headers):
        self.calls = 0
        self.status = status
        self.headers = headers

    def open(self, request, timeout):
        self.calls += 1
        assert request.full_url == TOKEN_URL
        assert request.get_method() == "POST"
        assert timeout == 15
        raise urllib.error.HTTPError(
            TOKEN_URL,
            self.status,
            "private-reason",
            self.headers,
            io.BytesIO(b"private body: bearer token and sensitive errors"),
        )


class Safe403DiagnosticsTests(unittest.TestCase):
    def test_classifies_cloudflare_challenge_without_logging_headers(self):
        opener = FakeRejectingOpener(
            403,
            {
                "Content-Type": "text/html; charset=utf-8",
                "cf-mitigated": "challenge",
                "Server": "cloudflare",
                "Set-Cookie": "session=private-cookie",
                "X-Secret": "private-header",
            },
        )
        with self.assertRaises(ProbeError) as raised:
            https_json(TOKEN_URL, post={"grant_type": "synthetic"}, opener=opener)
        message = str(raised.exception)
        self.assertEqual(opener.calls, 1)
        self.assertIn("HTTP 403", message)
        self.assertIn("response=html", message)
        self.assertIn("cf_challenge=indicated", message)
        self.assertIn("cf_server=indicated", message)
        for secret in ("private", "bearer", "session", "cloudflare", "Set-Cookie"):
            self.assertNotIn(secret, message)

    def test_json_403_is_not_automatically_called_an_identity_error(self):
        opener = FakeRejectingOpener(
            403,
            {
                "Content-Type": "application/problem+json",
                "Server": "cloudflare",
            },
        )
        with self.assertRaises(ProbeError) as raised:
            https_json(TOKEN_URL, post={"grant_type": "synthetic"}, opener=opener)
        self.assertIn("response=json", str(raised.exception))
        self.assertIn("cf_challenge=not_indicated", str(raised.exception))
        self.assertEqual(opener.calls, 1)

    def test_missing_or_malicious_headers_not_echoed(self):
        self.assertEqual(
            _safe_rejection_hints({"Content-Type": "text/html\r\nprivate-secret"}),
            "response=other_or_unknown; cf_challenge=not_indicated; cf_server=not_indicated",
        )
        self.assertEqual(
            _safe_rejection_hints(None),
            "response=other_or_unknown; cf_challenge=not_indicated; cf_server=not_indicated",
        )

    def test_http_error_does_not_expose_client_secret(self):
        opener = FakeRejectingOpener(403, {"Authorization": "private-secret"})
        with self.assertRaises(ProbeError) as raised:
            https_json(
                TOKEN_URL,
                post={
                    "grant_type": "authorization_code",
                    "code": "synthetic-private-code",
                    "client_secret": "synthetic-private-secret",
                },
                opener=opener,
            )
        message = str(raised.exception)
        self.assertEqual(opener.calls, 1)
        self.assertNotIn("synthetic-private", message)
        self.assertNotIn("Authorization", message)


if __name__ == "__main__":
    unittest.main()
