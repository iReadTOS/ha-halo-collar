"""Synthetic aiohttp transport tests. No public internet or login requests."""

from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from aiohttp_token_transport import MAX_BODY, TokenTransportError, post_token_json
from live_sso_feasibility import TOKEN_URL, _safe_rejection_hints, https_json
from safe_oauth_error_code import safe_oauth_error_code

SYNTHETIC_URL = "https://example.invalid/connect/token"
FORM = {
    "grant_type": "authorization_code",
    "client_id": "synthetic-client",
    "client_secret": "private-synthetic-secret",
    "code": "private-synthetic-code",
    "code_verifier": "private-synthetic-verifier",
    "redirect_uri": "synthetic://callback",
}


class FakeBody:
    def __init__(self, data):
        self.data = data

    async def read(self, size):
        return self.data[:size]


class FakeResponse:
    def __init__(self, status, payload, content_type="application/json"):
        self.status = status
        self.content = FakeBody(payload)
        self.headers = {"Content-Type": content_type, "Server": "cloudflare"}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False


class FakeSession:
    def __init__(self, response, log):
        self.response = response
        self.log = log

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    def post(self, url, *, data, headers, allow_redirects):
        self.log.append((url, dict(data), dict(headers), allow_redirects))
        return self.response


class AiohttpTokenTransportTests(unittest.TestCase):
    def run_case(self, status, body, *, content_type="application/json"):
        calls = []
        response = FakeResponse(status, body, content_type)
        with patch(
            "aiohttp_token_transport.aiohttp.ClientSession",
            side_effect=lambda **_kw: FakeSession(response, calls),
        ):
            try:
                result = post_token_json(
                    SYNTHETIC_URL,
                    FORM,
                    classify_headers=_safe_rejection_hints,
                    classify_error=safe_oauth_error_code,
                )
                return calls, result, None
            except TokenTransportError as exc:
                return calls, None, str(exc)

    def test_probe_routes_real_default_token_post_to_aiohttp(self):
        with patch(
            "aiohttp_token_transport.post_token_json",
            return_value={"synthetic": "ok"},
        ) as mocked:
            result = https_json(TOKEN_URL, post=FORM)
        self.assertEqual(result, {"synthetic": "ok"})
        mocked.assert_called_once()
        args, kwargs = mocked.call_args
        self.assertEqual(args, (TOKEN_URL, FORM))
        self.assertTrue(callable(kwargs["classify_headers"]))
        self.assertTrue(callable(kwargs["classify_error"]))

    def test_connection_error_is_sanitized(self):
        import aiohttp

        with patch(
            "aiohttp_token_transport.aiohttp.ClientSession",
            side_effect=aiohttp.ClientConnectionError("private-synthetic-code"),
        ):
            with self.assertRaises(TokenTransportError) as raised:
                post_token_json(
                    SYNTHETIC_URL,
                    FORM,
                    classify_headers=_safe_rejection_hints,
                    classify_error=safe_oauth_error_code,
                )
        self.assertEqual(str(raised.exception), "Provider request failed or timed out")

    def test_success_and_identical_form_without_redirects(self):
        calls, value, error = self.run_case(200, b'{"synthetic":"ok"}')
        self.assertIsNone(error)
        self.assertEqual(value, {"synthetic": "ok"})
        self.assertEqual(calls, [(SYNTHETIC_URL, FORM, {"Accept": "application/json"}, False)])

    def test_oauth_rejection_is_classified_without_leaks_or_retries(self):
        body = json.dumps(
            {
                "error": "invalid_grant",
                "error_description": "private-synthetic-secret",
                "code": "private-synthetic-code",
            }
        ).encode()
        calls, value, error = self.run_case(403, body)
        self.assertIsNone(value)
        self.assertEqual(len(calls), 1)
        self.assertIn("HTTP 403", error)
        self.assertIn("oauth_error=invalid_grant", error)
        self.assertNotIn("private", error)
        self.assertNotIn("error_description", error)
        self.assertNotIn("synthetic-code", error)

    def test_nonstandard_rejection_is_not_echoed(self):
        calls, _, error = self.run_case(403, b'{"message":"sensitive-secret"}')
        self.assertEqual(len(calls), 1)
        self.assertIn("oauth_error=unrecognized", error)
        self.assertNotIn("sensitive-secret", error)

    def test_redirect_is_not_followed(self):
        calls, _, error = self.run_case(302, b"private")
        self.assertEqual(len(calls), 1)
        self.assertIn("Unexpected provider response (HTTP 302)", error)
        self.assertNotIn("private", error)

    def test_oversized_success_body_is_rejected(self):
        calls, _, error = self.run_case(200, b"x" * (MAX_BODY + 50))
        self.assertEqual(len(calls), 1)
        self.assertIn("Unexpected provider response", error)

    def test_invalid_json_is_rejected(self):
        _, _, error = self.run_case(200, b"not-json")
        self.assertEqual(error, "Provider returned invalid JSON")


if __name__ == "__main__":
    unittest.main()
