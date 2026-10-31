"""Purely synthetic redirect probe tests; never contact Halo."""

from __future__ import annotations

import unittest
from urllib.parse import parse_qs, urlsplit

from redirect_probe import (
    CLIENT_ID,
    HOME_ASSISTANT_REDIRECT,
    OFFICIAL_REDIRECT,
    ProbeResult,
    StopRedirects,
    classify_response,
    make_authorize_url,
    probe,
)


class FakeResponse:
    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self.body = body

    def read(self, n: int) -> bytes:
        return self.body[:n]

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class FakeOpener:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        return self.response


class RedirectProbeTests(unittest.TestCase):
    def test_request_matches_official_client_and_pkce(self):
        url = make_authorize_url(OFFICIAL_REDIRECT)
        params = parse_qs(urlsplit(url).query)
        self.assertEqual(params["client_id"], [CLIENT_ID])
        self.assertEqual(params["redirect_uri"], [OFFICIAL_REDIRECT])
        self.assertEqual(params["response_type"], ["code"])
        self.assertEqual(params["code_challenge_method"], ["S256"])
        self.assertEqual(len(params["code_challenge"][0]), 43)
        self.assertIn("offline_access", params["scope"][0])
        self.assertNotIn("client_secret", params)

    def test_creates_fresh_state_and_pkce_challenge(self):
        a = parse_qs(urlsplit(make_authorize_url(HOME_ASSISTANT_REDIRECT)).query)
        b = parse_qs(urlsplit(make_authorize_url(HOME_ASSISTANT_REDIRECT)).query)
        for field in ("state", "nonce", "code_challenge"):
            self.assertNotEqual(a[field], b[field])

    def test_does_not_follow_redirects(self):
        self.assertIsNone(
            StopRedirects().redirect_request(None, None, 302, "", {}, "https://example.invalid")
        )

    def test_classifies_explicit_invalid_redirect(self):
        self.assertEqual(
            classify_response(400, b"<h1>Invalid redirect_uri</h1>"),
            ProbeResult(400, "redirect_rejected"),
        )

    def test_classifies_unauthorized_client(self):
        self.assertEqual(
            classify_response(400, b'{"error":"unauthorized_client"}').signal,
            "client_not_authorized",
        )

    def test_does_not_claim_login_redirect_proves_registration(self):
        self.assertEqual(classify_response(302, b"").signal, "redirect_not_followed_unverified")

    def test_does_not_claim_http_200_proves_registration(self):
        self.assertEqual(
            classify_response(200, b"<html>Sign in</html>").signal, "non_error_unverified"
        )

    def test_generic_bad_request_not_misclassified_as_invalid_redirect(self):
        self.assertEqual(classify_response(400, b"bad scope").signal, "rejected_reason_unknown")

    def test_sends_single_get_and_never_prints_provider_body(self):
        fake = FakeOpener(FakeResponse(200, b"fake-private-token"))
        result = probe(HOME_ASSISTANT_REDIRECT, opener=fake)
        self.assertEqual(result, ProbeResult(200, "non_error_unverified"))
        self.assertEqual(len(fake.requests), 1)
        request, timeout = fake.requests[0]
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(timeout, 12)
        self.assertNotIn("fake-private-token", repr(result))


if __name__ == "__main__":
    unittest.main()
