"""Offline Fedora desktop-session tests; all callbacks and tokens are synthetic."""

from __future__ import annotations

import http.client
import json
import stat
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import parse_qs, urlencode, urlsplit

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from account_binding import prepare_synthetic_new_login
from desktop_sso_demo import demo_handler
from desktop_sso_session import (
    CALLBACK_URI,
    DEMO_CLIENT_ID,
    SESSION_TTL,
    SYNTHETIC_CODE,
    DesktopSessionError,
    clear_session,
    complete_session,
    get_status,
    new_session,
)
from oidc_identity import OIDC_ISSUER
from sso_oauth import pkce_s256_challenge


class FakeResponse:
    def __init__(self, data):
        self.status = 200
        self.data = data

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    async def json(self, **_kwargs):
        return self.data


class FakeSession:
    def __init__(self, payload):
        self.payload = payload
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return FakeResponse(self.payload)


class DesktopSSOSessionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name) / "private"
        self.t0 = 1_800_000_000.0
        self.request = new_session(self.folder, now=self.t0)
        self.callback = CALLBACK_URI + "?" + urlencode(
            {"code": SYNTHETIC_CODE, "state": self.request.state}
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_private_permissions_and_pkce(self):
        self.assertEqual(stat.S_IMODE(self.folder.stat().st_mode), 0o700)
        pending = self.folder / "pending.json"
        self.assertEqual(stat.S_IMODE(pending.stat().st_mode), 0o600)
        info = json.loads(pending.read_text())
        self.assertEqual(info["state"], self.request.state)
        self.assertEqual(info["nonce"], self.request.nonce)
        self.assertEqual(info["verifier"], self.request.code_verifier)
        query = parse_qs(urlsplit(self.request.authorization_url).query)
        self.assertEqual(query["client_id"], [DEMO_CLIENT_ID])
        self.assertEqual(query["code_challenge"], [pkce_s256_challenge(self.request.code_verifier)])
        self.assertEqual(query["code_challenge_method"], ["S256"])
        self.assertNotIn(self.request.code_verifier, self.request.authorization_url)
        self.assertIn("synthetic.invalid", self.request.authorization_url)
        self.assertNotIn("auth.halocollar.com", self.request.authorization_url)

    def test_valid_callback_consumed_once(self):
        completed = complete_session(self.folder, self.callback, now=self.t0 + 1)
        self.assertIsNotNone(completed)
        self.assertEqual(completed.request.nonce, self.request.nonce)
        self.assertNotIn(self.request.state, repr(completed))
        self.assertFalse((self.folder / "pending.json").exists())
        self.assertTrue(get_status(self.folder).startswith("PASS"))
        self.assertIsNone(complete_session(self.folder, self.callback, now=self.t0 + 2))
        self.assertTrue(get_status(self.folder).startswith("REJECT"))

    def test_bad_callback_does_not_consume_good_pending(self):
        bad = CALLBACK_URI + "?" + urlencode({"code": SYNTHETIC_CODE, "state": "wrong"})
        self.assertIsNone(complete_session(self.folder, bad, now=self.t0 + 1))
        self.assertTrue((self.folder / "pending.json").exists())
        self.assertIsNotNone(complete_session(self.folder, self.callback, now=self.t0 + 2))

    def test_real_looking_codes_and_extra_fields_rejected(self):
        candidates = [
            CALLBACK_URI + "?" + urlencode({"code": "real-looking-secret", "state": self.request.state}),
            self.callback + "&code=synthetic-code",
            self.callback + "&unexpected=1",
            self.callback + "#fragment",
            self.callback.replace("haloapp://callback", "haloapp://other"),
        ]
        for candidate in candidates:
            with self.subTest(candidate_length=len(candidate)):
                self.assertIsNone(complete_session(self.folder, candidate, now=self.t0 + 1))
        self.assertIsNotNone(complete_session(self.folder, self.callback, now=self.t0 + 2))
        status = get_status(self.folder)
        self.assertNotIn("real-looking-secret", status)

    def test_expired_and_backdated_callback_rejected(self):
        self.assertIsNone(complete_session(self.folder, self.callback, now=self.t0 - 1))
        self.assertIsNone(
            complete_session(self.folder, self.callback, now=self.t0 + SESSION_TTL + 1)
        )
        self.assertIsNotNone(complete_session(self.folder, self.callback, now=self.t0 + 2))

    def test_two_pending_sessions_cannot_overlap(self):
        with self.assertRaises(DesktopSessionError):
            new_session(self.folder, now=self.t0 + 1)
        self.assertIsNotNone(complete_session(self.folder, self.callback, now=self.t0 + 2))
        second = new_session(self.folder, now=self.t0 + 3)
        self.assertNotEqual(second.state, self.request.state)
        self.assertNotEqual(second.nonce, self.request.nonce)
        self.assertNotEqual(second.code_verifier, self.request.code_verifier)

    def test_clear_removes_private_session(self):
        clear_session(self.folder)
        self.assertFalse((self.folder / "pending.json").exists())
        self.assertEqual(get_status(self.folder), "No callback result yet")
        self.assertIsNone(complete_session(self.folder, self.callback, now=self.t0 + 1))

    def test_result_never_contains_code_nonce_or_verifier(self):
        complete_session(self.folder, self.callback, now=self.t0 + 1)
        status = (self.folder / "status.txt").read_text()
        for secret in (SYNTHETIC_CODE, self.request.state, self.request.nonce, self.request.code_verifier):
            self.assertNotIn(secret, status)

    def test_simultaneous_callback_can_complete_only_once(self):
        with ThreadPoolExecutor(max_workers=6) as pool:
            outcomes = list(pool.map(lambda _: complete_session(self.folder, self.callback, now=self.t0 + 1), range(6)))
        self.assertEqual(sum(item is not None for item in outcomes), 1)

    def test_loopback_server_issues_real_http_302_without_remote_requests(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), demo_handler(self.request.state))
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
            connection.request("GET", "/")
            home = connection.getresponse()
            self.assertEqual(home.status, 200)
            self.assertIn(b"synthetic", home.read())
            connection.request("GET", "/redirect")
            redirect = connection.getresponse()
            self.assertEqual(redirect.status, 302)
            self.assertEqual(redirect.getheader("Location"), self.callback)
            self.assertEqual(redirect.getheader("Cache-Control"), "no-store")
            redirect.read()
            connection.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    async def test_same_nonce_links_synthetic_callback_to_verified_identity(self):
        """No real token endpoint: test fake RS256 and in-memory fake response."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
        jwk.update({"kid": "test-key", "alg": "RS256", "use": "sig"})
        claims = {
            "iss": OIDC_ISSUER,
            "aud": DEMO_CLIENT_ID,
            "sub": "synthetic-only-subject",
            "nonce": self.request.nonce,
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "email": "fake@example.invalid",
            "email_verified": True,
        }
        signed_id_token = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "test-key"})
        fake_session = FakeSession({
            "access_token": "fake-access-token",
            "refresh_token": "fake-refresh-token",
            "id_token": signed_id_token,
            "token_type": "Bearer",
            "expires_in": 3600,
        })
        completed = complete_session(self.folder, self.callback, now=self.t0 + 1)
        self.assertIsNotNone(completed)
        # Research helper posts only to fake_session; no real HTTP connection.
        proposal = await prepare_synthetic_new_login(
            fake_session,
            auth_request=completed.request,
            callback_url=self.callback,
            trusted_jwks={"keys": [jwk]},
            client_id=DEMO_CLIENT_ID,
        )
        self.assertEqual(proposal.binding.subject, "synthetic-only-subject")
        self.assertEqual(len(fake_session.calls), 1)
        self.assertNotIn("fake-refresh-token", repr(proposal))


if __name__ == "__main__":
    unittest.main()
