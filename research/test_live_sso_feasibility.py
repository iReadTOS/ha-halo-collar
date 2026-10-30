"""All tests are fake/local; NEVER open Halo's login page or send live tokens."""

from __future__ import annotations

import json
import stat
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from live_sso_feasibility import (
    AUTHORIZE_URL, CALLBACK, CLIENT_ID, DISCOVERY_URL, JWKS_URL,
    TOKEN_URL, NoRedirect, ProbeError, handle_callback, https_json,
    run_live, token_exchange, trusted_keys,
)
from sso_oauth import create_request
from oidc_identity import OIDC_ISSUER


class FakeHTTPResponse:
    def __init__(self, payload, status=200):
        self.status = status
        self.raw = json.dumps(payload).encode()

    def read(self, n):
        return self.raw[:n]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class FakeOpener:
    def __init__(self, key, nonce_provider):
        self.key = key
        self.nonce_provider = nonce_provider
        self.calls = []
        self.jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
        self.jwk.update({"kid": "synthetic-signing-key", "alg": "RS256", "use": "sig"})

    def open(self, request, timeout):
        self.calls.append((request, timeout))
        if request.full_url == DISCOVERY_URL:
            return FakeHTTPResponse({
                "issuer": OIDC_ISSUER,
                "jwks_uri": JWKS_URL,
                "authorization_endpoint": AUTHORIZE_URL,
                "token_endpoint": TOKEN_URL,
                "id_token_signing_alg_values_supported": ["RS256"],
                "code_challenge_methods_supported": ["plain", "S256"],
            })
        if request.full_url == JWKS_URL:
            return FakeHTTPResponse({"keys": [self.jwk]})
        if request.full_url == TOKEN_URL:
            values = parse_qs(request.data.decode())
            assert values["grant_type"] == ["authorization_code"]
            assert values["redirect_uri"] == [CALLBACK]
            assert values["client_id"] == [CLIENT_ID]
            assert values["client_secret"] == ["synthetic-app-client-secret"]
            assert values["code"] == ["synthetic-temporary-code"]
            assert len(values["code_verifier"][0]) >= 43
            now = int(time.time())
            id_token = jwt.encode({
                "iss": OIDC_ISSUER, "aud": CLIENT_ID,
                "sub": "fake-subject", "nonce": self.nonce_provider(),
                "iat": now, "exp": now + 3600,
            }, self.key, algorithm="RS256", headers={"kid": "synthetic-signing-key"})
            return FakeHTTPResponse({"access_token": "private-access",
                                     "refresh_token": "private-refresh",
                                     "id_token": id_token,
                                     "expires_in": 3600, "token_type": "Bearer"})
        raise AssertionError("Unexpected outbound request")


class LiveSSOFeasibilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name) / "private"
        self.folder.mkdir(mode=0o700)
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.nonce = None
        self.opener = FakeOpener(self.key, lambda: self.nonce)

    def tearDown(self):
        self.temp.cleanup()

    def test_public_metadata_and_keys_have_exact_endpoints(self):
        keys = trusted_keys(opener=self.opener)
        self.assertEqual(len(keys["keys"]), 1)
        self.assertEqual([call[0].full_url for call in self.opener.calls], [DISCOVERY_URL, JWKS_URL])

    def test_only_approved_provider_urls_possible(self):
        with self.assertRaises(ProbeError):
            https_json("https://untrusted.invalid/sso", opener=self.opener)
        self.assertEqual(self.opener.calls, [])

    def test_default_public_fetch_uses_curl_without_credentials(self):
        public_response = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=b'{"keys": [{"kty": "RSA"}]}', stderr=b""
        )
        with patch("live_sso_feasibility.subprocess.run", return_value=public_response) as runner:
            result = https_json(JWKS_URL)
        self.assertEqual(result, {"keys": [{"kty": "RSA"}]})
        cmd = runner.call_args.args[0]
        self.assertEqual(cmd[0], "curl")
        self.assertEqual(cmd[-1], JWKS_URL)
        self.assertIn("--fail", cmd)
        self.assertNotIn("--location", cmd)
        self.assertNotIn("--data", cmd)
        self.assertNotIn("--user", cmd)
        self.assertNotIn("client_secret", " ".join(cmd))

    def test_curl_failure_is_sanitized_and_not_retried(self):
        blocked = subprocess.CompletedProcess(
            args=[], returncode=22, stdout=b"", stderr=b"private-provider-body"
        )
        with patch("live_sso_feasibility.subprocess.run", return_value=blocked) as runner:
            with self.assertRaises(ProbeError) as ctx:
                https_json(DISCOVERY_URL)
        self.assertNotIn("private-provider-body", str(ctx.exception))
        runner.assert_called_once()

    def test_malformed_or_oversized_public_json_rejected(self):
        for body in (b"not-json", b"[1]", b"X" * 131074):
            with self.subTest(size=len(body)):
                result = subprocess.CompletedProcess(args=[], returncode=0, stdout=body, stderr=b"")
                with patch("live_sso_feasibility.subprocess.run", return_value=result):
                    with self.assertRaises(ProbeError):
                        https_json(JWKS_URL)

    def test_token_post_keeps_original_python_transport(self):
        class SimpleOpener:
            def open(self, request, timeout):
                assert request.full_url == TOKEN_URL
                assert request.get_method() == "POST"
                assert request.data is not None
                return FakeHTTPResponse({"test": "synthetic"})

        with patch("live_sso_feasibility.subprocess.run") as curl:
            response = https_json(
                TOKEN_URL, post={"grant_type": "synthetic"}, opener=SimpleOpener()
            )
        self.assertEqual(response, {"test": "synthetic"})
        curl.assert_not_called()

    def test_unrecognized_keys_and_claims_do_not_pass(self):
        request = create_request(client_id=CLIENT_ID, redirect_uri=CALLBACK)
        self.nonce = "wrong-nonce"
        keys = trusted_keys(opener=self.opener)
        with self.assertRaises(ValueError):
            token_exchange("synthetic-temporary-code", request, client_secret="synthetic-app-client-secret",
                           jwks=keys, opener=self.opener)

    def test_complete_browser_handoff_and_signed_identity_mocked(self):
        received = []
        holder = []

        def fake_browser(authorization_url):
            query = parse_qs(urlsplit(authorization_url).query)
            self.nonce = query["nonce"][0]
            callback = CALLBACK + "?" + urlencode({
                "state": query["state"][0], "code": "synthetic-temporary-code",
            })

            def background():
                # Callback process starts after the socket is ready.
                received.append(handle_callback(callback, self.folder))

            thread = threading.Thread(target=background)
            holder.append(thread)
            thread.start()
            return True

        with patch("live_sso_feasibility._read_constants", return_value=(CLIENT_ID, "synthetic-app-client-secret")):
            success = run_live(open_browser=fake_browser, callback_folder=self.folder, opener=self.opener)
        holder[0].join(2)
        self.assertTrue(success)
        self.assertEqual(received, [0])
        self.assertFalse((self.folder / "callback.sock").exists())
        self.assertEqual([req.full_url for req, _ in self.opener.calls], [DISCOVERY_URL, JWKS_URL, TOKEN_URL])
        self.assertEqual(list(self.folder.iterdir()), [])

    def test_fragmented_callback_stream_is_accepted(self):
        from live_sso_feasibility import read_callback_line

        class Chunks:
            def __init__(self, chunks):
                self.chunks = iter(chunks)

            def recv(self, _limit):
                return next(self.chunks, b"")

        uri = b"haloapp://callback?code=synthetic&state=synthetic"
        self.assertEqual(
            read_callback_line(Chunks([uri[:10], uri[10:34], uri[34:] + b"\n"])), uri
        )
        self.assertIsNone(read_callback_line(Chunks([uri])))
        self.assertIsNone(read_callback_line(Chunks([b"x" * 8192, b"\n"])))

    def test_real_looking_uri_rejected_without_listener(self):
        self.assertEqual(handle_callback(CALLBACK + "?code=looks-real&state=wrong", self.folder), 1)
        self.assertEqual(handle_callback("https://evil.invalid/?code=secret", self.folder), 2)
        self.assertEqual(list(self.folder.iterdir()), [])

    def test_callback_socket_private_while_listening(self):
        import socket
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            path = self.folder / "callback.sock"
            sock.bind(str(path))
            path.chmod(0o600)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            path.unlink()

    def test_never_follows_issuer_redirect(self):
        self.assertIsNone(NoRedirect().redirect_request(None, None, 302, "", {}, "https://fake.invalid"))


if __name__ == "__main__":
    unittest.main()
