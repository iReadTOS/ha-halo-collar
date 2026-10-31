"""Fake HTTPS/OIDC token tests for explicitly encrypted probe saving."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa
from live_sso_feasibility import CALLBACK, CLIENT_ID, token_exchange, trusted_keys
from secure_token_bundle import TokenVaultError, load_bundle, prepare_destination
from sso_oauth import create_request
from test_live_sso_feasibility import FakeOpener


class EncryptedProbeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "private" / "one-session.halo-vault"
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.request = create_request(client_id=CLIENT_ID, redirect_uri=CALLBACK)
        self.opener = FakeOpener(self.key, lambda: self.request.nonce)
        self.jwks = trusted_keys(opener=self.opener)
        self.passphrase = "this-is-a-long-passphrase"

    def tearDown(self):
        self.tmp.cleanup()

    def test_verified_fake_oauth_response_is_saved_without_exposing_tokens(self):
        prepare_destination(self.path)
        self.assertTrue(
            token_exchange(
                "synthetic-temporary-code",
                self.request,
                client_secret="synthetic-app-client-secret",
                jwks=self.jwks,
                opener=self.opener,
                vault_path=self.path,
                vault_passphrase=self.passphrase,
            )
        )
        value = load_bundle(self.path, passphrase=self.passphrase)
        self.assertEqual(value["subject"], "fake-subject")
        self.assertEqual(value["access_token"], "private-access")
        self.assertEqual(value["refresh_token"], "private-refresh")
        self.assertNotIn("id_token", value)
        self.assertNotIn(b"private-access", self.path.read_bytes())
        self.assertEqual(len(self.opener.calls), 3)

    def test_missing_passphrase_cannot_succeed_or_save(self):
        with self.assertRaises(TokenVaultError):
            token_exchange(
                "synthetic-temporary-code",
                self.request,
                client_secret="synthetic-app-client-secret",
                jwks=self.jwks,
                opener=self.opener,
                vault_path=self.path,
                vault_passphrase=None,
            )
        self.assertFalse(self.path.exists())

    def test_existing_vault_rejected_in_preflight(self):
        prepare_destination(self.path)
        self.path.write_text("already saved", encoding="utf-8")
        with self.assertRaises(TokenVaultError):
            prepare_destination(self.path)


if __name__ == "__main__":
    unittest.main()
