"""No Halo access: synthetic tokens and identities only."""
from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path

from oidc_identity import OIDC_ISSUER, VerifiedOIDCIdentity
from secure_token_bundle import TokenVaultError, load_bundle, save_verified_bundle
from token_exchange import OAuthTokens


class SecureTokenBundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "private" / "verified-sso.halo-vault"
        self.identity = VerifiedOIDCIdentity(
            issuer=OIDC_ISSUER, subject="synthetic-sub", email="fake@example.invalid", email_verified=True
        )
        self.tokens = OAuthTokens(
            access_token="fake-access-123", refresh_token="fake-refresh-123",
            id_token="fake-id-token", expires_in=3600.0
        )
        self.passphrase = "this-is-a-long-test-passphrase"

    def tearDown(self):
        self.tmp.cleanup()

    def store(self):
        save_verified_bundle(
            self.path, passphrase=self.passphrase, identity=self.identity,
            tokens=self.tokens, client_id="halo.app.android", now=1800000000.0
        )

    def test_save_and_read_private_bundle(self):
        self.store()
        self.assertEqual(stat.S_IMODE(self.path.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        content = self.path.read_bytes()
        for value in (b"fake-access-123", b"fake-refresh-123", b"synthetic-sub", b"fake-id-token"):
            self.assertNotIn(value, content)
        saved = load_bundle(self.path, passphrase=self.passphrase)
        self.assertEqual(saved["subject"], "synthetic-sub")
        self.assertEqual(saved["access_token"], "fake-access-123")
        self.assertEqual(saved["refresh_token"], "fake-refresh-123")
        self.assertEqual(saved["expires_at"], 1800003540.0)
        self.assertNotIn("id_token", saved)

    def test_wrong_passphrase_fails_safely(self):
        self.store()
        with self.assertRaisesRegex(TokenVaultError, "Incorrect passphrase") as ctx:
            load_bundle(self.path, passphrase="different-long-passphrase")
        self.assertNotIn("fake-access", str(ctx.exception))

    def test_existing_bundle_not_overwritten(self):
        self.store()
        original = self.path.read_bytes()
        with self.assertRaisesRegex(TokenVaultError, "already exists"):
            self.store()
        self.assertEqual(self.path.read_bytes(), original)

    def test_tampering_fails(self):
        self.store()
        content = bytearray(self.path.read_bytes())
        content[-1] ^= 1
        self.path.write_bytes(content)
        with self.assertRaises(TokenVaultError):
            load_bundle(self.path, passphrase=self.passphrase)

    def test_symlink_file_rejected(self):
        self.path.parent.mkdir(mode=0o700)
        secret = self.path.parent / "actual"
        secret.write_bytes(b"not-a-token")
        secret.chmod(0o600)
        self.path.symlink_to(secret)
        with self.assertRaises(TokenVaultError):
            load_bundle(self.path, passphrase=self.passphrase)
        with self.assertRaises(TokenVaultError):
            self.store()

    def test_insecure_directory_and_file_rejected(self):
        self.store()
        self.path.chmod(0o644)
        with self.assertRaises(TokenVaultError):
            load_bundle(self.path, passphrase=self.passphrase)
        self.path.chmod(0o600)
        self.path.parent.chmod(0o755)
        with self.assertRaises(TokenVaultError):
            load_bundle(self.path, passphrase=self.passphrase)

    def test_unverified_email_is_not_persisted(self):
        self.identity = VerifiedOIDCIdentity(
            issuer=OIDC_ISSUER, subject="test-only", email="unverified@example.invalid", email_verified=False
        )
        self.store()
        saved = load_bundle(self.path, passphrase=self.passphrase)
        self.assertIsNone(saved["email"])
        self.assertFalse(saved["email_verified"])

    def test_short_passphrase_rejected_before_writing(self):
        with self.assertRaises(TokenVaultError):
            save_verified_bundle(self.path, passphrase="too-short", identity=self.identity,
                tokens=self.tokens, client_id="halo.app.android")
        self.assertFalse(self.path.exists())

    def test_wrong_client_rejected(self):
        with self.assertRaises(TokenVaultError):
            save_verified_bundle(self.path, passphrase=self.passphrase, identity=self.identity,
                tokens=self.tokens, client_id="unknown-client")
        self.assertFalse(self.path.exists())


if __name__ == "__main__":
    unittest.main()
