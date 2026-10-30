"""Offline-only OIDC verification tests with ephemeral synthetic RSA signing keys."""

from __future__ import annotations

import json
import time
import unittest

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from oidc_identity import (
    IDTokenValidationError,
    OIDC_ISSUER,
    VerifiedOIDCIdentity,
    verify_id_token,
)


class OIDCIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(cls.key.public_key()))
        cls.jwk.update({"kid": "synthetic-key-1", "use": "sig", "alg": "RS256"})
        cls.jwks = {"keys": [cls.jwk]}
        cls.now = int(time.time())
        cls.claims = {
            "iss": OIDC_ISSUER,
            "sub": "synthetic-subject",
            "aud": "halo.app.android",
            "exp": cls.now + 3600,
            "iat": cls.now,
            "nonce": "synthetic-nonce",
            "email": "synthetic@example.invalid",
            "email_verified": True,
        }

    def sign(self, claims=None, *, key=None, kid="synthetic-key-1", alg="RS256"):
        return jwt.encode(
            self.claims if claims is None else claims,
            self.key if key is None else key,
            algorithm=alg,
            headers={"kid": kid},
        )

    def verify(self, token, *, jwks=None, nonce="synthetic-nonce", client="halo.app.android"):
        return verify_id_token(
            token,
            jwks=self.jwks if jwks is None else jwks,
            client_id=client,
            expected_nonce=nonce,
        )

    def test_accepts_signed_valid_identity(self):
        result = self.verify(self.sign())
        self.assertEqual(result.subject, "synthetic-subject")
        self.assertEqual(result.email, "synthetic@example.invalid")
        self.assertTrue(result.email_verified)
        self.assertIsInstance(result, VerifiedOIDCIdentity)
        self.assertNotIn("synthetic-subject", repr(result))
        self.assertNotIn("synthetic@example.invalid", repr(result))

    def test_rejects_bad_signature(self):
        with self.assertRaises(IDTokenValidationError):
            self.verify(self.sign(key=self.other_key))

    def test_rejects_wrong_nonce(self):
        with self.assertRaises(IDTokenValidationError):
            self.verify(self.sign(), nonce="other")

    def test_rejects_wrong_issuer_or_audience(self):
        for change in ({"iss": "https://evil.invalid"}, {"aud": "other-client"}):
            with self.subTest(change=change), self.assertRaises(IDTokenValidationError):
                self.verify(self.sign({**self.claims, **change}))

    def test_rejects_expired_or_future_issued_tokens(self):
        for change in ({"exp": self.now - 60}, {"iat": self.now + 120}):
            with self.subTest(change=change), self.assertRaises(IDTokenValidationError):
                self.verify(self.sign({**self.claims, **change}))

    def test_rejects_missing_claims(self):
        for name in ("iss", "sub", "aud", "exp", "iat", "nonce"):
            with self.subTest(name=name), self.assertRaises(IDTokenValidationError):
                self.verify(self.sign({k: v for k, v in self.claims.items() if k != name}))

    def test_rejects_none_or_empty_subject(self):
        for sub in (None, "", "  ", 123):
            with self.subTest(sub=sub), self.assertRaises(IDTokenValidationError):
                self.verify(self.sign({**self.claims, "sub": sub}))

    def test_rejects_unknown_or_duplicate_kid(self):
        with self.assertRaises(IDTokenValidationError):
            self.verify(self.sign(kid="not-registered"))
        with self.assertRaises(IDTokenValidationError):
            self.verify(self.sign(), jwks={"keys": [self.jwk, self.jwk]})

    def test_rejects_unacceptable_key_parameters(self):
        for change in ({"use": "enc"}, {"kty": "oct"}, {"alg": "HS256"}):
            with self.subTest(change=change), self.assertRaises(IDTokenValidationError):
                self.verify(self.sign(), jwks={"keys": [{**self.jwk, **change}]})

    def test_rejects_unacceptable_signature_algorithm(self):
        with self.assertRaises(IDTokenValidationError):
            self.verify(self.sign(alg="RS512"))

    def test_rejects_multi_audience_without_matching_azp(self):
        multi = {**self.claims, "aud": ["halo.app.android", "other-client"]}
        with self.assertRaises(IDTokenValidationError):
            self.verify(self.sign(multi))
        with self.assertRaises(IDTokenValidationError):
            self.verify(self.sign({**multi, "azp": "other-client"}))
        ok = self.verify(self.sign({**multi, "azp": "halo.app.android"}))
        self.assertEqual(ok.subject, "synthetic-subject")

    def test_email_is_not_assumed_verified(self):
        for changes in ({"email_verified": False}, {"email_verified": None}):
            self.assertFalse(self.verify(self.sign({**self.claims, **changes})).email_verified)
        c = {k: v for k, v in self.claims.items() if k not in ("email", "email_verified")}
        ident = self.verify(self.sign(c))
        self.assertIsNone(ident.email)
        self.assertFalse(ident.email_verified)

    def test_rejects_invalid_email_claim_type(self):
        with self.assertRaises(IDTokenValidationError):
            self.verify(self.sign({**self.claims, "email": ["synthetic@example.invalid"]}))

    def test_invalid_or_oversized_token_fails_without_echo(self):
        for value in ("synthetic-secret", "a" * 16400, None):
            with self.subTest(value=str(value)[:15]):
                with self.assertRaises(IDTokenValidationError) as ctx:
                    self.verify(value)
                self.assertNotIn("synthetic-secret", str(ctx.exception))

    def test_untrusted_provider_issuer_override_rejected(self):
        with self.assertRaises(IDTokenValidationError):
            verify_id_token(
                self.sign(),
                jwks=self.jwks,
                client_id="halo.app.android",
                expected_nonce="synthetic-nonce",
                issuer="https://attacker.invalid",
            )


if __name__ == "__main__":
    unittest.main()
