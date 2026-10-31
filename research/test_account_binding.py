"""Offline account-linking tests: fake HTTP session and ephemeral RSA keys ONLY."""

from __future__ import annotations

import json
import time
import unittest
from dataclasses import replace
from urllib.parse import urlencode

import jwt
from account_binding import (
    AccountBinding,
    AccountBindingError,
    EntrySnapshot,
    PreparedSSOLogin,
    assert_unchanged_before_reauth_commit,
    prepare_synthetic_new_login,
    prepare_synthetic_same_account_reauth,
)
from cryptography.hazmat.primitives.asymmetric import rsa
from oidc_identity import OIDC_ISSUER, IDTokenValidationError
from sso_oauth import OAuthResponseError, create_request
from token_exchange import TokenExchangeError


class FakeResponse:
    def __init__(self, data: dict, status: int = 200):
        self.data = data
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    async def json(self, *, content_type=None):
        return self.data


class FakeSession:
    def __init__(self, response: FakeResponse):
        self.response = response
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.response


class AccountBindingTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(cls.signing_key.public_key()))
        public_jwk.update({"kid": "test-key", "alg": "RS256", "use": "sig"})
        cls.jwks = {"keys": [public_jwk]}

    def setUp(self):
        self.request = create_request(
            client_id="halo.app.android", redirect_uri="https://example.invalid/oidc-callback"
        )
        self.callback = (
            self.request.redirect_uri
            + "?"
            + urlencode({"code": "synthetic-secret-code", "state": self.request.state})
        )
        self.saved = AccountBinding(OIDC_ISSUER, "subject-a", "halo.app.android")
        self.original = EntrySnapshot("entry-one", self.saved, "revision-one")
        self.current = self.original

    def signed_token(self, **overrides):
        now = int(time.time())
        claims = {
            "iss": OIDC_ISSUER,
            "sub": "subject-a",
            "aud": "halo.app.android",
            "iat": now,
            "exp": now + 3600,
            "nonce": self.request.nonce,
            "email": "shared@example.invalid",
            "email_verified": True,
        }
        key = overrides.pop("signing_key", self.signing_key)
        claims.update(overrides)
        return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "test-key"})

    def session(self, id_token=None, **kwargs):
        payload = {
            "access_token": "synthetic-access-private",
            "refresh_token": "synthetic-refresh-private",
            "id_token": self.signed_token() if id_token is None else id_token,
            "expires_in": 3600,
            "token_type": "Bearer",
            **kwargs,
        }
        return FakeSession(FakeResponse(payload))

    async def new_login(self, session, **kwargs):
        return await prepare_synthetic_new_login(
            session,
            auth_request=self.request,
            callback_url=kwargs.get("callback_url", self.callback),
            trusted_jwks=kwargs.get("trusted_jwks", self.jwks),
            client_id=kwargs.get("client_id", "halo.app.android"),
        )

    async def reauth(self, session, **kwargs):
        return await prepare_synthetic_same_account_reauth(
            session,
            original=kwargs.get("original", self.original),
            auth_request=self.request,
            callback_url=kwargs.get("callback_url", self.callback),
            trusted_jwks=kwargs.get("trusted_jwks", self.jwks),
            client_id=kwargs.get("client_id", "halo.app.android"),
        )

    async def test_new_login_produces_a_proposal_only(self):
        session = self.session()
        proposal = await self.new_login(session)
        self.assertIsInstance(proposal, PreparedSSOLogin)
        self.assertEqual(proposal.binding, self.saved)
        self.assertEqual(len(session.calls), 1)
        self.assertEqual(session.calls[0][1]["data"]["code_verifier"], self.request.code_verifier)

    async def test_same_account_reauth_and_commit_guard_accept_unchanged_entry(self):
        proposal = await self.reauth(self.session())
        assert_unchanged_before_reauth_commit(
            proposal, original=self.original, current=self.current
        )
        self.assertEqual(proposal.binding, self.saved)

    async def test_changed_email_is_not_a_different_subject(self):
        session = self.session(self.signed_token(email="updated@example.invalid"))
        proposal = await self.reauth(session)
        self.assertEqual(proposal.binding, self.saved)

    async def test_unverified_email_is_not_a_stable_identity(self):
        session = self.session(self.signed_token(email_verified=False))
        proposal = await self.reauth(session)
        self.assertEqual(proposal.binding, self.saved)

    async def test_same_email_but_different_subject_is_rejected(self):
        session = self.session(self.signed_token(sub="subject-b"))
        with self.assertRaises(AccountBindingError) as ctx:
            await self.reauth(session)
        self.assertNotIn("subject-b", str(ctx.exception))
        self.assertEqual(len(session.calls), 1)

    async def test_legacy_password_only_entry_rejected_before_token_exchange(self):
        original = EntrySnapshot("entry-one", None, "revision-one")
        session = self.session()
        with self.assertRaises(AccountBindingError):
            await self.reauth(session, original=original)
        self.assertEqual(session.calls, [])

    async def test_different_client_rejected_before_exchange(self):
        session = self.session()
        with self.assertRaises(AccountBindingError):
            await self.reauth(session, client_id="another-client")
        self.assertEqual(session.calls, [])

    async def test_invalid_callback_never_exchanges_code(self):
        session = self.session()
        with self.assertRaises(OAuthResponseError):
            await self.reauth(
                session, callback_url=self.request.redirect_uri + "?code=x&state=wrong"
            )
        self.assertEqual(session.calls, [])

    async def test_bad_signature_cannot_propose_account(self):
        session = self.session(self.signed_token(signing_key=self.other_key))
        with self.assertRaises(IDTokenValidationError):
            await self.reauth(session)
        self.assertEqual(len(session.calls), 1)

    async def test_wrong_nonce_cannot_propose_account(self):
        session = self.session(self.signed_token(nonce="wrong-nonce"))
        with self.assertRaises(IDTokenValidationError):
            await self.reauth(session)

    async def test_wrong_audience_cannot_propose_account(self):
        session = self.session(self.signed_token(aud="wrong-client"))
        with self.assertRaises(IDTokenValidationError):
            await self.reauth(session)

    async def test_wrong_issuer_cannot_propose_account(self):
        session = self.session(self.signed_token(iss="https://wrong.invalid"))
        with self.assertRaises(IDTokenValidationError):
            await self.reauth(session)

    async def test_expired_token_cannot_propose_account(self):
        session = self.session(self.signed_token(exp=int(time.time()) - 100))
        with self.assertRaises(IDTokenValidationError):
            await self.reauth(session)

    async def test_malformed_token_response_cannot_propose_account(self):
        session = self.session(id_token="not-a-jwt")
        with self.assertRaises(IDTokenValidationError):
            await self.reauth(session)
        session = self.session(refresh_token="")
        with self.assertRaises(TokenExchangeError):
            await self.reauth(session)

    async def test_commit_guard_rejects_entry_replacement(self):
        proposal = await self.reauth(self.session())
        changed = replace(self.original, entry_id="new-entry")
        with self.assertRaises(AccountBindingError):
            assert_unchanged_before_reauth_commit(proposal, original=self.original, current=changed)

    async def test_commit_guard_rejects_concurrent_credential_rotation(self):
        proposal = await self.reauth(self.session())
        changed = replace(self.original, revision="newer-credentials")
        with self.assertRaises(AccountBindingError):
            assert_unchanged_before_reauth_commit(proposal, original=self.original, current=changed)

    async def test_commit_guard_rejects_replacement_account(self):
        proposal = await self.reauth(self.session())
        changed = replace(
            self.original,
            binding=AccountBinding(OIDC_ISSUER, "subject-b", "halo.app.android"),
        )
        with self.assertRaises(AccountBindingError):
            assert_unchanged_before_reauth_commit(proposal, original=self.original, current=changed)

    async def test_commit_guard_rejects_wrong_proposed_identity(self):
        proposal = await self.new_login(self.session(self.signed_token(sub="subject-b")))
        with self.assertRaises(AccountBindingError):
            assert_unchanged_before_reauth_commit(
                proposal, original=self.original, current=self.original
            )

    async def test_repr_redacts_tokens_and_identity(self):
        proposal = await self.new_login(self.session())
        shown = repr(proposal) + repr(proposal.binding) + repr(self.original)
        for secret in (
            "subject-a",
            "synthetic-access-private",
            "synthetic-refresh-private",
            "entry-one",
        ):
            self.assertNotIn(secret, shown)

    def test_binding_rejects_untrusted_issuer_and_empty_subject(self):
        with self.assertRaises(AccountBindingError):
            AccountBinding("https://wrong.invalid", "subject-a", "halo.app.android")
        with self.assertRaises(AccountBindingError):
            AccountBinding(OIDC_ISSUER, "  ", "halo.app.android")


if __name__ == "__main__":
    unittest.main()
