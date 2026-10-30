"""Fake-session-only token-exchange tests; never contact Halo."""

from __future__ import annotations

import asyncio
import unittest
from urllib.parse import urlencode

from sso_oauth import OAuthResponseError, create_request
from token_exchange import (
    TOKEN_ENDPOINT,
    OAuthTokens,
    TokenExchangeError,
    build_exchange_data,
    exchange_synthetic_callback,
    parse_token_response,
)


class FakeResponse:
    def __init__(self, *, status=200, payload=None):
        self.status = status
        self.payload = payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    async def json(self, *, content_type=None):
        return self.payload


class FakeSession:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.response


def synthetic_tokens():
    return {
        "access_token": "synthetic-access-secret",
        "refresh_token": "synthetic-refresh-secret",
        "id_token": "synthetic-id-secret",
        "expires_in": 3600,
        "token_type": "Bearer",
    }


class TokenExchangeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.auth = create_request(
            client_id="halo.app.android", redirect_uri="https://example.invalid/callback"
        )
        self.callback = self.auth.redirect_uri + "?" + urlencode(
            {"code": "synthetic-code-secret", "state": self.auth.state}
        )
        self.session = FakeSession(FakeResponse(payload=synthetic_tokens()))

    async def test_success_posts_code_and_original_pkce_once(self):
        result = await exchange_synthetic_callback(
            self.session,
            auth_request=self.auth,
            callback_url=self.callback,
            client_id="halo.app.android",
            client_secret="synthetic-app-secret",
        )
        self.assertIsInstance(result, OAuthTokens)
        self.assertEqual(len(self.session.calls), 1)
        url, kwargs = self.session.calls[0]
        self.assertEqual(url, TOKEN_ENDPOINT)
        self.assertFalse(kwargs["allow_redirects"])
        self.assertEqual(kwargs["data"]["code_verifier"], self.auth.code_verifier)
        self.assertEqual(kwargs["data"]["code"], "synthetic-code-secret")
        self.assertEqual(kwargs["data"]["redirect_uri"], self.auth.redirect_uri)
        self.assertEqual(kwargs["data"]["grant_type"], "authorization_code")
        self.assertEqual(kwargs["data"]["client_secret"], "synthetic-app-secret")

    async def test_wrong_state_sends_no_request(self):
        with self.assertRaises(OAuthResponseError):
            await exchange_synthetic_callback(
                self.session,
                auth_request=self.auth,
                callback_url=self.auth.redirect_uri + "?state=wrong&code=secret",
                client_id="halo.app.android",
            )
        self.assertEqual(self.session.calls, [])

    async def test_callback_mismatch_sends_no_request(self):
        with self.assertRaises(OAuthResponseError):
            await exchange_synthetic_callback(
                self.session,
                auth_request=self.auth,
                callback_url="https://wrong.invalid/callback?code=secret&state=" + self.auth.state,
                client_id="halo.app.android",
            )
        self.assertEqual(self.session.calls, [])

    async def test_provider_error_does_not_expose_response(self):
        self.session.response = FakeResponse(status=403, payload={"error": "private-sensitive-text"})
        with self.assertRaises(TokenExchangeError) as context:
            await exchange_synthetic_callback(
                self.session,
                auth_request=self.auth,
                callback_url=self.callback,
                client_id="halo.app.android",
            )
        self.assertNotIn("private-sensitive-text", str(context.exception))
        self.assertNotIn("synthetic-code-secret", str(context.exception))

    async def test_tokens_are_redacted_in_repr(self):
        tokens = await exchange_synthetic_callback(
            self.session,
            auth_request=self.auth,
            callback_url=self.callback,
            client_id="halo.app.android",
        )
        self.assertNotIn("synthetic-access-secret", repr(tokens))
        self.assertNotIn("synthetic-refresh-secret", repr(tokens))
        self.assertNotIn("synthetic-id-secret", repr(tokens))

    def test_rejects_boolean_and_invalid_lifetime(self):
        for lifetime in (True, 0, 60, float("nan"), float("inf"), "3600"):
            with self.subTest(lifetime=lifetime):
                payload = synthetic_tokens()
                payload["expires_in"] = lifetime
                with self.assertRaises(TokenExchangeError):
                    parse_token_response(200, payload)

    def test_rejects_missing_id_token_or_refresh_token(self):
        for key in ("id_token", "refresh_token", "access_token"):
            with self.subTest(key=key):
                payload = synthetic_tokens()
                del payload[key]
                with self.assertRaises(TokenExchangeError):
                    parse_token_response(200, payload)

    def test_rejects_bad_type(self):
        payload = synthetic_tokens()
        payload["token_type"] = "mac"
        with self.assertRaises(TokenExchangeError):
            parse_token_response(200, payload)

    def test_rejects_invalid_pkce_verifier(self):
        from dataclasses import replace

        wrong = replace(self.auth, code_verifier="too short")
        with self.assertRaises(TokenExchangeError):
            build_exchange_data(
                auth_request=wrong, authorization_code="synthetic", client_id="halo.app.android"
            )

    def test_rejects_bad_authorization_code(self):
        for code in ("", "\nsecret", "a" * 4097):
            with self.subTest(code_length=len(code)):
                with self.assertRaises(TokenExchangeError):
                    build_exchange_data(
                        auth_request=self.auth, authorization_code=code, client_id="halo.app.android"
                    )

    def test_data_excludes_secret_when_not_supplied(self):
        result = build_exchange_data(
            auth_request=self.auth, authorization_code="synthetic", client_id="halo.app.android"
        )
        self.assertNotIn("client_secret", result)

    async def test_cancellation_propagates_without_retry(self):
        class CancelSession:
            def __init__(self):
                self.calls = 0

            def post(self, *args, **kwargs):
                self.calls += 1
                raise asyncio.CancelledError()

        session = CancelSession()
        with self.assertRaises(asyncio.CancelledError):
            await exchange_synthetic_callback(
                session,
                auth_request=self.auth,
                callback_url=self.callback,
                client_id="halo.app.android",
            )
        self.assertEqual(session.calls, 1)


if __name__ == "__main__":
    unittest.main()
