"""Synthetic-only tests: no network, Halo account, or collar required."""

import base64
import hashlib
import unittest
from urllib.parse import parse_qs, urlencode, urlsplit

from sso_oauth import OAuthResponseError, create_request, pkce_s256_challenge, validate_callback


class SsoOAuthTests(unittest.TestCase):
    def setUp(self):
        self.request = create_request(
            client_id="synthetic-test-client",
            redirect_uri="https://example.invalid/oauth/callback",
        )

    def callback(self, **params):
        return self.request.redirect_uri + "?" + urlencode(
            {"state": self.request.state, "code": "fake-code", **params}
        )

    def test_pkce_matches_standard_challenge(self):
        digest = hashlib.sha256(self.request.code_verifier.encode("ascii")).digest()
        expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        self.assertEqual(pkce_s256_challenge(self.request.code_verifier), expected)
        self.assertGreaterEqual(len(self.request.code_verifier), 43)

    def test_authorization_url_contains_expected_parameters(self):
        parts = urlsplit(self.request.authorization_url)
        params = parse_qs(parts.query)
        self.assertEqual(parts.netloc, "auth.halocollar.com")
        self.assertEqual(params["response_type"], ["code"])
        self.assertEqual(params["code_challenge_method"], ["S256"])
        self.assertEqual(params["redirect_uri"], [self.request.redirect_uri])
        self.assertEqual(params["state"], [self.request.state])
        self.assertEqual(params["nonce"], [self.request.nonce])
        self.assertNotIn("code_verifier", params)
        self.assertNotIn(self.request.code_verifier, self.request.authorization_url)

    def test_random_values_are_unique_across_requests(self):
        second = create_request(
            client_id="synthetic-test-client",
            redirect_uri=self.request.redirect_uri,
        )
        self.assertNotEqual(self.request.state, second.state)
        self.assertNotEqual(self.request.code_verifier, second.code_verifier)
        self.assertNotEqual(self.request.nonce, second.nonce)

    def test_valid_synthetic_callback(self):
        self.assertEqual(validate_callback(self.callback(), self.request), "fake-code")

    def test_wrong_state_rejected(self):
        with self.assertRaisesRegex(OAuthResponseError, "state mismatch"):
            validate_callback(self.callback(state="wrong"), self.request)

    def test_redirect_origin_rejected(self):
        with self.assertRaisesRegex(OAuthResponseError, "URI did not match"):
            validate_callback(
                "https://attacker.invalid/oauth/callback?"
                + urlencode({"state": self.request.state, "code": "fake-code"}),
                self.request,
            )

    def test_provider_error_does_not_leak_description(self):
        url = self.callback(error="access_denied", error_description="sensitive")
        with self.assertRaisesRegex(OAuthResponseError, "not granted") as error:
            validate_callback(url, self.request)
        self.assertNotIn("sensitive", str(error.exception))

    def test_duplicate_code_rejected(self):
        with self.assertRaisesRegex(OAuthResponseError, "duplicate"):
            validate_callback(self.callback() + "&code=another-code", self.request)

    def test_missing_code_rejected(self):
        with self.assertRaisesRegex(OAuthResponseError, "no authorization code"):
            validate_callback(self.callback(code=""), self.request)

    def test_fragment_rejected(self):
        with self.assertRaisesRegex(OAuthResponseError, "URI did not match"):
            validate_callback(self.callback() + "#access_token=bad", self.request)

    def test_unregistered_redirect_is_not_assumed_to_work(self):
        # The helper can build URLs for arbitrary callback URI values. It does NOT
        # verify that Halo's OAuth client registration accepts that callback.
        self.assertIn("example.invalid", self.request.authorization_url)


if __name__ == "__main__":
    unittest.main()
