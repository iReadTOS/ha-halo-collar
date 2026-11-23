"""Offline-only OAuth authorization-code/PKCE helpers for Halo SSO research.

This research module intentionally does not make HTTP requests, exchange tokens,
or integrate with Home Assistant. It does *not* establish that Halo has registered
an appropriate redirect URI for a third-party Home Assistant integration.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

DEFAULT_AUTHORIZATION_ENDPOINT = "https://auth.halocollar.com/connect/authorize"
DEFAULT_SCOPE = "openid email offline_access api.dogpark"


class OAuthResponseError(ValueError):
    """An invalid or unsuccessful authorization response; avoids sensitive data."""


@dataclass(frozen=True)
class AuthorizationRequest:
    """Private per-attempt state: never store the verifier in logs or a URL."""

    authorization_url: str
    redirect_uri: str
    state: str
    nonce: str
    code_verifier: str


def pkce_s256_challenge(code_verifier: str) -> str:
    """RFC 7636 SHA-256 challenge (base64url, without padding)."""
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def create_request(
    *,
    client_id: str,
    redirect_uri: str,
    authorization_endpoint: str = DEFAULT_AUTHORIZATION_ENDPOINT,
    scope: str = DEFAULT_SCOPE,
) -> AuthorizationRequest:
    """Create an OAuth URL without starting a browser or contacting Halo.

    The redirect_uri must be *registered by Halo for this exact OAuth client*.
    Supplying one here does not register it or make it usable.
    """
    endpoint = urlsplit(authorization_endpoint)
    redirect = urlsplit(redirect_uri)
    if not client_id or not client_id.strip():
        raise ValueError("An OAuth client ID is required")
    if endpoint.scheme != "https" or not endpoint.netloc or endpoint.fragment:
        raise ValueError("A valid HTTPS authorization endpoint is required")
    if not redirect.scheme or not redirect.netloc or redirect.query or redirect.fragment:
        raise ValueError("An absolute callback URI without query/fragment is required")
    if not scope.strip():
        raise ValueError("At least one scope is required")

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(48)
    params = [
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("response_type", "code"),
        ("scope", scope),
        ("state", state),
        ("nonce", nonce),
        ("code_challenge", pkce_s256_challenge(code_verifier)),
        ("code_challenge_method", "S256"),
    ]
    existing = parse_qsl(endpoint.query, keep_blank_values=True)
    if existing:
        raise ValueError("Authorization endpoint must not contain query parameters")
    authorization_url = urlunsplit(
        (endpoint.scheme, endpoint.netloc, endpoint.path, urlencode(params), "")
    )
    return AuthorizationRequest(
        authorization_url=authorization_url,
        redirect_uri=redirect_uri,
        state=state,
        nonce=nonce,
        code_verifier=code_verifier,
    )


def validate_callback(callback_url: str, request: AuthorizationRequest) -> str:
    """Validate the callback URI and state, returning only its authorization code.

    Token exchange, ID-token issuer/audience/nonce checks, session storage, and
    Home Assistant integration are deliberately OUT OF SCOPE for this experiment.
    """
    callback = urlsplit(callback_url)
    expected = urlsplit(request.redirect_uri)
    if (
        callback.scheme != expected.scheme
        or callback.netloc != expected.netloc
        or callback.path != expected.path
        or callback.fragment
    ):
        raise OAuthResponseError("OAuth callback URI did not match")
    entries = parse_qsl(callback.query, keep_blank_values=True)
    params: dict[str, str] = {}
    for name, value in entries:
        if name in params:
            raise OAuthResponseError("OAuth response included duplicate parameters")
        params[name] = value

    received_state = params.get("state", "")
    if not received_state or not secrets.compare_digest(received_state, request.state):
        raise OAuthResponseError("OAuth state mismatch")
    if params.get("error"):
        # Do not echo provider-supplied descriptions or callback contents.
        raise OAuthResponseError("OAuth authorization was not granted")
    code = params.get("code")
    if not code:
        raise OAuthResponseError("OAuth response contained no authorization code")
    return code
