"""Research-only authorization-code exchange with an injectable HTTP session.

No HTTP session is created here, and running the tests never contacts Halo.
The real-world callback registration and OIDC ID-token trust checks are UNSOLVED.
Do not use this module for a live Home Assistant integration or account login.
"""

from __future__ import annotations

import asyncio
import math
import re
from dataclasses import dataclass
from typing import Any

from sso_oauth import AuthorizationRequest, validate_callback

TOKEN_ENDPOINT = "https://auth.halocollar.com/connect/token"
_CODE_VERIFIER = re.compile(r"[A-Za-z0-9._~-]{43,128}\Z")


class TokenExchangeError(ValueError):
    """Safe-to-display error; never includes a code, secret, token, or response body."""


@dataclass(frozen=True, repr=False)
class OAuthTokens:
    """UNVERIFIED provider response; do not trust ID-token claims or persist it."""

    access_token: str
    refresh_token: str
    id_token: str
    expires_in: float

    def __repr__(self) -> str:
        return "OAuthTokens(<redacted>)"


def build_exchange_data(
    *,
    auth_request: AuthorizationRequest,
    authorization_code: str,
    client_id: str,
    client_secret: str | None = None,
) -> dict[str, str]:
    """Construct a code+PKCE POST body using the exact original callback URI."""
    if (
        not authorization_code
        or len(authorization_code) > 4096
        or any(ord(c) < 32 or ord(c) == 127 for c in authorization_code)
    ):
        raise TokenExchangeError("Invalid authorization code")
    if not client_id or not client_id.strip():
        raise TokenExchangeError("OAuth client ID missing")
    if not _CODE_VERIFIER.fullmatch(auth_request.code_verifier):
        raise TokenExchangeError("Invalid PKCE verifier")
    data = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": authorization_code,
        "redirect_uri": auth_request.redirect_uri,
        "code_verifier": auth_request.code_verifier,
    }
    if client_secret is not None:
        if not client_secret:
            raise TokenExchangeError("OAuth client secret missing")
        data["client_secret"] = client_secret
    return data


def parse_token_response(status: int, payload: Any) -> OAuthTokens:
    """Require a valid synthetic OIDC token response, without trusting its claims.

    Real use also requires cryptographic ID-token verification (issuer, audience,
    expiry, signature, nonce), trusted subject/account identity, and refresh logic.
    """
    if status != 200:
        raise TokenExchangeError(f"OAuth token exchange rejected (HTTP {status})")
    if not isinstance(payload, dict):
        raise TokenExchangeError("Invalid OAuth token response")
    values = tuple(payload.get(k) for k in ("access_token", "refresh_token", "id_token"))
    if any(not isinstance(v, str) or not v for v in values):
        raise TokenExchangeError("Required OAuth token field missing")
    token_type = payload.get("token_type")
    if not isinstance(token_type, str) or token_type.lower() != "bearer":
        raise TokenExchangeError("Unsupported OAuth token type")
    lifetime = payload.get("expires_in")
    if type(lifetime) not in (float, int) or not math.isfinite(lifetime) or lifetime <= 60:
        raise TokenExchangeError("Invalid OAuth token expiration")
    return OAuthTokens(
        access_token=values[0],
        refresh_token=values[1],
        id_token=values[2],
        expires_in=float(lifetime),
    )


async def exchange_synthetic_callback(
    session: Any,
    *,
    auth_request: AuthorizationRequest,
    callback_url: str,
    client_id: str,
    client_secret: str | None = None,
) -> OAuthTokens:
    """Validate callback then perform exactly one code-exchange POST.

    A caller supplies the HTTP session. Tests use a fake session exclusively.
    NEVER run this against a real Halo account; callback registration and full
    OIDC ID-token validation have not been established.
    """
    code = validate_callback(callback_url, auth_request)
    data = build_exchange_data(
        auth_request=auth_request,
        authorization_code=code,
        client_id=client_id,
        client_secret=client_secret,
    )
    try:
        async with asyncio.timeout(15):
            async with session.post(
                TOKEN_ENDPOINT,
                data=data,
                headers={"Accept": "application/json"},
                allow_redirects=False,
            ) as response:
                if response.status != 200:
                    raise TokenExchangeError(
                        f"OAuth token exchange rejected (HTTP {response.status})"
                    )
                try:
                    payload = await response.json(content_type=None)
                except (ValueError, TypeError):
                    raise TokenExchangeError("Invalid OAuth token response") from None
                return parse_token_response(response.status, payload)
    except TimeoutError:
        raise TokenExchangeError("OAuth token exchange timed out") from None
