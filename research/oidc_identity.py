"""Offline OIDC ID-token signature/claim validation prototype.

This code never fetches discovery metadata or JWKS. The caller must independently
obtain the *correct* key set over verified HTTPS from the trusted issuer.
Untrusted/caller-supplied JWKS are NOT a trust root. No real Halo login is
supported or intended. Uses PyJWT[crypto] for vetted RSA signature checking.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any

import jwt

OIDC_ISSUER = "https://auth.halocollar.com"
MAX_ID_TOKEN_LENGTH = 16384


class IDTokenValidationError(ValueError):
    """Safe-to-display generic error: never echo token, claims, or provider data."""


@dataclass(frozen=True, repr=False)
class VerifiedOIDCIdentity:
    issuer: str
    subject: str
    email: str | None
    email_verified: bool

    def __repr__(self) -> str:
        return "VerifiedOIDCIdentity(<redacted>)"


def verify_id_token(
    id_token: str,
    *,
    jwks: dict[str, Any],
    client_id: str,
    expected_nonce: str,
    issuer: str = OIDC_ISSUER,
) -> VerifiedOIDCIdentity:
    """Verify RS256 signature and minimal OIDC identity claims, fail-closed.

    Input JWKS *must* already be trusted as belonging to `issuer` (via independently
    verified OpenID Provider metadata and a trusted HTTPS jwks_uri). An attacker
    controlled JWKS would make signature checking meaningless.

    This is NOT an end-to-end OIDC client: it deliberately does not implement
    discovery, protected storage, auth-code exchange, refresh, or HA config flow.
    """
    if (
        not isinstance(id_token, str)
        or not id_token
        or len(id_token) > MAX_ID_TOKEN_LENGTH
        or not isinstance(jwks, dict)
        or not isinstance(client_id, str)
        or not client_id.strip()
        or not isinstance(expected_nonce, str)
        or not expected_nonce
        or issuer != OIDC_ISSUER
    ):
        raise IDTokenValidationError("Invalid OIDC verification inputs")

    try:
        header = jwt.get_unverified_header(id_token)
        if not isinstance(header, dict) or header.get("alg") != "RS256":
            raise IDTokenValidationError("OIDC ID token rejected")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise IDTokenValidationError("OIDC ID token rejected")

        keys = jwks.get("keys")
        if not isinstance(keys, list) or len(keys) > 64:
            raise IDTokenValidationError("OIDC signing keys unavailable")
        candidates = [
            key for key in keys if isinstance(key, dict) and key.get("kid") == kid
        ]
        if len(candidates) != 1:
            raise IDTokenValidationError("OIDC signing key not uniquely identified")
        candidate = candidates[0]
        if (
            candidate.get("kty") != "RSA"
            or candidate.get("alg", "RS256") != "RS256"
            or candidate.get("use", "sig") != "sig"
            or "d" in candidate
        ):
            raise IDTokenValidationError("Unsupported OIDC signing key")

        public_key = jwt.PyJWK.from_dict(candidate, algorithm="RS256").key
        claims = jwt.decode(
            id_token,
            public_key,
            algorithms=["RS256"],
            audience=client_id,
            issuer=issuer,
            options={"require": ["iss", "sub", "aud", "exp", "iat", "nonce"]},
            leeway=30,
        )

        subject = claims.get("sub")
        nonce = claims.get("nonce")
        if not isinstance(subject, str) or not subject.strip():
            raise IDTokenValidationError("OIDC identity missing")
        if (
            not isinstance(nonce, str)
            or not secrets.compare_digest(nonce, expected_nonce)
        ):
            raise IDTokenValidationError("OIDC nonce mismatch")

        audiences = claims["aud"]
        if isinstance(audiences, list):
            if len(audiences) != len(set(a for a in audiences if isinstance(a, str))):
                raise IDTokenValidationError("OIDC audience invalid")
            if len(audiences) > 1 and claims.get("azp") != client_id:
                raise IDTokenValidationError("OIDC authorized party mismatch")
        azp = claims.get("azp")
        if azp is not None and azp != client_id:
            raise IDTokenValidationError("OIDC authorized party mismatch")

        email = claims.get("email")
        if email is not None and (
            not isinstance(email, str) or not email.strip() or len(email) > 320
        ):
            raise IDTokenValidationError("OIDC email invalid")
        email_verified = claims.get("email_verified")
        if email_verified is not None and not isinstance(email_verified, bool):
            raise IDTokenValidationError("OIDC email verification invalid")
        return VerifiedOIDCIdentity(
            issuer=issuer,
            subject=subject,
            email=email,
            email_verified=email_verified is True,
        )
    except IDTokenValidationError:
        raise
    except (jwt.PyJWTError, ValueError, TypeError, OverflowError, KeyError):
        # Deliberately do not include the underlying exception or provider values.
        raise IDTokenValidationError("OIDC ID token rejected") from None
