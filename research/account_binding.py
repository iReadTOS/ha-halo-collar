"""Offline-only, side-effect-free SSO account binding and reauth research.

This experiment joins callback validation, a fake-session authorization-code
exchange, signed ID-token verification, and stable issuer+subject account binding.
It does NOT configure Home Assistant, persist credentials, fetch signing keys,
or permit real Halo authentication. A provider-approved callback is still unknown.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from oidc_identity import OIDC_ISSUER, VerifiedOIDCIdentity, verify_id_token
from sso_oauth import AuthorizationRequest
from token_exchange import OAuthTokens, exchange_synthetic_callback


class AccountBindingError(ValueError):
    """Fail-closed, non-sensitive account identity or commit error."""


@dataclass(frozen=True, repr=False)
class AccountBinding:
    """Persisted identity concept: never substitute email for OIDC subject."""

    issuer: str
    subject: str
    client_id: str

    def __post_init__(self) -> None:
        if (
            self.issuer != OIDC_ISSUER
            or not isinstance(self.subject, str)
            or not self.subject.strip()
            or not isinstance(self.client_id, str)
            or not self.client_id.strip()
        ):
            raise AccountBindingError("Invalid stored SSO identity")

    def __repr__(self) -> str:
        return "AccountBinding(<redacted>)"


@dataclass(frozen=True, repr=False)
class PreparedSSOLogin:
    """Verified but NOT persisted credentials; no mutation is performed here."""

    binding: AccountBinding
    tokens: OAuthTokens

    def __repr__(self) -> str:
        return "PreparedSSOLogin(<redacted>)"


@dataclass(frozen=True, repr=False)
class EntrySnapshot:
    """Synthetic model of the entry and its credential-lineage revision.

    The revision is an opaque, locally-controlled value which *must* change when
    the stored credential lineage is replaced. An eventual HA integration must
    use its actual current-entry/credential-lineage safeguards, not assume an
    entry exposes this particular revision field.
    """

    entry_id: str
    binding: AccountBinding | None
    revision: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.entry_id, str)
            or not self.entry_id
            or not isinstance(self.revision, str)
            or not self.revision
            or (self.binding is not None and not isinstance(self.binding, AccountBinding))
        ):
            raise AccountBindingError("Invalid saved entry snapshot")

    def __repr__(self) -> str:
        return "EntrySnapshot(<redacted>)"


def _binding_from_identity(identity: VerifiedOIDCIdentity, client_id: str) -> AccountBinding:
    return AccountBinding(
        issuer=identity.issuer,
        subject=identity.subject,
        client_id=client_id,
    )


async def prepare_synthetic_new_login(
    session: Any,
    *,
    auth_request: AuthorizationRequest,
    callback_url: str,
    trusted_jwks: dict[str, Any],
    client_id: str,
    client_secret: str | None = None,
) -> PreparedSSOLogin:
    """Return a proposed new SSO identity only after signed ID-token checks.

    The supplied session MUST be a fake in testing; the JWKS MUST be a trusted
    set in any future real implementation. This function does not write state.
    """
    tokens = await exchange_synthetic_callback(
        session,
        auth_request=auth_request,
        callback_url=callback_url,
        client_id=client_id,
        client_secret=client_secret,
    )
    identity = verify_id_token(
        tokens.id_token,
        jwks=trusted_jwks,
        client_id=client_id,
        expected_nonce=auth_request.nonce,
    )
    return PreparedSSOLogin(
        binding=_binding_from_identity(identity, client_id),
        tokens=tokens,
    )


async def prepare_synthetic_same_account_reauth(
    session: Any,
    *,
    original: EntrySnapshot,
    auth_request: AuthorizationRequest,
    callback_url: str,
    trusted_jwks: dict[str, Any],
    client_id: str,
    client_secret: str | None = None,
) -> PreparedSSOLogin:
    """Do not accept a different subject, even if the email claim matches.

    An existing password-only entry has no verified OIDC subject. It cannot be
    silently migrated, so an unbound entry is rejected BEFORE any token POST.
    """
    if original.binding is None:
        raise AccountBindingError("SSO account link not established")
    if original.binding.client_id != client_id:
        raise AccountBindingError("SSO client configuration changed")
    proposed = await prepare_synthetic_new_login(
        session,
        auth_request=auth_request,
        callback_url=callback_url,
        trusted_jwks=trusted_jwks,
        client_id=client_id,
        client_secret=client_secret,
    )
    if proposed.binding != original.binding:
        raise AccountBindingError("SSO account did not match existing entry")
    return proposed


def assert_unchanged_before_reauth_commit(
    proposed: PreparedSSOLogin,
    *,
    original: EntrySnapshot,
    current: EntrySnapshot,
) -> None:
    """Check a synthetic commit boundary; never writes to any config entry.

    A real integration must re-fetch the live entry and compare the actual
    credential lineage immediately before persisting refreshed credentials.
    """
    if original.binding is None or proposed.binding != original.binding:
        raise AccountBindingError("SSO account did not match existing entry")
    if current != original:
        raise AccountBindingError("SSO entry changed during authentication")
