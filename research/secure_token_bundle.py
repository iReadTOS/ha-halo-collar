"""Passphrase-encrypted *research* escrow for a verified Halo SSO session.

Never pass secrets via command-line arguments, stdout, debug logs or Git. A
bundle is NOT an authentication method or a Home Assistant config entry.
This module neither contacts Halo nor invokes any collar endpoint.
"""

from __future__ import annotations

import getpass
import json
import os
import secrets
import stat
import time
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from oidc_identity import OIDC_ISSUER, VerifiedOIDCIdentity
from token_exchange import OAuthTokens

_MAGIC = b"HALO-SSO-ESCROW-v1\x00"
_AAD = b"iReadTOS Halo SSO research encrypted verified credentials v1"
_MAX_BUNDLE = 131072


class TokenVaultError(ValueError):
    """Sanitized exception that does not display credential material."""


def default_bundle_path() -> Path:
    return (
        Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local/share")))
        / "halo-sso-research"
        / "verified-sso.halo-vault"
    )


def _private_parent(path: Path) -> None:
    parent = path.parent
    try:
        parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        meta = parent.lstat()
        if (
            not stat.S_ISDIR(meta.st_mode)
            or meta.st_uid != os.getuid()
            or stat.S_IMODE(meta.st_mode) != 0o700
        ):
            raise TokenVaultError("Token vault directory must be private (0700)")
    except OSError:
        raise TokenVaultError("Cannot access private token vault directory") from None


def _derive(passphrase: str, salt: bytes) -> bytes:
    if not isinstance(passphrase, str) or len(passphrase) < 12:
        raise TokenVaultError("A passphrase of at least 12 characters is required")
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(passphrase.encode("utf-8"))


def _payload(
    identity: VerifiedOIDCIdentity, tokens: OAuthTokens, client_id: str, now: float
) -> dict[str, Any]:
    if (
        not isinstance(identity, VerifiedOIDCIdentity)
        or identity.issuer != OIDC_ISSUER
        or not isinstance(identity.subject, str)
        or not identity.subject.strip()
        or client_id != "halo.app.android"
        or not isinstance(tokens, OAuthTokens)
        or not isinstance(tokens.access_token, str)
        or not tokens.access_token
        or not isinstance(tokens.refresh_token, str)
        or not tokens.refresh_token
        or not isinstance(tokens.expires_in, (int, float))
        or tokens.expires_in <= 60
    ):
        raise TokenVaultError("Invalid verified login for vault")
    # We intentionally DO NOT save the ID token or its one-time authorization code.
    return {
        "format": 1,
        "issuer": identity.issuer,
        "subject": identity.subject,
        "client_id": client_id,
        "access_token": tokens.access_token,
        "refresh_token": tokens.refresh_token,
        "expires_at": now + float(tokens.expires_in) - 60,
        "created_at": now,
        "email": identity.email if identity.email_verified else None,
        "email_verified": bool(identity.email_verified),
    }


def prepare_destination(path: Path) -> None:
    """Preflight permissions and writability BEFORE involving an account owner."""
    path = Path(path)
    _private_parent(path)
    if path.exists() or path.is_symlink():
        raise TokenVaultError(
            "Token vault already exists; existing credentials were not overwritten"
        )
    # Verify the private folder can actually create a file without pre-creating
    # the final vault. One disk-full/permission failure is caught before login.
    import tempfile

    try:
        fd, test_path = tempfile.mkstemp(prefix=".vault-preflight-", dir=path.parent)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, b"preflight")
            os.fsync(fd)
        finally:
            os.close(fd)
            os.unlink(test_path)
    except OSError:
        raise TokenVaultError("Cannot write to private token vault directory") from None


def save_verified_bundle(
    path: Path,
    *,
    passphrase: str,
    identity: VerifiedOIDCIdentity,
    tokens: OAuthTokens,
    client_id: str,
    now: float | None = None,
) -> None:
    """Encrypt and save once; never replace an existing bundle.

    Caller MUST verify real ID token with provider-trusted JWKS/nonce first.
    """
    path = Path(path)
    _private_parent(path)
    value = _payload(identity, tokens, client_id, time.time() if now is None else now)
    raw = json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    if len(raw) > _MAX_BUNDLE - 64:
        raise TokenVaultError("Login data too large for private token vault")
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(_derive(passphrase, salt)).encrypt(nonce, raw, _AAD)
    blob = _MAGIC + salt + nonce + ciphertext
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        raise TokenVaultError(
            "Token vault already exists; existing credentials were not overwritten"
        ) from None
    except OSError:
        raise TokenVaultError("Cannot create private token vault") from None
    try:
        with os.fdopen(fd, "wb") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(blob)
            output.flush()
            os.fsync(output.fileno())
    except OSError:
        path.unlink(missing_ok=True)
        raise TokenVaultError("Could not finish saving encrypted token vault") from None


def load_bundle(path: Path, *, passphrase: str) -> dict[str, Any]:
    """Decrypt into MEMORY only. Never log or print the returned dictionary."""
    path = Path(path)
    _private_parent(path)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size > _MAX_BUNDLE
            ):
                raise TokenVaultError("Token vault file must be private (0600)")
            blob = source.read(_MAX_BUNDLE + 1)
    except (OSError, ValueError):
        raise TokenVaultError("Private token vault is unavailable") from None
    if not blob.startswith(_MAGIC) or len(blob) < len(_MAGIC) + 16 + 12 + 16:
        raise TokenVaultError("Unsupported or damaged token vault")
    cursor = len(_MAGIC)
    salt, nonce, ciphertext = (
        blob[cursor : cursor + 16],
        blob[cursor + 16 : cursor + 28],
        blob[cursor + 28 :],
    )
    try:
        raw = AESGCM(_derive(passphrase, salt)).decrypt(nonce, ciphertext, _AAD)
        value = json.loads(raw)
        if (
            not isinstance(value, dict)
            or value.get("format") != 1
            or value.get("issuer") != OIDC_ISSUER
            or value.get("client_id") != "halo.app.android"
            or not isinstance(value.get("subject"), str)
            or not value["subject"]
            or not isinstance(value.get("access_token"), str)
            or not value["access_token"]
            or not isinstance(value.get("refresh_token"), str)
            or not value["refresh_token"]
            or type(value.get("expires_at")) not in (int, float)
        ):
            raise TokenVaultError("Invalid token vault contents")
        return value
    except (InvalidTag, UnicodeError, ValueError, TypeError, KeyError):
        raise TokenVaultError("Incorrect passphrase or damaged token vault") from None


def check_bundle() -> int:
    """A local integrity check; never prints account identifiers or secrets."""
    path = default_bundle_path()
    try:
        load_bundle(path, passphrase=getpass.getpass("Vault passphrase: "))
    except TokenVaultError as exc:
        print(f"STOP: {exc}")
        return 1
    print("PASS: encrypted credential vault decrypts and has the expected format")
    return 0


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Check a local research credential vault without exposing credentials"
    )
    parser.add_argument("command", choices=("check",))
    args = parser.parse_args()
    raise SystemExit(check_bundle())
