"""Decrypt an explicitly supplied, verified-login research vault in memory.

No file/network access. Caller authenticates HA user through HA config flow.
The vault does not establish provider authorization for third-party OAuth.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

_MAGIC = b"HALO-SSO-ESCROW-v1\x00"
_AAD = b"iReadTOS Halo SSO research encrypted verified credentials v1"
_ISSUER = "https://auth.halocollar.com"
_CLIENT_ID = "halo.app.android"
_MAX_BUNDLE = 131072
_MAX_BASE64 = (_MAX_BUNDLE + 2) // 3 * 4 + 16


class VaultImportError(ValueError):
    """Safe failure; never includes vault contents, passphrase, or tokens."""


@dataclass(frozen=True, repr=False)
class ImportedVault:
    issuer: str
    subject: str
    client_id: str
    access_token: str
    refresh_token: str
    expires_at: float
    email: str | None

    def __repr__(self) -> str:
        return "ImportedVault(<redacted>)"

    @property
    def unique_id(self) -> str:
        """Distinct from legacy email IDs; prevents disclosing raw OIDC sub in IDs."""
        identity = f"{self.issuer}\x00{self.client_id}\x00{self.subject}".encode()
        return "oidc:" + hashlib.sha256(identity).hexdigest()


def import_encrypted_vault(text: str, passphrase: str) -> ImportedVault:
    """Decrypt an AES-GCM/Scrypt vault from an HA form; reject all invalid input."""
    if not isinstance(text, str) or not 0 < len(text) <= _MAX_BASE64:
        raise VaultImportError("Invalid encrypted vault")
    if not isinstance(passphrase, str) or len(passphrase) < 12 or len(passphrase) > 1024:
        raise VaultImportError("Invalid vault passphrase")
    try:
        # Newlines from copy/paste are allowed, but no other base64 corruption.
        blob = base64.b64decode("".join(text.split()).encode("ascii"), validate=True)
        if not _MAGIC == blob[: len(_MAGIC)] or not len(_MAGIC) + 44 <= len(blob) <= _MAX_BUNDLE:
            raise VaultImportError("Invalid encrypted vault")
        i = len(_MAGIC)
        salt = blob[i : i + 16]
        nonce = blob[i + 16 : i + 28]
        ciphertext = blob[i + 28 :]
        key = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(passphrase.encode("utf-8"))
        data = json.loads(AESGCM(key).decrypt(nonce, ciphertext, _AAD))
        if not isinstance(data, dict) or data.get("format") != 1:
            raise VaultImportError("Invalid encrypted vault")
        if data.get("issuer") != _ISSUER or data.get("client_id") != _CLIENT_ID:
            raise VaultImportError("Incompatible OAuth identity")
        subject = data.get("subject")
        access = data.get("access_token")
        refresh = data.get("refresh_token")
        expiry = data.get("expires_at")
        if (
            not isinstance(subject, str)
            or not 0 < len(subject) <= 1024
            or not isinstance(access, str)
            or not 0 < len(access) <= 32768
            or not isinstance(refresh, str)
            or not 0 < len(refresh) <= 32768
            or type(expiry) not in (int, float)
            or not math.isfinite(expiry)
            or expiry <= 0
        ):
            raise VaultImportError("Invalid token vault fields")
        email = data.get("email") if data.get("email_verified") is True else None
        if email is not None and (not isinstance(email, str) or not 0 < len(email) <= 320):
            raise VaultImportError("Invalid token vault fields")
        return ImportedVault(_ISSUER, subject, _CLIENT_ID, access, refresh, float(expiry), email)
    except VaultImportError:
        raise
    except (
        UnicodeError,
        binascii.Error,
        InvalidTag,
        ValueError,
        TypeError,
        OverflowError,
        MemoryError,
    ):
        raise VaultImportError("Invalid passphrase or damaged encrypted vault") from None
