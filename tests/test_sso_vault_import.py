"""Encrypted vault import format and account-lineage tests; no Halo/HA calls."""

from __future__ import annotations

import base64
import importlib.util
import json
import secrets
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

path = Path(__file__).resolve().parents[1] / "custom_components/halo_collar/sso_vault.py"
spec = importlib.util.spec_from_file_location("sso_vault_standalone", path)
module = importlib.util.module_from_spec(spec)

sys.modules[spec.name] = module
spec.loader.exec_module(module)

PASSWORD = "local synthetic testing passphrase"
MAGIC = b"HALO-SSO-ESCROW-v1\x00"
AAD = b"iReadTOS Halo SSO research encrypted verified credentials v1"


def package(**changes):
    data = {
        "format": 1,
        "issuer": "https://auth.halocollar.com",
        "subject": "fake-subject",
        "client_id": "halo.app.android",
        "access_token": "fake-access",
        "refresh_token": "fake-refresh",
        "expires_at": 2_000_000_000,
        "created_at": 1_900_000_000,
        "email": "synthetic@example.invalid",
        "email_verified": True,
    }
    data.update(changes)
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    key = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(PASSWORD.encode())
    blob = MAGIC + salt + nonce + AESGCM(key).encrypt(nonce, json.dumps(data).encode(), AAD)
    return base64.b64encode(blob).decode()


def test_import_preserves_verified_identity_and_tokens():
    result = module.import_encrypted_vault(package(), PASSWORD)
    assert result.subject == "fake-subject"
    assert result.email == "synthetic@example.invalid"
    assert result.access_token == "fake-access"
    assert result.refresh_token == "fake-refresh"
    assert "fake" not in repr(result)
    assert result.unique_id.startswith("oidc:")
    assert len(result.unique_id) == 69


def test_distinct_identity_unique_id_does_not_follow_email():
    a = module.import_encrypted_vault(package(), PASSWORD)
    b = module.import_encrypted_vault(
        package(subject="another", email="synthetic@example.invalid"), PASSWORD
    )
    assert a.unique_id != b.unique_id
    assert a.unique_id != "synthetic@example.invalid"


def test_unverified_email_not_used():
    assert module.import_encrypted_vault(package(email_verified=False), PASSWORD).email is None


@pytest.mark.parametrize(
    "wrong", ["bad", "fake incorrect long password", "not the same passphrase"]
)
def test_wrong_passphrase_rejected(wrong):
    with pytest.raises(module.VaultImportError):
        module.import_encrypted_vault(package(), wrong)


def test_mutation_rejected_without_leaking_tokens():
    encoded = package()
    raw = bytearray(base64.b64decode(encoded))
    raw[-17] ^= 1
    with pytest.raises(module.VaultImportError) as exc:
        module.import_encrypted_vault(base64.b64encode(raw).decode(), PASSWORD)
    assert "fake-access" not in str(exc.value)


@pytest.mark.parametrize(
    "change",
    [
        {"issuer": "https://example.invalid"},
        {"client_id": "something-else"},
        {"subject": ""},
        {"access_token": ""},
        {"refresh_token": ""},
        {"expires_at": float("nan")},
        {"expires_at": True},
        {"email": [], "email_verified": True},
    ],
)
def test_wrong_bundle_fields_rejected(change):
    with pytest.raises(module.VaultImportError):
        module.import_encrypted_vault(package(**change), PASSWORD)


def test_newline_from_paste_accepted():
    original = package()
    assert (
        module.import_encrypted_vault(original[:40] + "\n" + original[40:], PASSWORD).subject
        == "fake-subject"
    )


def test_oversize_rejected_before_crypto():
    with pytest.raises(module.VaultImportError):
        module.import_encrypted_vault("Q" * 200000, PASSWORD)


def test_export_round_trip(tmp_path):
    import importlib.util

    filepath = Path(__file__).resolve().parents[1] / "research/export_encrypted_vault.py"
    spec2 = importlib.util.spec_from_file_location("vault_export", filepath)
    exporter = importlib.util.module_from_spec(spec2)
    spec2.loader.exec_module(exporter)
    vault = tmp_path / "test.halo-vault"
    vault.write_bytes(base64.b64decode(package()))
    vault.chmod(0o600)
    result = module.import_encrypted_vault(exporter.export_vault(vault), PASSWORD)
    assert result.subject == "fake-subject"
