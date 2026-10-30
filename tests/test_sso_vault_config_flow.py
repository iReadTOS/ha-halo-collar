"""Native HA SSO-vault import lifecycle tests with fake in-memory credentials."""

from __future__ import annotations

import base64
import json
import secrets
from unittest.mock import patch

import pytest

pytest.importorskip("homeassistant")

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from homeassistant import config_entries
from homeassistant.data_entry_flow import FlowResultType
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.halo_collar import _controls_signature
from custom_components.halo_collar.const import (
    CONF_ACCESS_TOKEN,
    CONF_AUTH_METHOD,
    CONF_CLIENT_ID,
    CONF_EMAIL,
    CONF_EXPIRES_AT,
    CONF_REFRESH_TOKEN,
    CONF_SSO_ISSUER,
    CONF_SSO_SUBJECT,
    DOMAIN,
    SSO_VAULT_AUTH,
)

PASS = "this-is-a-synthetic-passphrase-long-enough"


def fake_vault(*, sub="synthetic-subject", access="fake-access", refresh="fake-refresh"):
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    key = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(PASS.encode())
    payload = {
        "format": 1,
        "issuer": "https://auth.halocollar.com",
        "client_id": "halo.app.android",
        "subject": sub,
        "access_token": access,
        "refresh_token": refresh,
        "expires_at": 4102444800.0,
        "email": "owner@synthetic.invalid",
        "email_verified": True,
    }
    encrypted = AESGCM(key).encrypt(
        nonce,
        json.dumps(payload).encode(),
        b"iReadTOS Halo SSO research encrypted verified credentials v1",
    )
    return base64.b64encode(b"HALO-SSO-ESCROW-v1\x00" + salt + nonce + encrypted).decode()


async def start_import(hass):
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    assert result["type"] is FlowResultType.MENU
    assert result["step_id"] == "user"
    assert {"password", "sso_vault"} <= set(result["menu_options"])
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"next_step_id": "sso_vault"}
    )
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "sso_vault"
    return result


async def test_vault_import_creates_separate_oidc_entry_without_secrets_in_form(hass):
    start = await start_import(hass)
    encoded = fake_vault()
    result = await hass.config_entries.flow.async_configure(
        start["flow_id"], {"encrypted_vault": encoded, "vault_passphrase": PASS}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    entry = result["result"]
    assert entry.unique_id.startswith("oidc:")
    assert entry.data[CONF_AUTH_METHOD] == SSO_VAULT_AUTH
    assert entry.data[CONF_SSO_ISSUER] == "https://auth.halocollar.com"
    assert entry.data[CONF_SSO_SUBJECT] == "synthetic-subject"
    assert entry.data[CONF_CLIENT_ID] == "halo.app.android"
    assert entry.data[CONF_ACCESS_TOKEN] == "fake-access"
    assert entry.data[CONF_REFRESH_TOKEN] == "fake-refresh"
    assert entry.data[CONF_EXPIRES_AT] > 0
    assert entry.data[CONF_EMAIL] == "owner@synthetic.invalid"
    assert PASS not in repr(entry.data)
    assert encoded not in repr(entry.data)
    assert not any("password" in key for key in entry.data)
    assert _controls_signature(entry) == (False, False, False)


async def test_bad_passphrase_does_not_create_entry(hass):
    start = await start_import(hass)
    result = await hass.config_entries.flow.async_configure(
        start["flow_id"],
        {"encrypted_vault": fake_vault(), "vault_passphrase": "completely wrong long phrase"},
    )
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "invalid_vault"}


async def test_duplicate_oidc_subject_aborts(hass):
    first = await start_import(hass)
    result = await hass.config_entries.flow.async_configure(
        first["flow_id"], {"encrypted_vault": fake_vault(), "vault_passphrase": PASS}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    again = await start_import(hass)
    result2 = await hass.config_entries.flow.async_configure(
        again["flow_id"], {"encrypted_vault": fake_vault(), "vault_passphrase": PASS}
    )
    assert result2["type"] is FlowResultType.ABORT
    assert result2["reason"] == "already_configured"


async def test_password_entry_same_verified_email_aborts_not_replaces(hass):
    existing = MockConfigEntry(
        domain=DOMAIN,
        title="old",
        unique_id="owner@synthetic.invalid",
        data={CONF_EMAIL: "owner@synthetic.invalid", CONF_REFRESH_TOKEN: "old"},
    )
    existing.add_to_hass(hass)
    initial = await start_import(hass)
    result = await hass.config_entries.flow.async_configure(
        initial["flow_id"], {"encrypted_vault": fake_vault(), "vault_passphrase": PASS}
    )
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "password_entry_exists"
    assert existing.data[CONF_REFRESH_TOKEN] == "old"


async def test_sso_vault_reauth_rejects_different_subject(hass):
    initial = await start_import(hass)
    created = await hass.config_entries.flow.async_configure(
        initial["flow_id"], {"encrypted_vault": fake_vault(), "vault_passphrase": PASS}
    )
    entry = created["result"]
    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": config_entries.SOURCE_REAUTH, "entry_id": entry.entry_id},
        data=entry.data,
    )
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "sso_vault_reauth"
    changed = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {"encrypted_vault": fake_vault(sub="other-subject"), "vault_passphrase": PASS},
    )
    assert changed["type"] is FlowResultType.FORM
    assert changed["errors"] == {"base": "account_mismatch"}
    assert entry.data[CONF_REFRESH_TOKEN] == "fake-refresh"


async def test_sso_vault_reauth_same_subject_rotates_without_overwriting_identity(hass):
    initial = await start_import(hass)
    created = await hass.config_entries.flow.async_configure(
        initial["flow_id"], {"encrypted_vault": fake_vault(), "vault_passphrase": PASS}
    )
    entry = created["result"]
    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": config_entries.SOURCE_REAUTH, "entry_id": entry.entry_id},
        data=entry.data,
    )
    with patch("custom_components.halo_collar.config_flow.async_request_reload") as reload:
        changed = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {
                "encrypted_vault": fake_vault(access="next-access", refresh="next-refresh"),
                "vault_passphrase": PASS,
            },
        )
    assert changed["type"] is FlowResultType.ABORT
    assert changed["reason"] == "reauth_successful"
    assert entry.data[CONF_ACCESS_TOKEN] == "next-access"
    assert entry.data[CONF_REFRESH_TOKEN] == "next-refresh"
    assert entry.data[CONF_SSO_SUBJECT] == "synthetic-subject"
    reload.assert_called_once()
