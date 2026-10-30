"""Ensure SSO token updates cannot cross credential identities (synthetic only)."""

from __future__ import annotations

import pytest

pytest.importorskip("homeassistant")

from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.halo_collar import _credentials, _TokenWriter
from custom_components.halo_collar.const import (
    CONF_ACCESS_TOKEN,
    CONF_AUTH_METHOD,
    CONF_CLIENT_ID,
    CONF_CLIENT_SECRET,
    CONF_EXPIRES_AT,
    CONF_REFRESH_TOKEN,
    CONF_SSO_ISSUER,
    CONF_SSO_SUBJECT,
    DOMAIN,
    SSO_VAULT_AUTH,
)


def _entry(*, expires_at=4_102_444_800.0):
    return MockConfigEntry(
        domain=DOMAIN,
        title="Synthetic SSO read-only",
        unique_id="oidc:" + "a" * 64,
        data={
            CONF_AUTH_METHOD: SSO_VAULT_AUTH,
            CONF_SSO_ISSUER: "https://auth.halocollar.com",
            CONF_SSO_SUBJECT: "synthetic-subject",
            CONF_CLIENT_ID: "halo.app.android",
            CONF_CLIENT_SECRET: "synthetic-app-client-value",
            CONF_ACCESS_TOKEN: "old-access",
            CONF_REFRESH_TOKEN: "old-refresh",
            CONF_EXPIRES_AT: expires_at,
        },
    )


def _rotation():
    return {
        "access_token": "new-access",
        "refresh_token": "new-refresh",
        "expires_at": 4_102_445_000.0,
    }


async def test_sso_writer_persists_normal_token_rotation(hass):
    entry = _entry()
    entry.add_to_hass(hass)
    writer = _TokenWriter(hass, entry, _credentials(entry.data))
    writer.persist(_rotation())
    assert entry.data[CONF_ACCESS_TOKEN] == "new-access"
    assert entry.data[CONF_REFRESH_TOKEN] == "new-refresh"
    assert entry.data[CONF_SSO_SUBJECT] == "synthetic-subject"


@pytest.mark.parametrize(
    ("field", "changed"),
    [
        (CONF_AUTH_METHOD, "password"),
        (CONF_SSO_ISSUER, "https://other.invalid"),
        (CONF_SSO_SUBJECT, "other-subject"),
        (CONF_CLIENT_ID, "other-client"),
        (CONF_CLIENT_SECRET, "other-client-secret"),
    ],
)
async def test_sso_writer_refuses_changed_identity_and_stays_retired(hass, field, changed):
    entry = _entry()
    entry.add_to_hass(hass)
    original = dict(entry.data)
    writer = _TokenWriter(hass, entry, _credentials(entry.data))
    modified = {**original, field: changed}
    hass.config_entries.async_update_entry(entry, data=modified)
    writer.persist(_rotation())
    assert dict(entry.data) == modified
    # Restoring data must NOT reactivate an already retired writer.
    hass.config_entries.async_update_entry(entry, data=original)
    writer.persist(_rotation())
    assert dict(entry.data) == original


async def test_sso_runtime_refreshes_expired_tokens_without_a_write_transport(hass, aioclient_mock):
    """Exercise a real API client with mocked HTTP; no provider contact."""
    from homeassistant.config_entries import ConfigEntryState

    from custom_components.halo_collar.const import DEFAULT_API_BASE, DEFAULT_AUTH_BASE

    entry = _entry(expires_at=0.0)
    entry.add_to_hass(hass)
    aioclient_mock.post(
        f"{DEFAULT_AUTH_BASE}/connect/token",
        json={
            "access_token": "new-access",
            "refresh_token": "new-refresh",
            "expires_in": 3600,
        },
    )
    for path, payload in (
        ("/pet/my", []),
        ("/collar/my", []),
        ("/subscription/my", {}),
        ("/system/server-date-time", "2026-10-30T12:00:00Z"),
        ("/walk/my?page=1&pageSize=30", {"results": []}),
    ):
        aioclient_mock.get(f"{DEFAULT_API_BASE}{path}", json=payload)

    assert await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    assert entry.state is ConfigEntryState.LOADED
    assert entry.data[CONF_ACCESS_TOKEN] == "new-access"
    assert entry.data[CONF_REFRESH_TOKEN] == "new-refresh"
    client = hass.data[DOMAIN][entry.entry_id]["client"]
    assert client._write_transport is None
    assert await hass.config_entries.async_unload(entry.entry_id)
