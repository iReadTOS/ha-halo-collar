"""Offline comparison of the existing Halo password flow and SSO code request.

All credentials and responses are synthetic. No real server, OAuth callback,
Apple account or Halo collar is contacted.
"""

from __future__ import annotations

import sys
from pathlib import Path
from urllib.parse import parse_qs

import pytest

# The research prototypes are intentionally standalone, not HA package modules.
_RESEARCH_PATH = str(Path(__file__).resolve().parents[1] / "research")
if _RESEARCH_PATH not in sys.path:
    sys.path.insert(0, _RESEARCH_PATH)

from offline_request_parity import TOKEN_URL, prepare_offline_code_post  # noqa: E402
from sso_oauth import create_request  # noqa: E402

from custom_components.halo_collar.api import (  # noqa: E402
    HALO_ANDROID_CLIENT_VERSION,
    HaloApiClient,
)
from custom_components.halo_collar.const import (  # noqa: E402
    DEFAULT_API_BASE,
    DEFAULT_AUTH_BASE,
    DEFAULT_CLIENT_ID,
    DEFAULT_TOKEN_SCOPE,
)


class _FakeResponse:
    status = 200

    async def text(self):
        return ""

    async def json(self, *, content_type=None):
        return {
            "access_token": "synthetic-access",
            "refresh_token": "synthetic-refresh",
            "expires_in": 3600,
        }

    def release(self):
        pass


class _RecordingSession:
    def __init__(self):
        self.calls = []

    async def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return _FakeResponse()


async def _password_request_without_network():
    fake_session = _RecordingSession()
    client = HaloApiClient(
        session=fake_session,
        access_token="",
        refresh_token="synthetic-initial-refresh",
        expires_at=0,
        client_id=DEFAULT_CLIENT_ID,
        client_secret="synthetic-app-secret",
        api_base=DEFAULT_API_BASE,
        auth_base=DEFAULT_AUTH_BASE,
        write_transport=None,
    )
    await client.async_login(
        "synthetic-user@example.invalid",
        "synthetic-password",
        scope=DEFAULT_TOKEN_SCOPE,
    )
    assert len(fake_session.calls) == 1
    return fake_session.calls[0]


@pytest.mark.asyncio
async def test_existing_password_post_uses_real_header_builder_with_fake_session():
    url, kwargs = await _password_request_without_network()
    assert url == TOKEN_URL
    assert kwargs["allow_redirects"] is False
    assert kwargs["data"]["grant_type"] == "password"
    assert kwargs["data"]["client_id"] == DEFAULT_CLIENT_ID
    assert kwargs["data"]["username"] == "synthetic-user@example.invalid"
    assert kwargs["data"]["password"] == "synthetic-password"
    assert kwargs["data"]["scope"] == DEFAULT_TOKEN_SCOPE
    headers = kwargs["headers"]
    assert headers["Accept"] == "application/json"
    assert headers["Halo-Amplitude-SessionId"] == "0"
    assert headers["Halo-Client"].startswith(
        f"clientId={DEFAULT_CLIENT_ID}&version={HALO_ANDROID_CLIENT_VERSION}&"
    )


@pytest.mark.asyncio
async def test_offline_sso_matches_hacs_transport_conventions_but_keeps_pkce_grant():
    password_url, password_kwargs = await _password_request_without_network()
    authorization = create_request(
        client_id=DEFAULT_CLIENT_ID,
        redirect_uri="haloapp://callback",
        authorization_endpoint=DEFAULT_AUTH_BASE + "/connect/authorize",
        scope=DEFAULT_TOKEN_SCOPE,
    )
    prepared = prepare_offline_code_post(
        auth_request=authorization,
        authorization_code="synthetic-one-time-code",
        client_id=DEFAULT_CLIENT_ID,
        client_secret="synthetic-app-secret",
        hacs_token_headers=password_kwargs["headers"],
    )
    assert password_url == prepared.full_url == TOKEN_URL
    assert prepared.get_method() == "POST"
    assert prepared.data is not None
    request_headers = {name.lower(): value for name, value in prepared.header_items()}
    for name, value in password_kwargs["headers"].items():
        assert request_headers[name.lower()] == value
    assert request_headers["content-type"] == "application/x-www-form-urlencoded"
    assert "authorization" not in request_headers
    assert "cookie" not in request_headers

    fields = parse_qs(prepared.data.decode("ascii"), strict_parsing=True)
    assert fields == {
        "grant_type": ["authorization_code"],
        "client_id": [DEFAULT_CLIENT_ID],
        "client_secret": ["synthetic-app-secret"],
        "code": ["synthetic-one-time-code"],
        "redirect_uri": ["haloapp://callback"],
        "code_verifier": [authorization.code_verifier],
    }
    assert "username" not in fields
    assert "password" not in fields


def test_parity_builder_rejects_extra_or_missing_headers():
    authorization = create_request(
        client_id=DEFAULT_CLIENT_ID,
        redirect_uri="haloapp://callback",
    )
    baseline = {
        "Accept": "application/json",
        "Halo-Client": "synthetic-client-header",
        "Halo-Amplitude-SessionId": "0",
    }
    for modification in (
        {"Authorization": "Bearer never-use-this"},
        {"Cookie": "session=never-use-this"},
        {"X-Extra": "unexpected"},
        {"Halo-Amplitude-SessionId": ""},
    ):
        headers = {**baseline, **modification}
        with pytest.raises(ValueError):
            prepare_offline_code_post(
                auth_request=authorization,
                authorization_code="synthetic-one-time-code",
                client_id=DEFAULT_CLIENT_ID,
                client_secret="synthetic-app-secret",
                hacs_token_headers=headers,
            )
    missing = {k: v for k, v in baseline.items() if k != "Halo-Client"}
    with pytest.raises(ValueError):
        prepare_offline_code_post(
            auth_request=authorization,
            authorization_code="synthetic-one-time-code",
            client_id=DEFAULT_CLIENT_ID,
            client_secret="synthetic-app-secret",
            hacs_token_headers=missing,
        )
