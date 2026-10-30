"""OFFLINE-ONLY SSO token-request parity helper.

Builds a request object for inspection by tests. It deliberately performs no
network I/O and must not be wired into the live SSO probe without a separate
review of provider support.
"""

from __future__ import annotations

import urllib.parse
import urllib.request
from collections.abc import Mapping

from sso_oauth import AuthorizationRequest
from token_exchange import build_exchange_data

TOKEN_URL = "https://auth.halocollar.com/connect/token"
_EXPECTED_HACS_HEADER_NAMES = frozenset({"accept", "halo-client", "halo-amplitude-sessionid"})


def prepare_offline_code_post(
    *,
    auth_request: AuthorizationRequest,
    authorization_code: str,
    client_id: str,
    client_secret: str,
    hacs_token_headers: Mapping[str, str],
) -> urllib.request.Request:
    """Prepare but NEVER send an SSO code-exchange request.

    The caller must supply actual headers from HaloApiClient._token_headers().
    We reject added headers instead of accidentally forwarding arbitrary
    authentication data such as cookies or bearer tokens.
    """
    if not isinstance(hacs_token_headers, Mapping):
        raise ValueError("Expected Home Assistant token headers")
    names = [name.casefold() for name in hacs_token_headers]
    if (
        len(names) != len(_EXPECTED_HACS_HEADER_NAMES)
        or set(names) != _EXPECTED_HACS_HEADER_NAMES
        or any(not isinstance(value, str) or not value for value in hacs_token_headers.values())
    ):
        raise ValueError("Unexpected Home Assistant token headers")

    fields = build_exchange_data(
        auth_request=auth_request,
        authorization_code=authorization_code,
        client_id=client_id,
        client_secret=client_secret,
    )
    headers = dict(hacs_token_headers)
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    return urllib.request.Request(
        TOKEN_URL,
        data=urllib.parse.urlencode(fields).encode("ascii"),
        headers=headers,
        method="POST",
    )
