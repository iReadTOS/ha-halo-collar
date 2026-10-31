"""Research-only aiohttp token POST. No app fingerprint or credential spoofing.

Only the fixed caller-supplied token endpoint is used by the parent probe.
A caller must validate its exact HTTPS URL first. No redirects, retries,
credential logging, body logging, token persistence, or collar API calls.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Mapping
from typing import Any

import aiohttp

MAX_BODY = 131072
TIMEOUT = 15


class TokenTransportError(ValueError):
    """Safe-to-display transport error without response contents."""


class _ErrorView:
    """Read-only bounded adapter for the pre-existing safe OAuth classifier."""

    def __init__(self, headers: Mapping[str, str], data: bytes) -> None:
        self.headers = headers
        self._data = data

    def read(self, size: int) -> bytes:
        return self._data[:size]


async def _post_once(url: str, form: dict[str, str]) -> tuple[int, bytes, dict[str, str]]:
    timeout = aiohttp.ClientTimeout(total=TIMEOUT)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.post(
            url,
            data=form,
            headers={"Accept": "application/json"},
            allow_redirects=False,
        ) as response:
            # Bounded in-memory read; never persist or print response contents.
            body = await response.content.read(MAX_BODY + 1)
            headers = {
                name: response.headers.get(name, "")
                for name in ("Content-Type", "Server", "cf-mitigated")
            }
            return response.status, body, headers


def post_token_json(
    url: str,
    form: dict[str, str],
    *,
    classify_headers: Callable[[object], str],
    classify_error: Callable[[object], str],
) -> dict[str, Any]:
    """One token POST from synchronous probe code; never retry a one-time code."""
    try:
        status, body, headers = asyncio.run(_post_once(url, form))
    except (aiohttp.ClientError, TimeoutError, OSError, RuntimeError):
        raise TokenTransportError("Provider request failed or timed out") from None
    if status >= 400:
        category = classify_error(_ErrorView(headers, body))
        hints = classify_headers(headers)
        raise TokenTransportError(
            f"Provider rejected the request (HTTP {status}; {hints}; oauth_error={category})"
        )
    if status != 200 or len(body) > MAX_BODY:
        raise TokenTransportError(f"Unexpected provider response (HTTP {status})")
    try:
        payload = json.loads(body)
    except (ValueError, UnicodeError):
        raise TokenTransportError("Provider returned invalid JSON") from None
    if not isinstance(payload, dict):
        raise TokenTransportError("Provider returned invalid JSON object")
    return payload
