"""Privacy-preserving classification of an OAuth token endpoint rejection.

Only exact standard OAuth error names are ever returned. The HTTP response's
body and headers are not logged, displayed, persisted or returned. Research-only.
"""

from __future__ import annotations

import json
from typing import Any

MAX_ERROR_BYTES = 8192
# Exact allowlist: unexpected error strings, descriptions, URIs, account data,
# headers and token contents must never enter user-visible diagnostics.
_ALLOWED_ERRORS = frozenset(
    {
        "invalid_request",
        "invalid_client",
        "invalid_grant",
        "unauthorized_client",
        "unsupported_grant_type",
        "invalid_scope",
        "access_denied",
        "server_error",
        "temporarily_unavailable",
    }
)


def safe_oauth_error_code(error: Any) -> str:
    """Return only a fixed label from a bounded JSON response body.

    Reading the rejection body is solely for private local classification. A
    JSON response or known error label does not prove which layer rejected it.
    The caller must only invoke this for the exact trusted token endpoint.
    """
    headers = getattr(error, "headers", None)
    getter = getattr(headers, "get", None)
    if not callable(getter):
        return "unavailable"
    try:
        content_type = getter("Content-Type", "")
    except (TypeError, ValueError):
        return "unavailable"
    if not isinstance(content_type, str):
        return "unavailable"
    media_type = content_type.split(";", 1)[0].strip().casefold()
    if media_type != "application/json" and not media_type.endswith("+json"):
        return "not_json"

    try:
        raw = error.read(MAX_ERROR_BYTES + 1)
    except (OSError, ValueError, TypeError):
        return "unavailable"
    if not isinstance(raw, bytes) or len(raw) > MAX_ERROR_BYTES:
        return "unavailable"
    try:
        obj = json.loads(raw)
    except (ValueError, UnicodeError):
        return "unrecognized"
    if not isinstance(obj, dict):
        return "unrecognized"
    name = obj.get("error")
    if not isinstance(name, str):
        return "unrecognized"
    return name if name in _ALLOWED_ERRORS else "unrecognized"
