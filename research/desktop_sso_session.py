"""Private, single-use, synthetic desktop OAuth session (research only).

This code NEVER authenticates with Halo or exchanges real credentials. Its
callback accepts ONLY a fixed synthetic authorization code, not real ones.
"""

from __future__ import annotations

import fcntl
import json
import os
import secrets
import stat
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator
from urllib.parse import parse_qsl, urlsplit

from sso_oauth import AuthorizationRequest, OAuthResponseError, create_request, validate_callback

SYNTHETIC_CODE = "synthetic-code"
CALLBACK_URI = "haloapp://callback"
DEMO_CLIENT_ID = "halo.synthetic.offline"
DEMO_AUTH_ENDPOINT = "https://synthetic.invalid/authorize"
SESSION_TTL = 300


class DesktopSessionError(ValueError):
    """Deliberately generic: errors never contain OAuth values."""


@dataclass(frozen=True, repr=False)
class CompletedSyntheticSession:
    """An already-consumed synthetic login attempt; never print its internals."""

    request: AuthorizationRequest

    def __repr__(self) -> str:
        return "CompletedSyntheticSession(<redacted>)"


def _private_dir(folder: Path) -> None:
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    meta = folder.lstat()
    if not stat.S_ISDIR(meta.st_mode) or stat.S_IMODE(meta.st_mode) != 0o700:
        raise DesktopSessionError("Private research directory unavailable")
    if meta.st_uid != os.getuid():
        raise DesktopSessionError("Private research directory owner mismatch")


def _private_open(path: Path, flags: int, *, create: bool = False) -> int:
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags | (os.O_CREAT if create else 0), 0o600)
    meta = os.fstat(fd)
    if not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid() or stat.S_IMODE(meta.st_mode) != 0o600:
        os.close(fd)
        raise DesktopSessionError("Private research file unavailable")
    return fd


@contextmanager
def _locked(folder: Path) -> Iterator[None]:
    _private_dir(folder)
    fd = _private_open(folder / "session.lock", os.O_RDWR, create=True)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _status(folder: Path, message: str) -> None:
    fd = _private_open(folder / "status.txt", os.O_WRONLY | os.O_TRUNC, create=True)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(message + "\n")


def _read_pending(folder: Path) -> dict:
    fd = _private_open(folder / "pending.json", os.O_RDONLY)
    with os.fdopen(fd, "r", encoding="utf-8") as stream:
        raw = stream.read(8193)
    if len(raw) > 8192:
        raise DesktopSessionError("Invalid research session")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise DesktopSessionError("Invalid research session")
    return value


def new_session(folder: Path, *, now: float | None = None) -> AuthorizationRequest:
    """Make a fresh OIDC-shaped attempt, but never open the synthetic IdP URL."""
    request = create_request(
        client_id=DEMO_CLIENT_ID,
        redirect_uri=CALLBACK_URI,
        authorization_endpoint=DEMO_AUTH_ENDPOINT,
        scope="openid offline.synthetic",
    )
    with _locked(folder):
        # O_EXCL means an unfinished attempt cannot be overwritten.
        try:
            fd = _private_open(folder / "pending.json", os.O_WRONLY | os.O_EXCL, create=True)
        except FileExistsError:
            raise DesktopSessionError("A research session is already pending") from None
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump({
                "created": time.time() if now is None else now,
                "state": request.state,
                "nonce": request.nonce,
                "verifier": request.code_verifier,
            }, stream)
        (folder / "status.txt").unlink(missing_ok=True)
    return request


def complete_session(
    folder: Path, callback_url: str, *, now: float | None = None
) -> CompletedSyntheticSession | None:
    """Consume exactly one matching synthetic callback, without persisting the URL.

    A successful return means ONLY callback validation, not authentication.
    Never call the real token endpoint from this code.
    """
    with _locked(folder):
        try:
            info = _read_pending(folder)
            created = info["created"]
            current = time.time() if now is None else now
            if (
                type(created) not in (int, float)
                or not isinstance(callback_url, str)
                or len(callback_url) > 4096
                or current < created
                or current - created > SESSION_TTL
            ):
                raise DesktopSessionError("Invalid or expired research session")
            request = AuthorizationRequest(
                authorization_url=DEMO_AUTH_ENDPOINT,
                redirect_uri=CALLBACK_URI,
                state=info["state"],
                nonce=info["nonce"],
                code_verifier=info["verifier"],
            )
            if not all(isinstance(x, str) and x for x in (request.state, request.nonce, request.code_verifier)):
                raise DesktopSessionError("Invalid research session")
            parts = urlsplit(callback_url)
            params = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=True)
            if len(params) != 2 or {key for key, _ in params} != {"code", "state"}:
                raise DesktopSessionError("Invalid synthetic response")
            code = validate_callback(callback_url, request)
            if not secrets.compare_digest(code, SYNTHETIC_CODE):
                raise DesktopSessionError("Non-synthetic authorization code rejected")
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, OAuthResponseError):
            _status(folder, "REJECT: not a valid pending synthetic callback")
            return None

        # This consumes the attempt while holding the interprocess lock.
        (folder / "pending.json").unlink()
        _status(folder, "PASS: one-time PKCE session callback received")
        return CompletedSyntheticSession(request)


def get_status(folder: Path) -> str:
    with _locked(folder):
        try:
            fd = _private_open(folder / "status.txt", os.O_RDONLY)
        except FileNotFoundError:
            return "No callback result yet"
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            return stream.read(256).strip()


def clear_session(folder: Path) -> None:
    with _locked(folder):
        (folder / "pending.json").unlink(missing_ok=True)
        (folder / "status.txt").unlink(missing_ok=True)
