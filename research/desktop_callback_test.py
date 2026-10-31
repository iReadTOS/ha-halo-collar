"""Synthetic-only Fedora URL-handler experiment for the haloapp scheme.

No network, no credentials, no tokens, no real OAuth handling. This refuses
all input other than a fixed fake authorization response. Never use it for a
real Halo login or as an authentication-code collector.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

EXPECTED_PARAMS = {"code": "synthetic-code", "state": "halo-research-demo"}
STATUS_FILE = Path.home() / ".cache" / "halo-sso-research" / "last-callback-status.txt"


def is_synthetic_callback(uri: str) -> bool:
    """Accept only one known fake callback; never reflect arbitrary URI contents."""
    if not isinstance(uri, str) or len(uri) > 512:
        return False
    try:
        parts = urlsplit(uri)
        params = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=True)
    except ValueError:
        return False
    return (
        parts.scheme == "haloapp"
        and parts.netloc == "callback"
        and parts.path == ""
        and parts.fragment == ""
        and len(params) == 2
        and dict(params) == EXPECTED_PARAMS
    )


def record_status(accepted: bool, *, path: Path = STATUS_FILE) -> None:
    """Write a fixed test result only; never write the supplied URI."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        os.fchmod(out.fileno(), 0o600)
        out.write(
            "PASS: synthetic callback received\n"
            if accepted
            else "IGNORED: non-synthetic callback\n"
        )


def main(args: list[str] | None = None) -> int:
    argv = sys.argv[1:] if args is None else args
    accepted = len(argv) == 1 and is_synthetic_callback(argv[0])
    record_status(accepted)
    return 0 if accepted else 1


if __name__ == "__main__":
    sys.exit(main())
