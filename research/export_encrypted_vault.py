"""Print only the BASE64 representation of a local passphrase-encrypted vault.

Never prints plaintext tokens and never touches Halo or Home Assistant.
Copy the encrypted output directly to the Home Assistant SSO vault form.
Treat the encrypted text as sensitive; never upload it to issues or chat.
"""
from __future__ import annotations

import base64
import os
import stat
import sys
from pathlib import Path


def export_vault(path: Path) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags), "rb") as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 131072):
            raise ValueError("Vault is not a private file")
        payload = source.read(131073)
    if not payload.startswith(b"HALO-SSO-ESCROW-v1\x00") or len(payload) > 131072:
        raise ValueError("Not a supported encrypted vault")
    return base64.b64encode(payload).decode("ascii")


if __name__ == "__main__":
    # Import avoids requiring any research package dependencies.
    path = Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local/share"))) / "halo-sso-research" / "verified-sso.halo-vault"
    try:
        print(export_vault(path))
    except (OSError, ValueError):
        print("STOP: Encrypted vault unavailable or permissions unsafe", file=sys.stderr)
        raise SystemExit(1) from None
