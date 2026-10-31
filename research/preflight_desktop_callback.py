"""Offline, synthetic GIO URI-handler rehearsal for the Halo SSO probe.

Launches only a fabricated callback through the registered desktop handler.
Does not open Halo/Apple, make token requests, or create a credential vault.
Temporarily sets the live test handler as default and restores the prior one.
"""

from __future__ import annotations

import os
import socket
import stat
import subprocess
import sys
from pathlib import Path

MIME = "x-scheme-handler/haloapp"
LIVE_APP = "halo-live-sso-probe.desktop"
FAKE_CALLBACK = "haloapp://callback?code=synthetic-local-rehearsal&state=synthetic-local-rehearsal"
MAX_CALLBACK = 8192


class PreflightError(RuntimeError):
    """Redacted failure. Do not include the callback or subprocess output."""


def _call(*args: str) -> str:
    try:
        done = subprocess.run(args, capture_output=True, text=True, timeout=8, check=True)
    except (OSError, subprocess.SubprocessError):
        raise PreflightError("Desktop handler query/update failed") from None
    return done.stdout.strip()


def _private_socket_directory() -> Path:
    root = Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache")))
    folder = root / "halo-sso-research" / "live-probe"
    folder.mkdir(parents=True, mode=0o700, exist_ok=True)
    meta = folder.lstat()
    if (
        not stat.S_ISDIR(meta.st_mode)
        or meta.st_uid != os.getuid()
        or stat.S_IMODE(meta.st_mode) != 0o700
    ):
        raise PreflightError(
            "Private callback directory must belong to this user and have mode 0700"
        )
    return folder


def _read_fake_uri(connection: socket.socket) -> str | None:
    data = bytearray()
    while len(data) <= MAX_CALLBACK:
        piece = connection.recv(MAX_CALLBACK + 1 - len(data))
        if not piece:
            return None
        data.extend(piece)
        if b"\n" in piece:
            if len(data) > MAX_CALLBACK or not data.endswith(b"\n") or data.count(b"\n") != 1:
                return None
            try:
                return data[:-1].decode("utf-8")
            except UnicodeError:
                return None
    return None


def rehearsal() -> None:
    target = Path(__file__).resolve().with_name("live_sso_feasibility.py")
    desktop = Path.home() / ".local" / "share" / "applications" / LIVE_APP
    if not target.is_file():
        raise PreflightError("Run from an extracted copy next to live_sso_feasibility.py")
    if not desktop.is_file():
        raise PreflightError("Temporary live .desktop handler is not registered yet")
    try:
        contents = desktop.read_text(encoding="utf-8")
    except OSError:
        raise PreflightError("Unable to read temporary .desktop handler") from None
    exec_lines = [line[5:] for line in contents.splitlines() if line.startswith("Exec=")]
    if (
        len(exec_lines) != 1
        or str(target) not in exec_lines[0]
        or " callback %u" not in exec_lines[0]
        or "x-scheme-handler/haloapp;" not in contents
    ):
        raise PreflightError("Live .desktop Exec or MIME handler does not match this repository")

    previous = _call("xdg-mime", "query", "default", MIME)
    if not previous.endswith(".desktop") or "/" in previous:
        raise PreflightError("No safe previous default handler to restore")

    folder = _private_socket_directory()
    socket_path = folder / "callback.sock"
    if socket_path.exists() or socket_path.is_symlink():
        raise PreflightError("Callback socket already exists; check that no real probe is running")

    changed_default = False
    spawned = None
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(socket_path))
            os.chmod(socket_path, 0o600)
            listener.listen(1)
            listener.settimeout(30)
            changed_default = True
            _call("gio", "mime", MIME, LIVE_APP)
            if _call("xdg-mime", "query", "default", MIME) != LIVE_APP:
                raise PreflightError("Desktop default did not change to the live handler")
            env = os.environ.copy()
            # Avoid package resolution against the network during this local test.
            env["UV_OFFLINE"] = "1"
            try:
                spawned = subprocess.Popen(
                    ["gio", "open", FAKE_CALLBACK],
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except OSError:
                raise PreflightError("Could not launch synthetic callback through GIO") from None
            try:
                connection, _ = listener.accept()
            except TimeoutError:
                raise PreflightError(
                    "No callback arrived; check the .desktop Exec and uv environment"
                ) from None
            with connection:
                connection.settimeout(5)
                try:
                    received = _read_fake_uri(connection)
                except OSError:
                    raise PreflightError("Synthetic callback stream failed") from None
                if received != FAKE_CALLBACK:
                    try:
                        connection.sendall(b"rejected")
                    except OSError:
                        pass
                    raise PreflightError("Unexpected synthetic callback content")
                try:
                    connection.sendall(b"accepted")
                except OSError:
                    raise PreflightError("Could not acknowledge synthetic callback") from None
    finally:
        socket_path.unlink(missing_ok=True)
        if spawned is not None:
            try:
                spawned.wait(timeout=3)
            except subprocess.TimeoutExpired:
                spawned.terminate()
        if changed_default:
            # Restore even on errors; never leave the experimental handler active.
            try:
                _call("gio", "mime", MIME, previous)
            except PreflightError:
                print(
                    f"WARNING: manually restore handler with: gio mime {MIME} {previous}",
                    file=sys.stderr,
                )
                raise
    if _call("xdg-mime", "query", "default", MIME) != previous:
        raise PreflightError("Previous desktop handler was not restored")


def main() -> int:
    try:
        rehearsal()
    except (PreflightError, OSError) as error:
        print(f"STOP: {error}", file=sys.stderr)
        return 1
    print("PASS: GIO dispatched a synthetic URI through the live callback handler")
    print("PASS: Private callback socket received and acknowledged the expected URI")
    print("PASS: Previous default handler restored; no Halo/Apple login attempted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
