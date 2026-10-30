"""A localhost-only 302 -> Fedora URI-handler test using fake OAuth data.

Do not point this at Halo or use with actual authorization codes. The only
accepted code is the literal synthetic test value defined below. The demo
uses neither network APIs beyond localhost nor any account credentials.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import tempfile
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit

FAKE_CODE = "synthetic-code"
CALLBACK = "haloapp://callback"
LIFETIME_SECONDS = 300


def storage_dir() -> Path:
    base = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return base / "halo-sso-research" / "302-demo"


def _safe_dir(folder: Path) -> None:
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    if folder.is_symlink() or folder.stat().st_mode & 0o077:
        raise RuntimeError("Demo directory must be private (mode 0700)")


def _write_private(path: Path, text: str) -> None:
    fd, temp = tempfile.mkstemp(prefix=".tmp-", dir=path.parent, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(text)
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def create_session(folder: Path, *, now: float | None = None) -> str:
    """Create fresh state. One pending test at a time, no real OAuth data."""
    _safe_dir(folder)
    pending = folder / "pending.json"
    if pending.exists():
        raise RuntimeError("Previous demo is pending; use 'clear' before restarting")
    (folder / "status.txt").unlink(missing_ok=True)
    state = secrets.token_urlsafe(32)
    _write_private(pending, json.dumps({"state": state, "created": time.time() if now is None else now}))
    return state


def _interpret_callback(url: str, state: str, *, now: float, created: float) -> bool:
    """Require EXACTLY the fake code, correct callback and fresh one-time state."""
    if now < created or now - created > LIFETIME_SECONDS or len(url) > 4096:
        return False
    parsed = urlsplit(url)
    if parsed.scheme != "haloapp" or parsed.netloc != "callback" or parsed.path or parsed.fragment:
        return False
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if len(pairs) != 2 or {k for k, _ in pairs} != {"code", "state"}:
        return False
    params = dict(pairs)
    return params["code"] == FAKE_CODE and secrets.compare_digest(params["state"], state)


def receive_callback(folder: Path, url: str, *, now: float | None = None) -> str:
    """Process *only synthetic* callbacks; never display/store URL or code."""
    _safe_dir(folder)
    pending = folder / "pending.json"
    status = folder / "status.txt"
    try:
        info = json.loads(pending.read_text(encoding="utf-8"))
        valid = _interpret_callback(
            url, info["state"], now=time.time() if now is None else now, created=info["created"]
        )
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        valid = False
    if valid:
        try:
            # Atomic rename consumes pending attempt; a duplicate callback cannot pass.
            os.rename(pending, folder / "consumed.json")
        except OSError:
            valid = False
        else:
            (folder / "consumed.json").unlink(missing_ok=True)
    result = "PASS: one-time synthetic HTTP redirect callback received" if valid else "REJECT: callback was not an active synthetic test"
    _write_private(status, result + "\n")
    return result


def make_handler(state: str):
    destination = CALLBACK + "?" + urlencode({"code": FAKE_CODE, "state": state})

    class DemoHandler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            # Avoid printing request URL or browser-derived information.
            pass

        def do_GET(self):
            path = urlsplit(self.path).path
            if path == "/":
                html = (
                    "<!doctype html><meta charset='utf-8'><title>Local synthetic OAuth demo</title>"
                    "<h2>Local test only — no Halo login</h2>"
                    "<p>This test redirects to a fake <code>haloapp://</code> callback.</p>"
                    "<p><a href='/redirect'>Start synthetic OAuth redirect</a></p>"
                    "<p>No account credentials, tokens, or remote websites are involved.</p>"
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(html)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Referrer-Policy", "no-referrer")
                self.end_headers()
                self.wfile.write(html)
            elif path == "/redirect":
                self.send_response(302)
                self.send_header("Location", destination)
                self.send_header("Cache-Control", "no-store")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()

    return DemoHandler


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("serve", "callback", "status", "clear"))
    parser.add_argument("url", nargs="?")
    args = parser.parse_args()
    folder = storage_dir()
    if args.action == "clear":
        _safe_dir(folder)
        for name in ("pending.json", "consumed.json", "status.txt"):
            (folder / name).unlink(missing_ok=True)
        print("Synthetic demo state cleared")
    elif args.action == "callback":
        if args.url is None:
            return 2
        receive_callback(folder, args.url)  # Deliberately no URL or token output.
    elif args.action == "status":
        try:
            print((folder / "status.txt").read_text(encoding="utf-8").strip())
        except FileNotFoundError:
            print("No callback result yet")
    elif args.action == "serve":
        try:
            state = create_session(folder)
        except RuntimeError as exc:
            print(f"Cannot start demo: {exc}")
            return 1
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(state))
        print(f"Open in Brave: http://127.0.0.1:{server.server_port}/", flush=True)
        print("Click the link on that page, approve the SYNTHETIC handler, then check status.", flush=True)
        print("Press Ctrl+C here when finished.", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
