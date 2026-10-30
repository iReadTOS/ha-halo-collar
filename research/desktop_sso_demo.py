"""Loopback-only browser demo for a ONE-TIME FAKE OAuth desktop session.

Does not visit Halo, perform a real login, or exchange/store tokens. Desktop
handler must only be registered temporarily for this local research demo.
"""

from __future__ import annotations

import argparse
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlencode, urlsplit

from desktop_sso_session import (
    CALLBACK_URI,
    SYNTHETIC_CODE,
    DesktopSessionError,
    clear_session,
    complete_session,
    get_status,
    new_session,
)


def session_dir() -> Path:
    return Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "halo-sso-research" / "desktop-session"


def demo_handler(state: str):
    callback = CALLBACK_URI + "?" + urlencode({"code": SYNTHETIC_CODE, "state": state})

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass  # Never log paths containing login state.

        def do_GET(self):
            path = urlsplit(self.path).path
            if path == "/":
                payload = (
                    b"<!doctype html><meta charset='utf-8'><title>Offline PKCE demo</title>"
                    b"<h2>Local synthetic login test</h2>"
                    b"<p>No Halo or Apple account is involved.</p>"
                    b"<p><a href='/redirect'>Simulate authorization response</a></p>"
                )
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Referrer-Policy", "no-referrer")
                self.end_headers()
                self.wfile.write(payload)
            elif path == "/redirect":
                self.send_response(302)
                self.send_header("Location", callback)
                self.send_header("Cache-Control", "no-store")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()

    return Handler


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("serve", "callback", "status", "clear"))
    parser.add_argument("url", nargs="?")
    args = parser.parse_args()
    folder = session_dir()
    if args.action == "clear":
        clear_session(folder)
        print("Synthetic session cleared")
    elif args.action == "callback":
        if not args.url:
            return 2
        complete_session(folder, args.url)  # Never print the callback or tokens.
    elif args.action == "status":
        print(get_status(folder))
    elif args.action == "serve":
        try:
            request = new_session(folder)
        except DesktopSessionError:
            print("A session is already pending; run 'clear' first")
            return 1
        server = ThreadingHTTPServer(("127.0.0.1", 0), demo_handler(request.state))
        print(f"Open in Brave: http://127.0.0.1:{server.server_port}/", flush=True)
        print("Click 'Simulate authorization response' to start the synthetic redirect.", flush=True)
        print("Ctrl+C ends the local server. No remote network requests are made.", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
