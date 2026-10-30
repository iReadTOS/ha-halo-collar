"""OPT-IN, local-only Halo browser SSO feasibility probe.

This uses the mobile app's OAuth registration for a user-initiated, personal
technical test. It is NOT an officially approved third-party OAuth client or
Home Assistant login feature. It never accesses the collar API, never sends
collar commands, and never persists access/refresh/ID tokens.

Desktop callback still briefly passes via process argv (%u); desktop custom
URI schemes are not exclusive, even though PKCE and random state help protect
against interception. Run only if you accept these limitations.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import socket
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from pathlib import Path
from typing import Any

from oidc_identity import IDTokenValidationError, OIDC_ISSUER, verify_id_token
from sso_oauth import OAuthResponseError, create_request, validate_callback
from token_exchange import TokenExchangeError, build_exchange_data, parse_token_response

AUTHORITY = "https://auth.halocollar.com"
DISCOVERY_URL = AUTHORITY + "/.well-known/openid-configuration"
JWKS_URL = DISCOVERY_URL + "/jwks"
AUTHORIZE_URL = AUTHORITY + "/connect/authorize"
TOKEN_URL = AUTHORITY + "/connect/token"
CALLBACK = "haloapp://callback"
SCOPE = "openid email offline_access api.dogpark"
CLIENT_ID = "halo.app.android"
MAX_BODY = 131072
MAX_CALLBACK = 8192
TIMEOUT = 300


class ProbeError(Exception):
    """Safe-to-display error. Never contain credential, code, URL or token."""


def private_folder() -> Path:
    root = Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache")))
    path = root / "halo-sso-research" / "live-probe"
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ProbeError("Private callback directory must belong to you and be mode 0700")
    return path


def _read_constants() -> tuple[str, str]:
    """Read distributed *application* client values without importing HA or printing them."""
    const = Path(__file__).resolve().parent.parent / "custom_components/halo_collar/const.py"
    try:
        tree = ast.parse(const.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        raise ProbeError("Can't read OAuth app defaults from integration const.py") from None
    values = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in ("DEFAULT_CLIENT_ID", "DEFAULT_CLIENT_SECRET"):
                try:
                    values[name] = ast.literal_eval(node.value)
                except (ValueError, TypeError):
                    raise ProbeError("Invalid OAuth app defaults in const.py") from None
    if values.get("DEFAULT_CLIENT_ID") != CLIENT_ID or not isinstance(values.get("DEFAULT_CLIENT_SECRET"), str) or not values["DEFAULT_CLIENT_SECRET"]:
        raise ProbeError("Unexpected OAuth app client configuration")
    return CLIENT_ID, values["DEFAULT_CLIENT_SECRET"]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args):
        return None


def https_json(url: str, *, post: dict[str, str] | None = None, opener=None) -> dict[str, Any]:
    """HTTPS requests only to exact trusted provider endpoints, no redirects."""
    if url not in (DISCOVERY_URL, JWKS_URL, TOKEN_URL):
        raise ProbeError("Unexpected identity-provider endpoint")
    if opener is None:
        opener = urllib.request.build_opener(NoRedirect())
    data = None if post is None else urllib.parse.urlencode(post).encode("ascii")
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    request = urllib.request.Request(url, data=data, headers=headers, method="POST" if post is not None else "GET")
    try:
        with opener.open(request, timeout=15) as response:
            status = response.status
            raw = response.read(MAX_BODY + 1)
    except urllib.error.HTTPError as exc:
        # Do not print the provider's response body, which can include sensitive values.
        raise ProbeError(f"Provider rejected the request (HTTP {exc.code})") from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise ProbeError("Provider request failed or timed out") from None
    if status != 200 or len(raw) > MAX_BODY:
        raise ProbeError(f"Unexpected provider response (HTTP {status})")
    try:
        parsed = json.loads(raw)
    except (ValueError, UnicodeError):
        raise ProbeError("Provider returned invalid JSON") from None
    if not isinstance(parsed, dict):
        raise ProbeError("Provider returned invalid JSON object")
    return parsed


def trusted_keys(*, opener=None) -> dict[str, Any]:
    metadata = https_json(DISCOVERY_URL, opener=opener)
    if (metadata.get("issuer") != OIDC_ISSUER
            or metadata.get("jwks_uri") != JWKS_URL
            or metadata.get("authorization_endpoint") != AUTHORIZE_URL
            or metadata.get("token_endpoint") != TOKEN_URL
            or "RS256" not in metadata.get("id_token_signing_alg_values_supported", [])
            or "S256" not in metadata.get("code_challenge_methods_supported", [])):
        raise ProbeError("Provider discovery did not match trusted Halo endpoints")
    keys = https_json(JWKS_URL, opener=opener)
    if not isinstance(keys.get("keys"), list) or not keys["keys"]:
        raise ProbeError("Provider signing keys unavailable")
    return keys


def token_exchange(code: str, request, *, client_secret: str, jwks: dict[str, Any], opener=None):
    """Exchange once and verify an ID token; never persist/print token values."""
    form = build_exchange_data(auth_request=request, authorization_code=code,
                               client_id=CLIENT_ID, client_secret=client_secret)
    payload = https_json(TOKEN_URL, post=form, opener=opener)
    tokens = parse_token_response(200, payload)
    identity = verify_id_token(tokens.id_token, jwks=jwks,
                               client_id=CLIENT_ID, expected_nonce=request.nonce)
    # Only a boolean result is returned; tokens are dropped on return.
    return bool(identity.subject)


def handle_callback(uri: str, path: Path) -> int:
    """Forward URI over private Unix socket to the waiting parent; no log/files."""
    if not isinstance(uri, str) or not uri.startswith(CALLBACK + "?") or len(uri) > MAX_CALLBACK:
        return 2
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(4)
            sock.connect(str(path / "callback.sock"))
            sock.sendall(uri.encode("utf-8") + b"\n")
            reply = sock.recv(16)
        return 0 if reply == b"accepted" else 1
    except (OSError, ValueError, UnicodeError):
        return 1


def run_live(*, open_browser=webbrowser.open, callback_folder: Path | None = None, opener=None) -> bool:
    """Only called from explicit start command. Tokens and codes remain in memory."""
    client_id, client_secret = _read_constants()
    jwks = trusted_keys(opener=opener)
    request = create_request(client_id=client_id, redirect_uri=CALLBACK,
                             authorization_endpoint=AUTHORIZE_URL, scope=SCOPE)
    folder = callback_folder or private_folder()
    sock_path = folder / "callback.sock"
    if sock_path.exists() or sock_path.is_symlink():
        raise ProbeError("Callback socket already exists; check for another running probe")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(sock_path))
        os.chmod(sock_path, 0o600)
        listener.listen(2)
        deadline = time.monotonic() + TIMEOUT
        try:
            print("Starting optional live test. Authenticate only if you choose to.", flush=True)
            print("No collar APIs are called and no tokens will be saved.", flush=True)
            if not open_browser(request.authorization_url):
                print("Open the authorization page manually in your browser if needed.", flush=True)
                print("Do not copy its URL or callback into this chat.", flush=True)
            while time.monotonic() < deadline:
                listener.settimeout(max(0.1, deadline - time.monotonic()))
                try:
                    connection, _ = listener.accept()
                except socket.timeout:
                    break
                with connection:
                    connection.settimeout(4)
                    data = connection.recv(MAX_CALLBACK + 1)
                    if len(data) > MAX_CALLBACK or not data.endswith(b"\n"):
                        connection.sendall(b"rejected")
                        continue
                    try:
                        raw_url = data[:-1].decode("utf-8")
                        code = validate_callback(raw_url, request)
                    except (UnicodeError, OAuthResponseError, ValueError):
                        connection.sendall(b"rejected")
                        continue
                    connection.sendall(b"accepted")
                    # The browser callback has arrived and its random state matches.
                    # Stop listening before attempting the one-time code exchange.
                    print("Matching callback received; checking token exchange without saving tokens.", flush=True)
                    return token_exchange(code, request, client_secret=client_secret,
                                          jwks=jwks, opener=opener)
            raise ProbeError("No matching callback arrived before the test expired")
        finally:
            sock_path.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Opt-in Halo SSO feasibility research (not a HA integration)")
    parser.add_argument("command", choices=("start", "callback"))
    parser.add_argument("callback_uri", nargs="?")
    args = parser.parse_args()
    try:
        if args.command == "callback":
            if not args.callback_uri:
                return 2
            return handle_callback(args.callback_uri, private_folder())
        if args.callback_uri:
            return 2
        print("This test uses Halo's mobile OAuth registration, not a provider-approved third-party client.")
        print("You will be redirected to Halo/Apple if you voluntarily continue in the browser.")
        success = run_live()
        if success:
            print("PASS: browser sign-in produced a valid Halo identity token. Tokens discarded.")
        return 0 if success else 1
    except (ProbeError, TokenExchangeError, IDTokenValidationError, ValueError) as exc:
        print(f"STOP: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
