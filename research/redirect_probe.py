"""Inspect pre-login OAuth redirect handling without authenticating.

This standalone research utility only GETs the provider's /connect/authorize
endpoint, never follows HTTP redirects, never obtains or exchanges codes, and
never sends account credentials. It is **not** an OAuth client and does not
prove that a redirect URI is registered when the result is inconclusive.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import re
import secrets
import sys
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

AUTH_ENDPOINT = "https://auth.halocollar.com/connect/authorize"
CLIENT_ID = "halo.app.android"  # Public, static app-level identifier.
SCOPE = "openid email offline_access api.dogpark"
OFFICIAL_REDIRECT = "haloapp://callback"
HOME_ASSISTANT_REDIRECT = "https://my.home-assistant.io/redirect/oauth"
MAX_RESPONSE_BYTES = 128 * 1024


class StopRedirects(HTTPRedirectHandler):
    """Prevent follow-up requests or visits to login/callback URLs."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass(frozen=True)
class ProbeResult:
    status: int
    signal: str


def make_authorize_url(redirect_uri: str) -> str:
    """Generate a syntactically valid pre-login OIDC authorization URL."""
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    query = urlencode(
        {
            "client_id": CLIENT_ID,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": SCOPE,
            "state": secrets.token_urlsafe(32),
            "nonce": secrets.token_urlsafe(32),
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "prompt": "login",
        }
    )
    return f"{AUTH_ENDPOINT}?{query}"


def classify_response(status: int, body: bytes) -> ProbeResult:
    """Report only coarse, privacy-safe signals, never raw response data."""
    # A rejection is only redirect-specific if the response says so.
    # Generic HTTP 200 or a login redirect does not prove redirect registration.
    text = body.decode("utf-8", errors="replace").lower()
    text = re.sub(r"<[^>]{0,4096}>", " ", text)
    if re.search(r"invalid[ _-]+redirect(?:[ _-]+uri|[ _-]+url)?|redirect(?:[ _-]+uri|[ _-]+url)?[ _-]+(?:is[ _-]+)?invalid", text):
        signal = "redirect_rejected"
    elif "unauthorized_client" in text:
        signal = "client_not_authorized"
    elif status in (301, 302, 303, 307, 308):
        signal = "redirect_not_followed_unverified"
    elif status >= 500:
        signal = "server_error"
    elif status >= 400:
        signal = "rejected_reason_unknown"
    else:
        signal = "non_error_unverified"
    return ProbeResult(status, signal)


def probe(redirect_uri: str, *, opener=None) -> ProbeResult:
    """Issue exactly one non-authenticated GET with redirects disabled."""
    if opener is None:
        opener = build_opener(StopRedirects())
    url = make_authorize_url(redirect_uri)
    request = Request(url, headers={"Accept": "text/html,application/json"}, method="GET")
    try:
        with opener.open(request, timeout=12) as response:
            status = response.status
            body = response.read(MAX_RESPONSE_BYTES)
    except HTTPError as error:
        # urllib raises HTTPError for 3xx when redirect-following is disabled.
        with error:
            status = error.code
            body = error.read(MAX_RESPONSE_BYTES)
    return classify_response(status, body)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--compare",
        action="store_true",
        help="Compare the known official app callback with HA's standard callback",
    )
    args = parser.parse_args()
    targets = (
        (("official_app", OFFICIAL_REDIRECT), ("home_assistant", HOME_ASSISTANT_REDIRECT))
        if args.compare
        else (("home_assistant", HOME_ASSISTANT_REDIRECT),)
    )
    print("Pre-login check only; no authentication, redirects, or token exchange.")
    for label, redirect_uri in targets:
        try:
            result = probe(redirect_uri)
        except (URLError, TimeoutError, OSError) as error:
            print(f"{label}: transport_error ({type(error).__name__})")
            return 1
        print(f"{label}: HTTP {result.status}, {result.signal}")
    print("A non-error response alone does NOT prove that an OAuth callback is allowed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
