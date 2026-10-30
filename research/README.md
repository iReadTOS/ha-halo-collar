# Halo SSO feasibility experiment (offline only)

This isolated research folder targets a potential contribution to
`iReadTOS/ha-halo-collar` / upstream `itsreverence/ha-halo-collar`.

## Established findings

- Halo's OpenID Connect discovery metadata advertises authorization-code, PKCE
  `S256`, device-code, and refresh-token capabilities at the *server* level.
- The existing `halo.app.android` client returned `unauthorized_client` for a
  device-authorization request both with and without its static app secret.
  Therefore, we should **not** implement device code for that client.
- The official Halo mobile app uses browser-based OIDC, an authorization-code
  response, scopes `openid email offline_access api.dogpark`, and a mobile
  callback `haloapp://callback`.
- It remains **unverified** whether Halo permits a Home Assistant callback URI
  for a client available to this unofficial integration. This is the main
  blocker. The existing mobile callback must not be repurposed to intercept a
  user login or authorization code.

## Scope of this experiment

`sso_oauth.py` builds an authorization URL with fresh state, nonce, and PKCE S256
challenge and parses synthetic callbacks after checking origin and state. It
never makes a network request, opens a browser, logs in, exchanges tokens,
changes an account, or interacts with a collar. All tests use synthetic data.

**This is not yet an installable Home Assistant authentication implementation.**
Proper OIDC token exchange, ID token validation, nonce checks, token refresh,
account identity enforcement, reauthentication, and supported callback setup
would still be required.

## Run locally

From the root of the fork after copying the `research/` folder:

```bash
python3 -m unittest discover -s research -p 'test_*.py' -v
```

## Decision gate for implementation

1. Determine whether an OAuth client usable by the integration has an approved
   callback for Home Assistant, or whether Halo offers an officially supported
   third-party client registration path. Do **not** assume that the mobile
   `haloapp://callback` works for HA.
2. If a compliant redirect is available, implement HA's native OAuth flow and
   reuse the existing `HaloApiClient` token-validation/persistence routines.
3. Keep existing password login functional, test with synthetic tokens first,
   and keep cloud write controls off by default.
4. Never ask users to share Apple login details, access/refresh tokens,
   authorization codes, or private API captures.

## Authorization-code token exchange research

`token_exchange.py` adds the next *offline-only* stage of the experiment:
verify the synthetic callback state and URI, construct an authorization-code
POST using the original PKCE verifier and redirect URI, and validate the
response. `test_token_exchange.py` uses a fake in-memory HTTP session and
synthetic tokens; no tests contact Halo or run a real account login.

This is **not a deployable or complete OIDC login**. We have not established
whether Halo accepts a Home Assistant callback. A real implementation must
also validate ID-token signatures and claims against Halo's verified OIDC
metadata (issuer, audience, expiry, nonce), verify same-account identity,
securely persist and rotate tokens, and handle reauthentication. Do not use
these helpers with live Halo credentials or authorization codes.

The previous unauthenticated GET checks for both the official mobile callback
and Home Assistant's callback returned HTTP 403 without a redirect-specific
error. Cloudflare was listed as the response server but no explicit challenge
marker or block-page indicator was found. This remains **inconclusive**; do
not treat it as proof that the Home Assistant callback is registered or rejected.

## Signed ID-token verification (offline research)

`oidc_identity.py` verifies a synthetic RS256-signed ID token against a supplied
JWKS, including issuer, audience, expiry, issuance time, nonce, authorized party,
and subject. It treats optional email claims as *not verified* unless the token
explicitly asserts `email_verified: true`, and uses the stable issuer+subject
identity rather than trusting email as an account identifier.

A live caller MUST obtain the correct JWKS through authenticated HTTPS from a
validated issuer discovery document; this module intentionally makes no network
requests. Passing an attacker-provided JWKS defeats signature verification.
This remains offline-only and does not enable login or remove the requirement
for a provider-approved HA redirect URI. Additional OIDC checks and HA integration
are required before any production use.

Install the research-only crypto dependency in an ephemeral environment and run
all tests, including the existing stdlib-only tests:

```bash
uv run --no-project --with 'PyJWT[crypto]>=2.10,<3' \
  python -m unittest discover -s research -p 'test_*.py' -v
```
