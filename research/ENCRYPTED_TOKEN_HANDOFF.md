# Opt-in encrypted Halo SSO token escrow — research only

**Goal:** If a consenting account holder completes the existing experimental
browser login and Halo accepts the code exchange, preserve verified access and
refresh tokens so they need not automatically repeat authentication solely
because the previous prototype discarded the result.

This is NOT a complete Home Assistant SSO integration and does not establish
that Halo permits third-party use of `halo.app.android` / `haloapp://callback`.
The token endpoint has returned HTTP 403 to previous *invalid* preflight calls,
so a real authorization-code exchange may still fail. Stop on a 403; do not
bypass provider restrictions. Neither Apple authentication nor a saved token
bundle guarantees that refresh will work, that the account is the right one,
or that access persists. Never submit authorization URLs, passphrases, tokens,
cookies, token files, or private OAuth responses to chat or GitHub.

## Security properties

- Off by default: without `--save-encrypted`, successful logins still discard tokens.
- Before browsing, checks the destination and asks twice for a passphrase (12+ chars).
- After authorization-code exchange, validates RS256 ID-token signature, issuer,
  audience, expiry, and nonce against Halo's verified published signing keys.
- Only then encrypts access/refresh credentials plus verified issuer/subject
  using Scrypt + AES-256-GCM. ID token and authorization code are **not saved**.
- Vault directory is owner-only (0700); file owner-only (0600), with an
  exclusive-create that never overwrites a previous bundle; vault is outside Git.
- `check` decrypts locally and reports only pass/fail, not secrets or identity.
- Decryption does not reauthenticate or re-verify the original signed ID token;
  the eventual HA importer must safely preserve subject binding, refresh tokens,
  check that the account has the expected collars, and reject account switches.
- Local custom-scheme callbacks temporarily appear in process arguments, which
  is a security limitation. Use only a trusted user session and owner-approved login.

## Install via ZIP

From the repository root, ensure working files are committed, then extract the
ZIP so that its `research/` files overlay existing `research/` files:

```sh
git switch experiment/browser-sso
git status --short
unzip -o ~/Downloads/halo_encrypted_sso_escrow.zip -d .
```

The ZIP modifies only `research/live_sso_feasibility.py` and adds:
`research/secure_token_bundle.py`, `research/test_secure_token_bundle.py`,
`research/test_secure_token_probe.py`, and this document.

Run the full offline suite:

```sh
uv run --no-project --with 'PyJWT[crypto]>=2.10,<3' \
  python -m unittest discover -s research -p 'test_*.py' -q
```

All tests are synthetic. None opens Halo or logs into an account.

## Optional live attempt **only with the account holder's consent**

Do **not** run this if Halo disallows independent use of its mobile OAuth
registration. The code is an isolated feasibility experiment, not supported by
Halo. A token POST rejection or callback error is not reason to retry to bypass
any restrictions.

Register the temporary desktop handler as documented in
`research/LIVE_SSO_FEASIBILITY.md`, using `uv` rather than system Python.
From the repo root, run:

```sh
uv run --no-project --with 'PyJWT[crypto]>=2.10,<3' \
  python research/live_sso_feasibility.py start --save-encrypted
```

Choose a **new strong vault passphrase**. Do not put it in command arguments,
configuration files, or chat. If the signed login succeeds and the save succeeds,
the tool reports a vault at:

`~/.local/share/halo-sso-research/verified-sso.halo-vault`

Check it locally (no token output):

```sh
uv run --no-project --with 'PyJWT[crypto]>=2.10,<3' \
  python research/secure_token_bundle.py check
```

Restore/remove the temporary `haloapp://` handler after completing or
aborting the attempt. The secret vault is NOT stored inside the repository,
not uploaded to GitHub, and not consumed automatically by HA yet. Do not place
it in public or unencrypted backup locations.

## Remaining integration work, **before claiming one-login setup**

1. Build a controlled Home Assistant encrypted-bundle import that consumes the
   payload only inside HA, checks issuer/client/subject, establishes a dedicated
   SSO credential lineage, and never displays or logs tokens/passphrases.
2. Wire refreshed tokens into existing `_TokenWriter` and test same-account
   reauthentication, token rotation, service restart, fail-closed errors,
   and the two-collar read-only flow under the pinned HA harness.
3. Verify with the account owner that the account and collars are correct,
   and that Halo authorizes the client/redirect scheme. The account holder may
   still need to authenticate again if refresh fails or provider rules change.

**Do not install this research code into your production HA instance.**
