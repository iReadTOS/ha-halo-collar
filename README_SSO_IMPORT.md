# Experimental Halo SSO encrypted-vault import for Home Assistant

**Status:** Experimental, unofficial Sign in with Apple support.
The original email/password login and its opt-in write controls remain supported.
Imported SSO entries deliberately disable write controls.

**Provider limitation:** This uses Halo's mobile OAuth client registration,
not an approved third-party integration registration. Continued access and
compatibility are not guaranteed. Obtain account-owner consent and maintain
a protected Home Assistant backup.

## Verified results

A real Sign in with Apple browser authentication succeeded using an OAuth
authorization-code exchange through `aiohttp`. OIDC identity verification,
encrypted vault creation, and Home Assistant vault import also succeeded.

In the no-collar test account, Home Assistant successfully refreshed OAuth
credentials, persisted the rotated credentials, and recovered after multiple
Core restarts. The isolated Home Assistant test suite passed 551 tests.

Live telemetry for paired collars has not yet been validated. The old
`urllib` HTTP 403 issue was resolved for the tested exchange by using
`aiohttp`, but the underlying transport difference remains unconfirmed.

## Importing encrypted credentials into Home Assistant

This beta uses a manual encrypted-vault handoff. It does not yet provide
a native browser login inside Home Assistant.

The vault stays on Fedora, and is not placed in Git. To copy only its **encrypted**
contents into HA, run locally:

```sh
python3 research/export_encrypted_vault.py
```

This prints a base64 encoding of the **encrypted** vault, not raw token values.
Treat it as sensitive anyway. Copy it into Home Assistant's Add Integration >
Halo Collar > Import encrypted SSO vault form. Enter the passphrase in the
separate password field. HA decrypts in memory; it stores access/refresh tokens
in its own config entry (HA backups and storage access must remain protected),
not the passphrase or original encrypted blob.

**No token, passphrase, or vault text should be pasted into ChatGPT or GitHub.**
Use a private, HTTPS HA session only. You may retain the encrypted original on
Fedora but protect it and its passphrase. Deleting it does not revoke a refresh
token already stored by HA. Rotated refresh tokens in HA do **not** update the
original Fedora vault, so the saved vault is not a reliable reauthentication
source after token rotation. New sign-in may still be required.

The first HA refresh performs read-only GET requests; imported SSO entries do not
initialize the write transport and do not load buttons/switches, even if control
options are changed. Password-grant entries keep upstream behavior.

The new SSO entries use a SHA256 identifier derived from issuer, client ID and
OIDC subject, never just email; the import rejects matching existing password
entries where verified email is available. It cannot prove that two accounts
are distinct if the existing password entry has no verifiable OIDC subject.

**Unsupported provider flow:** This doesn't solve Halo's redirect registration
or whether a mobile app client may be used by a desktop third-party integration.
A separate fork would face that same problem. Keep the branch experimental.
