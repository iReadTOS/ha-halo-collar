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
Core restarts. The isolated Home Assistant test suite passed 552 tests on the SSO diagnostics privacy-fix commit (`bf50677`).

Limited real-account testing successfully retrieved sensor values from two paired collars, survived three Home Assistant Core restarts, and remained operational overnight. Broader compatibility and individual telemetry accuracy still require verification. The old
`urllib` HTTP 403 issue was resolved for the tested exchange by using
`aiohttp`, but the underlying transport difference remains unconfirmed.

## Creating an encrypted SSO vault on Fedora

This experimental procedure uses Halo's mobile OAuth registration,
not an approved third-party client. Only authenticate to an account
you own or are authorized to use. Stop if Halo rejects the request.

Use a trusted Fedora session. Custom URI handlers are not exclusive,
and callback URLs can briefly appear in local process arguments.
Never share OAuth callbacks, vault files, passphrases, or tokens.

### Prepare a private vault location

From the root of this repository:

~~~sh
export HALO_SSO_DATA="$HOME/.local/share/halo-sso-beta"
mkdir -p "$HALO_SSO_DATA"
chmod 700 "$HALO_SSO_DATA"
test ! -e "$HALO_SSO_DATA/halo-sso-research/verified-sso.halo-vault"
~~~

Use a separate private directory for each account. The vault writer
will not overwrite an existing vault.

### Register the temporary callback handler

Record the current handler before changing it:

~~~sh
xdg-mime query default x-scheme-handler/haloapp
~~~

Then register the experimental handler:

~~~sh
mkdir -p ~/.local/share/applications
cat > ~/.local/share/applications/halo-sso-beta.desktop <<EOF
[Desktop Entry]
Type=Application
Name=Halo SSO Beta Research
Exec=$(command -v uv) run --no-project --with "PyJWT[crypto]>=2.10,<3" --with "aiohttp>=3.9,<4" python "$PWD/research/live_sso_feasibility.py" callback %u
MimeType=x-scheme-handler/haloapp;
NoDisplay=false
Terminal=false
EOF
update-desktop-database ~/.local/share/applications
gio mime x-scheme-handler/haloapp halo-sso-beta.desktop
~~~

### Authenticate and create the vault

~~~sh
XDG_DATA_HOME="$HALO_SSO_DATA" \
uv run --no-project \
  --with 'PyJWT[crypto]>=2.10,<3' \
  --with 'aiohttp>=3.9,<4' \
  python research/live_sso_feasibility.py start --save-encrypted
~~~

Choose a strong vault passphrase when prompted. Authenticate only
through the legitimate Halo/Apple sign-in page. The callback expires
after five minutes. The helper validates the identity and encrypts
tokens locally; it never sends collar commands.

### Verify the encrypted vault

~~~sh
XDG_DATA_HOME="$HALO_SSO_DATA" \
uv run --no-project \
  --with 'PyJWT[crypto]>=2.10,<3' \
  python research/secure_token_bundle.py check
~~~

A successful check confirms the vault decrypts and has the expected
format without printing credentials.

### Export for Home Assistant

On Fedora Wayland, install `wl-clipboard` if needed. Copy the
encrypted vault directly to the clipboard:

~~~sh
XDG_DATA_HOME="$HALO_SSO_DATA" \
python3 research/export_encrypted_vault.py | wl-copy
~~~

Continue with the Home Assistant import instructions below.
Clear the clipboard and any clipboard history after importing.

### Restore the previous callback handler

Restore the handler recorded earlier using `gio mime`, then remove
the temporary desktop entry:

~~~sh
rm ~/.local/share/applications/halo-sso-beta.desktop
update-desktop-database ~/.local/share/applications
~~~

Keep the encrypted vault and passphrase protected outside Git.
Home Assistant does not synchronize rotated credentials back to
the original vault. Reauthentication may require a fresh login.

## Importing encrypted credentials into Home Assistant

**Preconditions:** Use a separate, protected Home Assistant test instance with the fork's `experiment/browser-sso` branch installed; do not replace your existing upstream integration to experiment. The encrypted vault must already exist from an account-owner-initiated, independently verified SSO research session. This page is not a guide to bypass the provider's unsupported OAuth client restrictions.


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

If you later need reauthentication, create a **new** encrypted vault with the same verified provider account identity; expired vault content cannot be reused as a reliable refresh source. Never edit config-entry token or subject fields by hand.

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
