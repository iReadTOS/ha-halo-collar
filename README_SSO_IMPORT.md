# Experimental Halo SSO encrypted-vault import for Home Assistant

**Status:** Experimental, unofficial Sign in with Apple support.
The original email/password login remains supported. SSO entries use the same
separately opt-in physical controls as password entries; all are off by default.
Only synthetic tests have validated SSO control dispatch. Halo's live write
authorization for SSO-derived tokens and physical behavior remain unverified.

**Provider limitation:** This uses Halo's mobile OAuth client registration,
not an approved third-party integration registration. Continued access and
compatibility are not guaranteed. Obtain account-owner consent and maintain
a protected Home Assistant backup.

## Verification and limitations

In a limited, account-owner-initiated test, the browser authorization-code flow,
OIDC verification, encrypted-vault import, token refresh, and Home Assistant
telemetry operated successfully. A real SSO account with two collars supplied
telemetry across multiple Home Assistant restarts. This does not establish broad
provider compatibility or independent telemetry accuracy.

The research helper has offline, synthetic OAuth, callback, identity-validation,
transport, and encrypted-vault tests. Home Assistant authentication and control
paths have separate synthetic regression tests. These tests do not contact Halo,
prove live SSO write authorization, or validate physical collar behavior.

**Important:** The following procedure is an experimental Fedora/Linux workflow,
not a native Home Assistant browser sign-in. It uses the existing mobile-app
OAuth registration and the custom `haloapp://` URI scheme; neither is an approved
third-party callback arrangement. Do not treat an accepted login as vendor
approval or guaranteed future compatibility.

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

**Preconditions:** Use a separate, protected Home Assistant test instance with a version of this integration that includes the experimental SSO vault flow. Do not replace a production installation solely to test this feature. The encrypted vault must come from an account-owner-initiated, independently verified sign-in; this does not bypass provider restrictions.


This implementation uses a manual encrypted-vault handoff. It does not
provide native browser login inside Home Assistant.

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

New SSO entries start telemetry-only. The same opt-in fence, Find Collar, and
Recall whistle options available to password entries are also shown for SSO.
They use upstream's existing freshness, account-registration, cooldown, and
command-safety checks. Provider-side authorization of these writes from SSO
tokens has not been verified. Do not issue physical commands to test login.
On the first setup after upgrading from a read-only SSO beta, the integration
automatically clears previously saved fence, Find Collar, and Recall
control opt-ins. Those values were ignored by the old beta and must never
become active merely because of an upgrade. Polling and staleness settings
are preserved. To enable any control afterward, explicitly opt in through
**Configure**. New SSO accounts also start with all controls off.

The new SSO entries use a SHA256 identifier derived from issuer, client ID and
OIDC subject, never just email; the import rejects matching existing password
entries where verified email is available. It cannot prove that two accounts
are distinct if the existing password entry has no verifiable OIDC subject.

**Unsupported provider flow:** This doesn't solve Halo's redirect registration
or whether a mobile app client may be used by a desktop third-party integration.
A separate fork faces the same limitation. Treat this workflow as experimental
until the upstream maintainer has reviewed its compatibility and risks.
