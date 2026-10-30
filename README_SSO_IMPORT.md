# Experimental Halo SSO encrypted-vault import for Home Assistant

**Status:** staged experimental importer. Does not enable third-party Halo OAuth.
Original email/password setup stays supported. Import is optional and manual.
**Do not install in production Home Assistant until the pinned HA suite passes,
and until you are comfortable with the unsupported provider/client status.**

The prior browser feasibility probe can, *only if Halo accepts a real OAuth exchange*,
write `~/.local/share/halo-sso-research/verified-sso.halo-vault` after ID-token
signature and nonce verification. This package creates an HA config flow for that
vault. The current browser login may fail at Halo's token endpoint with HTTP 403.
We cannot guarantee first-try authentication, refresh, or continued account access.

## Local installation (source only; no HA deployment)

In the `experiment/browser-sso` branch, from repo root:

```sh
unzip -o ~/Downloads/halo_ha_vault_importer.zip -d .
python3 install_sso_vault.py
uv sync --extra dev
uv run pytest -q
uv run --isolated --python /usr/bin/python3 \
  --with-requirements requirements_test_ha_stable.txt pytest -q
```

The installer verifies that the existing source matches expected anchors before
modifying tracked integration files, compiles edited Python first, and adds
cryptography to the development-test dependencies. Review
`git diff`, and **do not install in production HA yet**. Leave the root-level
installer out of commits; it only applies source modifications.

## After a successful, account-owner-approved login (future, NOT required now)

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
