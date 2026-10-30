# Optional Halo browser SSO feasibility probe — not an HA integration

**Do not run unless you personally choose to initiate a real Halo/Apple login.**
This is an experimental personal compatibility test using the mobile app's
`halo.app.android` OAuth registration and `haloapp://callback`, **not** a
provider-approved third-party registration. A successful test does not grant
permission to ship or use this as a third-party integration. Halo's policies
and its ability to support third-party OAuth clients remain unverified.

This tool is **not** a Home Assistant integration, does not modify the Halo
account, does not call the collar API or any collar command endpoints, and does
not persist access, refresh, or ID tokens. It fetches Halo's public OIDC
metadata and signing keys, creates a fresh PKCE browser request, optionally
waits for a real browser callback, exchanges one code, verifies the ID token,
and prints only a pass/fail message. A user-initiated login can still create an
authentication session and provider-side logs. Treat any generated tokens as
sensitive, even though the tool immediately drops them.

Security limitations: Linux desktop handlers for custom URL schemes are not
exclusive. The browser passes the callback URI as a process argument (briefly
visible to local process-inspection utilities), although a random state and
PKCE protect against many interception scenarios. The file is never logged or
written to disk by this tool. Use a trusted laptop with no other competing
`haloapp` handler; verify the official `https://auth.halocollar.com` domain
before entering any credentials. Never share callback URLs, tokens, or logs
containing either. No login information is required by ChatGPT.

## Run the completely offline synthetic tests first

From your fork's repository root:

```bash
uv run --no-project --with 'PyJWT[crypto]>=2.10,<3' \
  python -m unittest discover -s research -p 'test_*.py' -q
```

The added tests use in-memory fake HTTPS responses and ephemeral signing keys.
They don't access the real Halo network.

## Optional live compatibility check

The following steps are **optional**, and involve a real Halo account login.
Do not use the test with live credentials if you are uncomfortable using the
mobile application's OAuth registration outside its intended application.

1. Register a **temporary** local Fedora callback handler:

```bash
mkdir -p ~/.local/share/applications
cat > ~/.local/share/applications/halo-live-sso-probe.desktop <<EOF
[Desktop Entry]
Type=Application
Name=Halo SSO Feasibility Probe (Temporary)
Exec=/usr/bin/python3 $PWD/research/live_sso_feasibility.py callback %u
MimeType=x-scheme-handler/haloapp;
NoDisplay=false
Terminal=false
EOF
update-desktop-database ~/.local/share/applications
gio mime x-scheme-handler/haloapp halo-live-sso-probe.desktop
```

2. In the repo root, opt in to a user-initiated test:

```bash
uv run --no-project --with 'PyJWT[crypto]>=2.10,<3' \
  python research/live_sso_feasibility.py start
```

The command loads the official app-level OAuth client values from your fork's
`custom_components/halo_collar/const.py`, retrieves public verified metadata,
and opens Halo's OAuth login page. **Only if you choose to**, use the official
Halo/Apple sign-in page. Select *Halo SSO Feasibility Probe (Temporary)* if
Brave asks which app handles the `haloapp://` callback. The one-time session
expires after five minutes. No authorization code or token is printed.

3. Interpret only the redacted result:

- `PASS: browser sign-in produced a valid Halo identity token. Tokens discarded.`
  means that the tested authorization-code exchange and ID-token verification
  worked for one session. It does **not** mean that Halo approves independent
  clients or that its collar API/refresh works from HA.
- `STOP: Provider rejected the request (HTTP NNN)` or a validation error means
  that this route remains unverified. Do not paste sensitive OAuth URLs, traces,
  tokens, or cookies into an issue or ChatGPT.

4. Immediately restore the previous synthetic handler and remove the temporary
registration:

```bash
gio mime x-scheme-handler/haloapp halo-sso-research.desktop
rm ~/.local/share/applications/halo-live-sso-probe.desktop
update-desktop-database ~/.local/share/applications
```

`Ctrl+C` also ends the waiting process. The socket is cleaned up normally. If
a crash leaves a socket behind, inspect and remove only your private test
socket at `~/.cache/halo-sso-research/live-probe/callback.sock` after ensuring
no test process is still running.

## Do not merge or deploy

Do not merge this helper into the Home Assistant runtime or use it with
real collars. A supported long-term solution requires Halo to approve an
OAuth client and redirect for third-party use, plus secure token persistence,
refresh, identity linking, and HA reauth handling.
