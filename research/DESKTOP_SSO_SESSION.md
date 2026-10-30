# Synthetic desktop authentication session (local research only)

This experiment extends the earlier Fedora/Brave `haloapp://callback` demo with:

- Fresh PKCE S256 verifier/challenge, state, and nonce per attempt
- A private, 0700 local directory with 0600 attempt files
- One active session at a time, a five-minute lifetime, and an interprocess lock
- One-time consumption of the exact synthetic `code=synthetic-code` callback
- Rejection of replays, unrecognized codes, wrong state, and changed callbacks
- A local `127.0.0.1` HTTP 302 demo, **not** the Halo authentication server
- A synthetic test that joins the callback's nonce with a **fake signed JWT**
  using the existing offline verification/account-binding research helpers

The demo accepts **no real authorization code**, and the desktop executable
makes **no token exchange**. The signed-token test uses an in-memory fake
session and an ephemeral RSA key; no network calls or real credentials.

**The Android application's mobile callback is not permission to authenticate
as the mobile app.** Halo has not approved this desktop helper or an HA callback.
Do not use this to sign into a real Halo or Apple account.

## Testing on Fedora

Run all research tests:

```bash
uv run --no-project --with 'PyJWT[crypto]>=2.10,<3' \
  python -m unittest discover -s research -p 'test_*.py' -q
```

To use the browser demo, from the repository root register a temporary desktop
handler (the normal Python interpreter suffices, and the handler uses stdlib only):

```bash
cat > ~/.local/share/applications/halo-sso-session-test.desktop <<EOF
[Desktop Entry]
Type=Application
Name=Halo Synthetic PKCE Session Test
Exec=/usr/bin/python3 $PWD/research/desktop_sso_demo.py callback %u
MimeType=x-scheme-handler/haloapp;
NoDisplay=false
Terminal=false
EOF
update-desktop-database ~/.local/share/applications
gio mime x-scheme-handler/haloapp halo-sso-session-test.desktop
python3 research/desktop_sso_demo.py clear
python3 research/desktop_sso_demo.py serve
```

Open the displayed `127.0.0.1` address in Brave and click **Simulate authorization
response**. Only approve the **Halo Synthetic PKCE Session Test** application.
In a second terminal run:

```bash
python3 research/desktop_sso_demo.py status
```

It should say `PASS: one-time PKCE session callback received`. Clicking again
should produce `REJECT: not a valid pending synthetic callback`.

After testing, press Ctrl+C in the server terminal and clean up:

```bash
python3 research/desktop_sso_demo.py clear
gio mime x-scheme-handler/haloapp halo-sso-research.desktop
rm ~/.local/share/applications/halo-sso-session-test.desktop
update-desktop-database ~/.local/share/applications
```

The older synthetic handler is restored as the default. If you later stop doing
these experiments altogether, you can remove that older handler separately.
