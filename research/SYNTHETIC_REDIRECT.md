# Synthetic browser-to-Fedora HTTP 302 redirect test

This is strictly a **local fake OAuth test**. Its 302 server binds only to
`127.0.0.1`, uses fake `code=synthetic-code`, generates a new random `state`,
accepts one callback for at most five minutes, and refuses other callbacks.
It never connects to Halo, Apple, or Home Assistant.

## Install temporary desktop handler (from fork root)

```bash
mkdir -p "$HOME/.local/share/applications"
cat > "$HOME/.local/share/applications/halo-sso-302-test.desktop" <<EOF_DESKTOP
[Desktop Entry]
Type=Application
Name=Halo Synthetic 302 Test
Exec=/usr/bin/python3 $PWD/research/synthetic_redirect.py callback %u
MimeType=x-scheme-handler/haloapp;
NoDisplay=false
Terminal=false
EOF_DESKTOP
update-desktop-database "$HOME/.local/share/applications"
gio mime x-scheme-handler/haloapp halo-sso-302-test.desktop
gio mime x-scheme-handler/haloapp
```

This intentionally changes the user-level `haloapp://` association to a
synthetic-only handler. Do not use it for an actual Halo login.

## Run

In **terminal A**:

```bash
python3 research/synthetic_redirect.py clear
python3 research/synthetic_redirect.py serve
```

Open the `http://127.0.0.1:PORT/` address printed by the script in Brave.
Click **Start synthetic OAuth redirect**. If Brave asks for permission to open
an external application, accept only if it identifies **Halo Synthetic 302
Test**. Never enter credentials or visit Halo's actual sign-in page.

In **terminal B**:

```bash
python3 research/synthetic_redirect.py status
```

Expected result: `PASS: one-time synthetic HTTP redirect callback received`.
Clicking a second time should produce `REJECT`, proving replay protection.

Stop terminal A with Ctrl+C and clear state:

```bash
python3 research/synthetic_redirect.py clear
```

## Restore previous handler

If you want to restore the earlier synthetic handler:

```bash
gio mime x-scheme-handler/haloapp halo-sso-research.desktop
```

Remove this test handler after finishing:

```bash
rm "$HOME/.local/share/applications/halo-sso-302-test.desktop"
update-desktop-database "$HOME/.local/share/applications"
```

The desktop handler only proves local browser-to-desktop mechanics. It does not
establish that Halo permits third-party software to use `haloapp://callback`
or will issue tokens to this program. The real OAuth identity provider's redirect
registration and authorization remain unresolved.
