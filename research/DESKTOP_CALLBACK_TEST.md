# Synthetic-only Fedora `haloapp://` handoff experiment

This is **not an OAuth login tool** and must never be used to capture a real Halo authorization response. It performs no network access, refuses anything except two fixed synthetic fields, and writes only one non-sensitive pass/fail line to `~/.cache/halo-sso-research/last-callback-status.txt`.

## Run from the fork root on Fedora

```bash
python3 -m unittest discover -s research -p 'test_desktop_callback_test.py' -v

mkdir -p "$HOME/.local/share/applications"
cat > "$HOME/.local/share/applications/halo-sso-research.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Halo Synthetic Callback Test
Comment=No real login, tokens, or network access
Exec=/usr/bin/python3 $PWD/research/desktop_callback_test.py %u
MimeType=x-scheme-handler/haloapp;
NoDisplay=true
Terminal=false
EOF

xdg-mime default halo-sso-research.desktop x-scheme-handler/haloapp
xdg-mime query default x-scheme-handler/haloapp
xdg-open 'haloapp://callback?code=synthetic-code&state=halo-research-demo'
cat "$HOME/.cache/halo-sso-research/last-callback-status.txt"
```

Expected default: `halo-sso-research.desktop`. Expected result: `PASS: synthetic callback received`.

Then test the **same fake URI** in Brave's address bar and approve the external-app prompt only if it names *Halo Synthetic Callback Test*. The status file should again contain `PASS`. Do not enter Halo credentials or perform a real Apple login for this test.

## Cleanup

Delete `~/.local/share/applications/halo-sso-research.desktop` after the experiment. The desktop MIME default association may also remain in `~/.config/mimeapps.list` (or a desktop-specific MIME defaults file); remove only the `x-scheme-handler/haloapp=halo-sso-research.desktop` entry under `[Default Applications]`, if present. You can verify with `xdg-mime query default x-scheme-handler/haloapp`. Do not delete or overwrite your entire `mimeapps.list`.

**Limitations:** Demonstrates only desktop/browser URI handoff. It does not show that Halo permits third-party OAuth clients, accepts authorization-code exchanges, or lets Home Assistant use the resulting tokens.
