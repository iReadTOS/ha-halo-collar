# Halo local callback rehearsal (no Halo or Apple login)

Copy `research/preflight_desktop_callback.py` into the existing `research` folder.
Optionally apply `halo_socket_read_fix.patch` from the repository root using
`git apply --check halo_socket_read_fix.patch && git apply halo_socket_read_fix.patch`.

Requires the previously created `~/.local/share/applications/halo-live-sso-probe.desktop`
with `Exec=` pointing at the actual repository file
`research/live_sso_feasibility.py callback %u`. It should use `uv` and the
`PyJWT[crypto]` dependency as previously discussed.

Run with:

    python3 research/preflight_desktop_callback.py

The script temporarily selects the live handler, sends a *synthetic* URI via
`gio open`, checks that the private Unix socket receives it, and restores your
previous default handler (normally `halo-sso-research.desktop`). It supplies
`UV_OFFLINE=1` to the launcher to avoid `uv` fetching dependencies for this
rehearsal. No Halo credentials, real OAuth code, passkey, collar commands, or
live tokens are used. It does NOT test whether Brave delegates custom URI
schemes, whether Halo issues tokens, or whether the provider permits the OAuth
client/redirect registration.

The socket-read robustness patch prevents a valid callback from being rejected
merely because its bytes arrive in multiple Unix-stream chunks. After applying
it, re-run the existing synthetic research and pinned HA tests. It does not
change provider endpoints, headers, claims, auth-code exchange, or encryption.

If the rehearsal reports STOP, inspect the synthetic test failure, not real
credentials. Do not do a real account-holder login until the local handoff works.
