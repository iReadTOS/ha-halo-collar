# Halo OAuth redirect preflight (research only)

The official Halo Android app uses the public OAuth client ID `halo.app.android`
and the registered mobile callback `haloapp://callback`. Its compiled
`Halo.Droid.Services.AuthClientConfigProvider` returns the exact same app-level
OAuth client ID and client secret as the existing unofficial Home Assistant
integration; no second client has been established.

Home Assistant's standard OAuth helper may use
`https://my.home-assistant.io/redirect/oauth`. The provider must allow that
callback **for the exact OAuth client ID** before the integration can complete
that authorization-code flow. Server-wide PKCE and authorization-code support
is not enough.

## Safe optional preflight

From the root of the fork, on a machine with network access, run:

```bash
python3 research/redirect_probe.py --compare
```

The script requests *only* two **pre-login** authorization pages: first with
the official app's callback as a comparison, then with the standard Home
Assistant callback. It sends neither user credentials nor OAuth client secret,
does not follow redirects, does not open a browser, and does not request or
exchange tokens. It prints only status codes and coarse outcomes, never raw
response bodies, cookies, authentication codes, or `Location` headers.

`redirect_rejected` is evidence against that candidate callback. An HTTP 200,
login-page response, or 302 is **not proof** the callback is allowed: the
server might defer validation. Proxy/WAF errors also make this inconclusive.
No real account login should be attempted unless a safe supported callback
has been established and the user has explicitly agreed.

## Offline tests

```bash
python3 -m unittest discover -s research -p 'test_*.py' -v
```

Tests use only synthetic data. No requests are made to Halo while testing.
Do not modify the original app, register a handler for `haloapp://callback`,
or intercept/replay authorization codes from the official app.
