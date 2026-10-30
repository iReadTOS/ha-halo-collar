# Offline-only Halo OAuth token request comparison

**Purpose:** Compare how the existing Halo HACS integration constructs its
password-grant token request with a *prepared, unsent* authorization-code/PKCE
request using the same HACS-generated client headers.

This package does **not** modify the existing integration, the live SSO probe,
or the Home Assistant instance. It does **not** retry an HTTP 403, change
transport fingerprints, or assert that Halo approves third-party OAuth.

## Install

From the root of your `experiment/browser-sso` checkout:

```bash
unzip -o ~/Downloads/halo_offline_request_parity.zip -d .
uv run ruff check research/offline_request_parity.py tests/test_oauth_request_parity.py
uv run ruff format --check research/offline_request_parity.py tests/test_oauth_request_parity.py
uv run --isolated --python /usr/bin/python3 \
  --with-requirements requirements_test_ha_stable.txt pytest -q
git diff --check
git status --short
```

`tests/test_oauth_request_parity.py` uses a fake HTTP session to exercise
`HaloApiClient.async_login()` and observes its real token headers. It constructs
a separate *unsent* `urllib.request.Request` using those captured headers and
the real research `build_exchange_data()` PKCE form builder, then asserts exact
differences in grant-specific body fields.

No live OAuth URL or response is logged. All test passwords, tokens, codes and
secrets are synthetic. A green test only establishes local request parity.
The live SSO probe is **unchanged**: it still uses `urllib` and does not include
the HACS-specific mobile headers.

## Interpretation

If tests pass, we have eliminated uncertainty about the **locally modeled**
differences, not established that Halo will accept a real code exchange. The
observed HTTP 403 could be due to OAuth grant policy, the registered client
configuration, or another server decision. Do not repeat real token requests
with altered app identity or headers to bypass an access restriction.

For an upstream PR, this is research-only test scaffolding; reconsider whether
it belongs in the final minimal patch. Keep production Home Assistant isolated.
