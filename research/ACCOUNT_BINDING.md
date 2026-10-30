# Offline account-binding and reauthentication experiment

`account_binding.py` combines the existing **synthetic** callback, OAuth code
exchange, and cryptographically signed ID-token validation into a proposed login.
It then adds fail-closed issuer + subject + OAuth client binding.

This module is NOT a live sign-in method, does not read or write Home Assistant
configuration, and cannot fix Halo's unknown redirect registration. Do not send
real authorization codes, tokens, or account information through it.

## Rules under test

- Do not build an account identity from an email claim alone. Two distinct Halo
  subjects can advertise the same email, and an email can change for one subject.
- A reauth must match the saved, verified `issuer`, `sub`, and `client_id` exactly.
- Password-only integration entries cannot be silently migrated to SSO because
  they do not have a previously authenticated OIDC subject. A user-approved,
  separately designed account-linking process would be needed.
- A reauth must verify that its original entry and credential lineage are still
  current *immediately before* storing new tokens; changing entries or tokens
  mid-flight must abort rather than overwrite newer credentials.
- Invalid signatures, audiences, nonces, callbacks, or account bindings must
  never produce a persisted credential update. Research helpers do not persist
  anything even on success.
- Token responses must not be printed, included in exceptions, or committed to git.

`EntrySnapshot.revision` is only a synthetic model of credential lineage.
It is **not** a field currently provided by Home Assistant. The eventual
integration must adapt to its existing entry checks, token snapshots, and reload
lifecycle. These functions do not enforce transactional writes or concurrent
reactive updates in a real HA environment.

**Still blocking deployment:** a Halo-approved redirect URI/client, trusted
provider discovery and JWKS retrieval, correct Home Assistant OAuth handling,
server-side entry/token persistence, and safe legacy-account linking.

Run all offline tests from the repository root:

```bash
uv run --no-project --with 'PyJWT[crypto]>=2.10,<3' \
  python -m unittest discover -s research -p 'test_*.py' -v
```
