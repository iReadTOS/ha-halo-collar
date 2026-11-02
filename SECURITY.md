# Security policy

## Supported versions

The `experiment/browser-sso` branch and `0.7.9b1` beta candidate are experimental and not a supported stable release. Security fixes and provider compatibility are not guaranteed.

## Reporting a vulnerability

Do not open a public issue containing Halo credentials, OAuth tokens, encrypted vault contents or passphrases, OIDC account subjects, pet names, serial numbers, precise locations, fence data, private API payloads, Home Assistant secrets, or unredacted diagnostics.

For vulnerabilities in **this fork**, check the [fork's Security page](https://github.com/iReadTOS/ha-halo-collar/security) for private-reporting options. If private reporting is unavailable, ask the fork maintainer for a secure contact channel **without posting exploit details or secrets publicly**. Do not report this fork's SSO issues to the upstream maintainer by default.

Include:

- Home Assistant and Halo Collar integration versions;
- a minimal description and reproduction;
- only the redacted logs or diagnostics needed to understand the issue.

## Sensitive data and credential response

The password flow exchanges Halo account credentials for OAuth tokens and does not persist the password. Experimental SSO imports a passphrase-encrypted token vault, decrypts it in memory, and stores tokens, verified issuer/subject and client metadata in the protected Home Assistant config entry—not the original vault/passphrase. Home Assistant stores sensitive token and identity data for both authentication types. Treat Home Assistant backups, diagnostics, API captures, and logs as sensitive until reviewed.

If a password or token is exposed:

1. change the Halo password or revoke the affected session when possible;
2. reauthenticate the integration;
3. remove the sensitive material from public issues, screenshots, logs, and commits;
4. do not repost the raw credential while discussing the incident.

## Safety boundary

Password-authenticated Halo Collar entries are **telemetry-only by default**. Imported SSO entries are **always read-only**: they do not initialize the write transport or load the button/switch platforms. The only supported writes for password entries are opt-in fence controls and Find collar. Fence-off requires a stronger opt-in and rejects active or unknown walks. Fence changes require reported-state confirmation. Find collar requires entitlement, fresh exact mapping, no active or unknown walk, and a cooldown. Provider acceptance does not verify physical execution. See [control transactions](docs/ARCHITECTURE.md#control-transactions) for the full guarantees.

Fence creation, editing, and deletion; corrections; bind/unbind; account changes; arbitrary collar behavior; and other private write endpoints remain intentionally unsupported. Treat every Home Assistant control as a supplemental convenience, not a containment authority. Confirm safety-critical state in the official Halo app and physically verify your pet is safe.

The integration depends on an undocumented private cloud API and may stop working when Halo changes that service.
