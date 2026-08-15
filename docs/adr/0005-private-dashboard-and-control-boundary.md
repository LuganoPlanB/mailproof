# ADR 0005: Private dashboard and control boundary

## Status

Accepted for dashboard v1 contracts; implementation remains a later milestone.

## Decision

`mailproof dashboard` v1 uses `auth_mode=none`: it identifies no human user and
records every v1 action as actor `unauthenticated-local` plus an opaque session
correlation ID. This is acceptable only behind an explicit, fail-closed local
network boundary. It does not authenticate a caller and is not an Internet
console.

The command has these exact flags:

| Flag | Default | Contract |
| --- | --- | --- |
| `--host <address>` | `127.0.0.1` | IP address or hostname to listen on. |
| `--port <number>` | `3000` | Decimal integer in `1..65535`. |
| `--public-origin <origin>` | derived locally | Exact browser origin used for same-origin checks and future WebAuthn RP configuration. |

For the default/local bind, omitted `--public-origin` derives to
`http://localhost:<port>`. It is required for a wildcard or non-loopback bind.
It is an absolute origin containing only scheme, host, and optional port:
credentials, path, query, fragment, empty/ambiguous host, and HTTP except for
hostname `localhost` are startup errors. Canonical IPv4 and bracketed IPv6
forms are compared by authority, so `127.0.0.1`, `[::1]`, and a hostname are
not interchangeable unless the configured origin is exactly the same authority.

Every request must have `Host` exactly equal to the configured public-origin
authority. Every mutation must additionally have `Origin` exactly equal to the
full configured origin; when `Sec-Fetch-Site` is supplied it must be
`same-origin`. `Forwarded`, `X-Forwarded-*`, and other forwarded
identity/origin headers are rejected, not trusted. The shipped Compose mapping
is `127.0.0.1:3000` and dashboard/control services stay off the `public`
network. Deliberate environment overrides remain possible, but must supply the
non-local public origin and retain these checks.

The dashboard uses a host-only (`Domain` absent), `HttpOnly`, `SameSite=Strict`,
`Path=/` session cookie; it adds `Secure` for HTTPS. Its opaque value contains a
random 256-bit session correlation ID and a MAC derived from
`--session-key-file`, and expires after 12 hours. Each mutation form also has a
five-minute HMAC token bound to session ID, HTTP method, canonical route,
random nonce, and expiry. Policy confirmation consumption/replay prevention is
separately owned by control-api. Browser requests never receive or carry the
0600 bearer credentials used by dashboard-to-results/control clients.

## Request examples and startup failures

Allowed local HTTP request:

```http
GET /operations HTTP/1.1
Host: localhost:3000
```

Allowed HTTPS mutation (with the session and a fresh form token):

```http
POST /policy/preview HTTP/1.1
Host: dashboard.example.test
Origin: https://dashboard.example.test
Sec-Fetch-Site: same-origin
```

Rejected examples include `Host: evil.test`, `Origin: https://evil.test`,
`Sec-Fetch-Site: cross-site`, any `X-Forwarded-Host`, and a request which
attempts to send an internal bearer token. Startup fails before listening for:
`--port 0`/`65536`; `--host 0.0.0.0` without an origin; a non-loopback bind
without an origin; `http://127.0.0.1:3000`; origins with path or credentials;
and a single optional control URL/token flag without its partner.

## Threat disposition

| Threat | Disposition |
| --- | --- |
| DNS rebinding or hostile Host | Exact configured authority; fail closed. |
| Forged forwarded headers or proxy confusion | Forwarded headers rejected; proxy trust deferred to a new ADR. |
| CSRF/cross-site form or fetch | Exact Origin, `same-origin` fetch metadata, strict cookie, and expiring route-bound token. |
| Clickjacking | Dashboard response policy must deny framing; not a substitute for mutation checks. |
| Stolen internal bearer token | Token is 0600, server-to-server only, never rendered or accepted from browsers. |
| Browser caching | Sensitive pages/forms use `Cache-Control: no-store`. |
| Deliberate non-loopback exposure | Explicit origin/configuration only; no silent public bind. |
| Operator denial of service | Bounded headers/body/timeouts and local deployment boundary; availability limits remain operational policy. |

Passkeys, reverse-proxy trust, authenticated actors, and RBAC require a later
ADR. They reuse this public-origin vocabulary but cannot retroactively turn a
v1 session correlation into a human identity.

## Consequences

Dashboard access is intentionally private but unauthenticated in v1; it is not
safe to publish. Signing keys remain confined to their runtime/report boundary,
and the dashboard only consumes reduced internal API projections.
