# Private dashboard operations

The v1 dashboard is an unauthenticated, single-host operator console. Audit
records identify only `unauthenticated-local` plus an opaque session correlation
ID; neither is a human identity. Do not publish it or put it behind a public
reverse proxy.

## Safe access

Start the optional profile after the normal graph is healthy:

```bash
docker compose --profile dashboard up -d --wait
curl --fail --silent --show-error http://localhost:3000/healthz
ssh -N -L 3000:127.0.0.1:3000 operator@mailproof-host
```

Compose publishes `127.0.0.1:3000:3000` by default while the container listens
on its private network. Keep that loopback boundary and use the SSH tunnel for
remote administration. The standalone defaults are `--host 127.0.0.1` and
`--port 3000`; omitted `--public-origin` derives `http://localhost:<port>`.
Results URL/token and session-key files are required. Control URL/token are an
all-or-nothing pair. A wildcard/non-loopback bind requires an exact HTTPS origin
but never authorizes public exposure. Host, Origin, forwarded-header, CSRF, and
replayed-form checks fail closed.

## Operations and recovery

Overview/funnel values are UTC bounded projections and distinguish zero from
unavailable, partial, or stale data. See [metrics](../dashboard-metrics-v1.md)
and the [dashboard API](../dashboard-api-v1.md) for sources, reconciliation,
campaign grouping reasons, late merges, and indicator-key limits. Policy changes
are previewed and confirmed with a reason, expected version, digest, expiry, and
audit record. Disabled/expired rules do not match; peer/outer blocks precede
selected-subject blocks, which precede allowlist evaluation. Capability rotation
is irreversible and must be stored once through the approved secret channel.

The analytics and intel projectors are singleton no-network services. Recover a
failed projector, then use only documented `--dry-run` followed by `--confirm`
rebuild/retention commands. Back up SQLite and runtime secrets through
`scripts/backup.sh`, including dashboard session, results/control API,
confirmation, capability-digest, and indicator-HMAC keys. Never back up or
commit Playwright output, browser dependencies, or screenshots. Browser pages,
logs, and diagnostics must exclude raw mail, addresses, peer IPs, bearer tokens,
capabilities, confirmation values, and key material.

## Future passkeys

Passkeys require a new ADR: HTTPS proxy, separately validated WebAuthn RP ID,
the same public-origin vocabulary, authenticated actor/RBAC design, explicit
trusted-proxy rules, and invalidation of v1 sessions. Do not trust
`X-Forwarded-*` or reinterpret a v1 session as a person before that work.
