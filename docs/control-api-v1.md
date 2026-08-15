# Control API v1

Internal-only JSON API, version `mailproof.control/v1`. It is never
browser-addressable. Other than `GET /healthz`, every request needs the 0600
bearer token; JSON is the only accepted request media type. Errors are
`{"schema_version":"mailproof.error/v1","code":"...","message":"request cannot be processed"}` and reveal no secrets.

## Endpoints and pagination

| Endpoint | Contract |
| --- | --- |
| `GET /healthz` | Generic process health only; no bearer required. |
| `GET /v1/control/policy` | Effective versioned policy; bearer required. |
| `GET /v1/control/audit` | Reverse-chronological audit events; bearer required. |
| `POST /v1/control/previews` | Typed, dry-run command preview. |
| `POST /v1/control/confirmations` | Consume a preview confirmation. |

Policy/audit cursors are integrity-protected opaque values. They default to 50,
cap at 100, and accept bounded type/status/time filters only (one UTC
half-open range no larger than 366 days and at most 100 values). Bad cursor,
filter, JSON, or unknown field gives `invalid_filter` or `invalid_request`;
expired preview is `preview_expired`, stale version is `policy_version_conflict`,
consumed idempotency is `idempotency_replayed`, and unsupported commands are
`unsupported_command`.

## Command schema

Every preview/confirmation has `schema_version`, `command_id`, `command_type`,
`expected_policy_version`, nonempty bounded `reason`, `idempotency_key`, and
the typed `command`. Expiring rules also require RFC3339 UTC `expiry`.
Preview returns `confirmation_token`, `before_digest`, `after_digest`, an
expiry, normalized command, and `dry_run:true`. Confirmation repeats command
ID, expected version, idempotency key, confirmation token, before/after digest;
success returns the policy/audit identity and stable result code.

Permitted command types are `quota_change`, `submitter_suspend`,
`submitter_reactivate`, `capability_rotate`, `subject_allowlist_put`,
`peer_block_put`, `outer_domain_block_put`, and `subject_domain_block_put`.
Domain command values are exact normalized domains or an explicit `*.` wildcard
where allowed; CIDR is canonical IPv4/IPv6 CIDR. Arbitrary policy expressions,
raw SQL, addresses, and tokens are forbidden fields.

Precedence is exact: disabled/expired rules never match; peer/outer blocks deny
before SPF/DNS when their inputs suffice; selected-subject block denies before
allowlist; a nonempty allowlist requires exact or explicit wildcard membership;
an empty allowlist permits any syntactically valid sender. Each committed command
creates a durable audit record with actor `unauthenticated-local` plus session
correlation ID, command/version/digests/result/reason, but no secret.

`mailproof control-api --listen=:8081 --state=... --token-file=... --confirmation-key-file=... --capability-key-file=...`
has the same bounded server lifecycle as dashboard: 5s read-header, 10s
read/write, 60s idle, 32KiB headers, bounded body, and graceful shutdown.
