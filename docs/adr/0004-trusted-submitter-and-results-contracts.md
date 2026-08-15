# ADR 0004: Trusted submitter and results contracts

## Status

Accepted for the v2 narrow SMTP policy and results-service work. This supersedes
only ADR 0003's v1 deferral of a narrow SMTP policy service. It does not allow
an SMTP-time Rspamd milter or arbitrary Rspamd-to-Go callback plugin.

## Trust boundary and threat disposition

A submitter is an operator-enrolled mailbox proven reachable by a one-time
challenge, not a message-header identity. TLS protects a transport hop but does
not authenticate a remote mailbox. Trusted admission facts are Postfix's
observed peer, HELO, envelope sender/recipient, active capability record,
resolver result, and durable policy decision. `Authentication-Results`,
`Received`, `Return-Path`, `From`, and `Reply-To` are attacker-controlled
mail content and never trusted routing data. Wrapper SPF/envelope facts never
apply to a detached `message/rfc822` child.

| Layer | Control and failure disposition |
| --- | --- |
| Postfix client limits | Coarse connection, source-IP, recipient, and size limits reject overload before lookup. |
| Pre-`DATA` policy | Capability, envelope, SPF, and atomic quota. Permanent identity failures reject; DNS, clock, or persistence uncertainty temp-fails. |
| Post-seal header gate | Collector requires one valid, unexpired, unconsumed stamp; otherwise audits and rejects without analysis. |
| Selected-subject preflight | Canonical selection and sender eligibility reject without analyzers. |

Sieve is loop-safe delivery routing only, after SMTP acceptance; it performs no
MIME selection or security policy. Every denial is persisted with stage, stable
reason code, trusted source fields, policy version, and decision ID before an
SMTP response where one exists. It never creates an analysis run. Pre-`DATA`
denials are returned to the connecting MTA and never generate backscatter.
Post-`DATA` denials are asynchronously notarized and may notify only the
verified submitter identified by the admission record; `queued` is not signed.

| STRIDE / abuse case | Trusted control | Failure / reason code |
| --- | --- | --- |
| Spoofed sender, header injection | observed envelope and canonical parser | reject `identity.envelope_mismatch` / `header.untrusted` |
| Capability theft, guessing, replay | keyed digest; single active capability; single-use stamp | reject `capability.invalid`, `capability.revoked`, or `stamp.replayed` |
| Challenge replay | expiring, one-time challenge bound to mailbox | reject `challenge.invalid_or_expired` |
| SPF/HELO spoofing | resolver uses local peer/HELO/envelope | reject `spf.not_pass`; defer `spf.temporary_unavailable` |
| Quota race / distributed IPs | SQLite `BEGIN IMMEDIATE` windows; independent IP limits | reject `quota.minute`, `quota.hour`, or `quota.day` |
| Oversized mail, floods, DoS | bounded requests, headers, parsing, concurrency, filters | reject `limit.exceeded` or defer `service.overloaded` |
| SMTP loops / backscatter | null reverse path and loop markers | `loop.detected`; no pre-`DATA` notification |
| SQLite contention | decision persistence required before response | defer `persistence.unavailable` |
| DNS failure | resolver uncertainty never authenticates | defer `dns.unavailable` |
| Subject impersonation | selector plus independent sender gate | reject `subject.selection_*` / `subject.sender_*` |
| Result privacy / rejection flood | internal projection API, bounded retention/indexes | `api.unauthorized`, `api.invalid_filter`, or `limit.exceeded` |

Thus spoofing is rejected, tampering is sealed and MAC-checked, repudiation has
immutable artifacts and reason-coded decisions, disclosure is projected away,
DoS is bounded, and privilege is limited to an operator-created challenge and
verified capability. Unsigned, invalid, duplicate, expired, or consumed stamps
are untrusted headers and fail closed.

## Enrollment, identity, and quotas

An operator initiates a challenge. A valid one-time, expiring response activates
the submitter and returns exactly one `verify+<capability>@domain` address. The
registry stores only a keyed capability digest. Revocation disables admission;
rotation atomically invalidates the old capability. Replay is quota-exempt and
cannot change its snapshotted reply recipient.

Canonicalization preserves the local part, lowercases and IDNA-normalizes the
domain, and rejects control characters, comments, groups, IP literals, and zero
or multiple RFC 5322 mailboxes. Admission requires non-null canonical envelope
sender equal to the active submission address, one matching canonical wrapper
`From`, and SPF `pass` for locally observed peer/HELO/envelope. `Reply-To` is
ignored. Defaults are 5 admitted submissions/minute, 30/hour, and 100/day;
one atomic decision applies all rolling windows and denies the strictest one.
Each decision snapshots limits and policy version, so changes apply only later.

| Example | Disposition |
| --- | --- |
| valid activation | active capability and one-time address |
| expired, incorrect, replayed challenge | `challenge.invalid_or_expired` |
| revoked/rotated capability | `capability.revoked` / `capability.invalid` |
| envelope / `From` mismatch | `identity.envelope_mismatch` / `identity.from_mismatch` |
| SPF `fail` / `temperror` | reject `spf.not_pass` / defer `spf.temporary_unavailable` |
| quota N-1 / N / N+1 | admit / admit / deny applicable window |

## Stamp and selected-subject contract

The local policy service durably creates a random decision ID then returns a
bounded `PREPEND` header. Its canonical HMAC payload, using a key distinct from
the capability-digest key, binds decision ID, submitter ID, canonical envelope,
privacy-reduced peer, HELO, recipient capability digest, SPF outcome,
policy/quota version, queue ID, and expiry. It is the sole message-carried
bridge. After sealing, the collector consumes exactly one valid stamp and
publishes `mailproof.ingress-context/v2`; missing, multiple, forged, expired,
replayed stamps, uncorrelated queue IDs, auto-submitted mail, and loop mail are
durable post-`DATA` rejections with no expensive analysis.

The existing selector remains authoritative: no top-level `message/rfc822`
selects the original, one selects that child, and more than one is an
indeterminate error. Preflight then requires exactly one canonical selected-
subject `From`. This is eligibility filtering, not authentication; eligible
mail still receives existing DKIM/DMARC/SPF analyses.

The startup UTF-8 allowlist is
`/runtime/config/subject-sender-domain-allowlist`. Missing or empty permits any
syntactically valid sender. Blank lines and `#` comments are ignored. Entries
and candidates are lowercased and IDNA-normalized: `lugano.ch` is exact and
`*.lugano.ch` matches subdomains only. Matching is dot-boundary-aware; no regex,
implicit suffix match, or IP literal is permitted. Malformed entries fail
startup. Thus `user@lugano.ch` may be forwarded by any verified forwarder while
`notlugano.ch` and `lugano.ch.evil.example` do not match. Selection ambiguity
and missing, malformed, or multiple sender mailboxes have a stable stage/reason,
durable decision ID, verified-forwarder destination, and notarization status.

## Results API

Signed immutable analysis and rejection artifacts are authoritative. SQLite
results/decisions are rebuildable projections; report-delivery attempts are a
separate mutable lifecycle. The internal Compose-network service uses a bearer
token read from a `0600` file and compared in constant time. It has no
browser/dashboard scope. Its versioned schemas, JSON examples, errors, filters,
cursor rule, page maximum, and aggregate bounds are in
[Results API v1](../results-api-v1.md).

Only these `GET` endpoints exist: `/healthz`, `/v1/results`,
`/v1/results/{run_id}`, `/v1/decisions`, `/v1/decisions/{decision_id}`, and
`/v1/analytics/summary?from=&to=&interval=hour|day`. No projection returns raw
messages, headers, capability/challenge/signing material, full peer IP,
report-recipient address, or attacker-controlled display text.

