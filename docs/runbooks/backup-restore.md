# Backup, restore, retention, and upgrades

Authoritative state is the Maildir, immutable artifact tree, SQLite database and
WAL, restricted Postfix ingress log, runtime token registry, submitter rows,
capability and admission-stamp HMAC keys, signing keys, and
committed configuration. Redis and Unbound are disposable caches and are never
backed up. Treat every backup as secret material: it contains recipient
correlation and private keys.

ClamAV definitions default to explicit operator provisioning. Copy
`.env.example` to a protected deployment `.env` and choose either `artifact`
with an approved HTTPS URL, release version, and SHA-256, or retain `none` and
run `scripts/provision-clamav-db.sh --dry-run ...` then `--confirm`. Artifact
mode verifies the exact digest and records provenance in `clamav-db`; it is the
reproducible release path. The alternative `latest` mode is deliberately
opt-in: it invokes freshclam at startup and, with
`docker compose --profile clamav-updater up -d`, refreshes on the configured
interval. Latest definitions are mutable, so their recorded provenance and
backup are required and a release cannot claim a reproducible scanner input.
An absent or invalid database makes ClamAV unavailable and prevents Rspamd from
becoming ready; it is never treated as a clean scan.

Run `scripts/backup.sh --dry-run --output /secure/backup` first, then repeat
with `--confirm`. The script creates a SQLite online backup and emits a
`SHA256SUMS` manifest. Copy it to encrypted storage before applying retention.

Restore only on a fresh project with `scripts/restore.sh --dry-run --input
/secure/backup`, followed by `--confirm`. It verifies every copied file before
writing named volumes. Start the graph, run `scripts/smoke.sh --confirm`, and
use `mailproof verify-report --bundle ... --keys ... --json` for each sampled
retained report. Do not use `docker compose down -v`: it destroys authoritative
volumes.

For retention, stop intake, drain workers, select only runs whose report,
delivery, and message references are beyond policy, export a verified backup,
then delete through a future retention command; never remove files directly
from a volume. Rotate a signing key only after publishing its public key and
keeping prior verification keys. Rotate recipient tokens and feeds by staged
configuration update and smoke verification. Schema migrations are forward-only:
the rollback procedure is restore of the pre-migration backup, not a downgrade.

## Submitter enrollment and recovery

Start with `mailproof submitter challenge --email ADDRESS --dry-run --json`,
then repeat with `--confirm`; confirmation sends a 15-minute, single-use code
through internal Postfix. Activate it with `mailproof submitter activate --email
ADDRESS --code CODE --confirm --json`. The submission address appears exactly
once, so store it in the approved secret store rather than a ticket or shell
history. Use `submitter list --json` and `submitter revoke --id ID --confirm
--json` for safe operator views and revocation. For an exposed or lost address,
run the rotate dry-run then `submitter rotate --id ID --confirm --json`; the old
address immediately stops working. Never edit SQLite or runtime JSON manually.

`/runtime/secrets` is an authoritative backup input and contains distinct
`capability-hmac-key` and `admission-stamp-hmac-key` files. Back them up only
through `scripts/backup.sh`. If a key is lost, restore it from the verified
backup before startup. If the capability key cannot be recovered, revoke and
re-enroll affected submitters: keyed digests cannot be recovered or re-keyed.

## Sender policy, rejection, and analytics operations

Before the first `scripts/init.sh --confirm`, set the selected-subject policy
in the protected `.env`. Leave `MAILPROOF_SUBJECT_SENDER_DOMAIN_ALLOWLIST`
empty to allow any syntactically valid selected sender, set it to `lugano.ch`
to allow exactly that domain, or set it to `*.lugano.ch` for subdomains only.
This policy is applied after DATA to the subject selected from the sealed
message; it never restricts the independently verified forwarding mailbox.
Malformed entries fail the collector closed at startup. Change the protected
deployment configuration, restart the collector, and verify the health check;
do not edit generated runtime files.

Pre-DATA admission failures are returned to the connecting MTA and create no
outbound backscatter. Post-DATA selected-subject failures are durably queued,
notarized asynchronously, and delivered only to the verified forwarder
snapshot. A queued or failed notarization is not a signed result: inspect the
decision's notarization status, restore reporter/key access, and let the
durable outbox retry. Preserve the decision and its artifact directory during
incident response.

The results API is internal-only. Retrieve its bearer token only from the
protected runtime secret through an approved operator channel; never put it in
`.env`, a URL, shell history, or a reverse-proxy header. A reverse proxy must
remain on the internal `analytics` network and must not publish the API without
an accepted architecture change. With a protected token variable, a consumer
can query bounded JSON projections:

```bash
curl --fail --silent --show-error \
  -H "Authorization: Bearer ${MAILPROOF_RESULTS_TOKEN}" \
  'http://results-api:8080/v1/results?limit=50'
curl --fail --silent --show-error \
  -H "Authorization: Bearer ${MAILPROOF_RESULTS_TOKEN}" \
  'http://results-api:8080/v1/analytics/summary?from=2026-08-01T00:00:00Z&to=2026-08-02T00:00:00Z&interval=day'
```

Use only the documented filters, page cursor, and UTC ranges in
[`results-api-v1.md`](../results-api-v1.md). On token leakage, replace the
mode-0600 runtime token through the approved secret-rotation procedure, restart
the API, and treat prior API access as potentially disclosed. Rebuild result
projections only with the documented `mailproof results rebuild --dry-run` then
`--confirm` operation when it is available in the deployed version, after
verifying signed artifacts. Until then, recover projections by restoring the
verified backup; never reconstruct them by parsing raw mail or editing SQLite.
