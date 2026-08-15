# Backup, restore, retention, and upgrades

Authoritative state is the Maildir, immutable artifact tree, SQLite database and
WAL, restricted Postfix ingress log, runtime token registry, signing keys, and
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
