# Work orchestration

The collector is a singleton. Run a scheduled sweep with `scripts/collect-once.sh --confirm`; continuous deployments use the Compose collector service. Workers are stateless apart from the shared SQLite state and immutable artifacts, so increase throughput with `docker compose up -d --scale worker=4`. SQLite and named volumes are single-host only.

For bounded scheduled work, use `scripts/drain.sh --confirm --max-jobs 100 --max-runtime 10m`. A drain stops when no due analysis job remains; it does not alter Maildir files. A SIGINT/SIGTERM stops polling or idle workers without claiming another job. Collector contention exits with code 3; invalid invocation exits with code 2.

The effective v1 limits are enforced by `internal/budget`: 50 MiB delivered messages, 1,000 parts, depth 30, 100 URLs, five redirects, 10-second connects, 60-second analyzers, three attempts per phase, five-minute leases renewed each minute. Do not add independent service limits; generated analyzer configuration must use this same policy.

## Read-only inspection

`mblaze` is inspection only: `mlist /var/mail/verification/new`, `mshow <message>`, and `mseq` may list or display Maildir entries but must never feed policy evidence. Use `mailproof status --json`, `mailproof inspect --delivery ID --json`, and `mailproof replay --run ID --json` for supported queue operations. Replay creates a new run and leaves the prior run and Maildir unchanged.
