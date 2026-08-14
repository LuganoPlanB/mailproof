# Compose smoke runbook

Prerequisites: Docker Engine with the Compose plugin, and an available host SMTP
test port. Copy `.env.example` to `.env`, then initialize non-secret runtime
configuration with `scripts/init.sh --dry-run --report-recipient user@example.org`.
Repeat with `--confirm` after reviewing the output. Start with `docker compose
up -d`, then smoke-test with `scripts/smoke.sh --dry-run` and repeat with
`scripts/smoke.sh --confirm`; it waits for Postfix and Dovecot health and submits a
synthetic message to the configured verification mailbox.

`runtime/` is generated local state. `runtime/secrets/` is mode 0700 and secret
files are mode 0600. Do not place private keys or submitter tokens in `.env`.
