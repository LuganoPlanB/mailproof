#!/usr/bin/env bash
set -Eeuo pipefail
case "${MAILPROOF_ANALYZER_ROLE:?}" in
  redis) exec redis-server --save '' --appendonly no ;;
  unbound) exec unbound -d ;;
  clamav) exec clamd --foreground=true --config-file=/etc/clamav/clamd.conf ;;
  rspamd) exec rspamd -f -u _rspamd -g _rspamd ;;
  olefy)
    # Minimal olefy-compatible HTTP endpoint: receives one submitted Office blob,
    # invokes the pinned oletools parser, and returns its bounded text result.
    exec python3 /usr/local/lib/mailproof-olefy.py ;;
  *) exit 64 ;;
esac
