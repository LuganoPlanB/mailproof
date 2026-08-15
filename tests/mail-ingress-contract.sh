#!/usr/bin/env bash
set -Eeuo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
must() { rg -q -- "$2" "${root}/$1" || { printf 'missing %s in %s\n' "$2" "$1" >&2; exit 1; }; }
must config/postfix/main.cf 'message_size_limit = 52428800'
must config/postfix/main.cf 'check_recipient_access texthash:/runtime/secrets/postfix-recipient-access'
must config/postfix/main.cf 'reject_unauth_destination'
must config/dovecot/dovecot.conf 'protocols = lmtp'
must config/dovecot/sieve-before 'Routing only'
must docs/ingress-transaction-context.md 'lost_coverage'
must config/rspamd/local.d/antivirus.conf 'scan_mime_parts = false'
must config/rspamd/local.d/antivirus.conf 'no_cache = true'
must config/rspamd/local.d/external_services.conf 'olefy'
must config/rspamd/plugins.d/mailproof.lua 'PROJECTION_COMPLETE'
must scripts/rspamd-check.sh 'pass_all'
must scripts/rspamd-check.sh 'verify@mailproof.test'
printf '%s\n' 'mail-ingress-contract: ok'
