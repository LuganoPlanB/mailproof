#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

runtime=/runtime
mkdir -p -- "${runtime}/secrets" "${runtime}/config" "${runtime}/artifacts"
chmod 0700 -- "${runtime}" "${runtime}/secrets" "${runtime}/config"
printf '%s\n' '[]' > "${runtime}/secrets/submitters.json"
: > "${runtime}/secrets/postfix-recipient-access"
: > "${runtime}/secrets/report-signing-key.pem"
chmod 0600 -- "${runtime}/secrets/submitters.json" "${runtime}/secrets/postfix-recipient-access" "${runtime}/secrets/report-signing-key.pem"
printf '%s\n' "${MAILPROOF_REPORT_RECIPIENT:?MAILPROOF_REPORT_RECIPIENT is required}" > "${runtime}/config/report-recipient"
chmod 0600 -- "${runtime}/config/report-recipient"
