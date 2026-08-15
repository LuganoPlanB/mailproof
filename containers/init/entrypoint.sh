#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

runtime=/runtime
mkdir -p -- "${runtime}/secrets" "${runtime}/config" "${runtime}/artifacts" /clamav-db /artifacts /state /reports /var/mail/verification /var/log/mailproof
chmod 0700 -- "${runtime}" "${runtime}/secrets" "${runtime}/config"
printf '%s\n' '[]' > "${runtime}/secrets/submitters.json"
printf '%s OK\n' "${MAILPROOF_VERIFY_RECIPIENT:?MAILPROOF_VERIFY_RECIPIENT is required}" > "${runtime}/secrets/postfix-recipient-access"
if [[ ! -s ${runtime}/secrets/report-signing-key.pem ]]; then
  openssl genpkey -algorithm ED25519 -out "${runtime}/secrets/report-signing-key.pem"
fi
chmod 0600 -- "${runtime}/secrets/submitters.json" "${runtime}/secrets/postfix-recipient-access" "${runtime}/secrets/report-signing-key.pem"
printf '%s\n' "${MAILPROOF_REPORT_RECIPIENT:?MAILPROOF_REPORT_RECIPIENT is required}" > "${runtime}/config/report-recipient"
chmod 0600 -- "${runtime}/config/report-recipient"
printf '%s\n' "${MAILPROOF_CLAMAV_PROVISION:-none}" > "${runtime}/config/clamav-provision-mode"
chmod 0600 -- "${runtime}/config/clamav-provision-mode"
chown 1000:1000 /artifacts /state /reports /var/mail/verification /var/log/mailproof
