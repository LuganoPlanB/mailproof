#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

runtime=/runtime
mkdir -p -- "${runtime}/secrets" "${runtime}/config" "${runtime}/artifacts" /clamav-db /artifacts /state /reports /var/mail/verification /var/log/mailproof
chmod 0700 -- "${runtime}" "${runtime}/secrets" "${runtime}/config"
if [[ ! -e ${runtime}/secrets/submitters.json ]]; then
	printf '%s\n' '[]' >"${runtime}/secrets/submitters.json"
fi
if [[ ! -e ${runtime}/secrets/postfix-recipient-access ]]; then
	printf '%s OK\n' "${MAILPROOF_VERIFY_RECIPIENT:?MAILPROOF_VERIFY_RECIPIENT is required}" >"${runtime}/secrets/postfix-recipient-access"
fi
if [[ ! -s ${runtime}/secrets/report-signing-key.pem ]]; then
	openssl genpkey -algorithm ED25519 -out "${runtime}/secrets/report-signing-key.pem"
fi
if [[ ! -s ${runtime}/secrets/capability-hmac-key ]]; then
	openssl rand -out "${runtime}/secrets/capability-hmac-key" 32
fi
if [[ ! -s ${runtime}/secrets/admission-stamp-hmac-key ]]; then
	openssl rand -out "${runtime}/secrets/admission-stamp-hmac-key" 32
fi
if [[ ! -s ${runtime}/secrets/results-api-token ]]; then
	openssl rand -hex 32 >"${runtime}/secrets/results-api-token"
fi
chmod 0600 -- "${runtime}/secrets/submitters.json" "${runtime}/secrets/postfix-recipient-access" "${runtime}/secrets/report-signing-key.pem" "${runtime}/secrets/capability-hmac-key" "${runtime}/secrets/admission-stamp-hmac-key" "${runtime}/secrets/results-api-token"
printf '%s\n' "${MAILPROOF_REPORT_RECIPIENT:?MAILPROOF_REPORT_RECIPIENT is required}" >"${runtime}/config/report-recipient"
chmod 0600 -- "${runtime}/config/report-recipient"
printf '%s\n' "${MAILPROOF_CLAMAV_PROVISION:-none}" >"${runtime}/config/clamav-provision-mode"
chmod 0600 -- "${runtime}/config/clamav-provision-mode"
if [[ ! -e ${runtime}/config/subject-sender-domain-allowlist ]]; then
	printf '%s\n' "${MAILPROOF_SUBJECT_SENDER_DOMAIN_ALLOWLIST:-}" >"${runtime}/config/subject-sender-domain-allowlist"
fi
chmod 0600 -- "${runtime}/config/subject-sender-domain-allowlist"
chown 1000:1000 /artifacts /state /reports /var/mail/verification /var/log/mailproof
