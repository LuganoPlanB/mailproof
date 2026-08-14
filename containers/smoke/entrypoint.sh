#!/usr/bin/env bash
set -Eeuo pipefail

message_id=${MAILPROOF_SMOKE_MESSAGE_ID:?MAILPROOF_SMOKE_MESSAGE_ID is required}
recipient=${MAILPROOF_VERIFY_RECIPIENT:?MAILPROOF_VERIFY_RECIPIENT is required}
expected_delta=${MAILPROOF_SMOKE_EXPECTED_DELTA:-1}
count_maildir() {
  find /var/mail/verification -type f -print0 | awk 'BEGIN { RS = "\\0" } END { print NR }'
}

before=$(count_maildir)
printf 'EHLO smoke\r\nMAIL FROM:<>\r\nRCPT TO:<%s>\r\nDATA\r\nFrom: smoke@example.test\r\nTo: %s\r\nSubject: Mailproof smoke\r\nMessage-ID: <%s>\r\n\r\nMailproof smoke fixture.\r\n.\r\nQUIT\r\n' "${recipient}" "${recipient}" "${message_id}" | nc -w 10 postfix 25
for _ in $(seq 1 15); do
  after=$(count_maildir)
  if ((after == before + expected_delta)); then
    printf 'maildir-count=%s message-id=%s\n' "${after}" "${message_id}"
    exit 0
  fi
  sleep 1
done
printf 'expected Maildir count delta %s after Message-ID %s\n' "${expected_delta}" "${message_id}" >&2
exit 1
