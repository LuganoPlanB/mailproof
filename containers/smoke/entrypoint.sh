#!/usr/bin/env bash
set -Eeuo pipefail

message_id=${MAILPROOF_SMOKE_MESSAGE_ID:?MAILPROOF_SMOKE_MESSAGE_ID is required}
recipient=${MAILPROOF_VERIFY_RECIPIENT:?MAILPROOF_VERIFY_RECIPIENT is required}
expected_delta=${MAILPROOF_SMOKE_EXPECTED_DELTA:-1}
count_maildir() {
  find /var/mail/verification/new -maxdepth 1 -type f -print0 | awk 'BEGIN { RS = "\\0" } END { print NR }'
}

before=$(count_maildir)
# smtplib reads each response before advancing, unlike a one-way nc pipeline.
MAILPROOF_SMOKE_RECIPIENT=${recipient} MAILPROOF_SMOKE_MESSAGE_ID=${message_id} python3 - <<'PY'
import os
import smtplib

recipient = os.environ["MAILPROOF_SMOKE_RECIPIENT"]
message_id = os.environ["MAILPROOF_SMOKE_MESSAGE_ID"]
message = (
    f"From: smoke@example.test\r\nTo: {recipient}\r\nSubject: Mailproof smoke\r\n"
    f"Message-ID: <{message_id}>\r\n\r\nMailproof smoke fixture.\r\n"
)
with smtplib.SMTP("postfix", 25, timeout=15) as client:
    client.sendmail("", [recipient], message)
PY
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
