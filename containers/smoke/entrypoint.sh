#!/usr/bin/env bash
set -Eeuo pipefail

message_id=${MAILPROOF_SMOKE_MESSAGE_ID:?MAILPROOF_SMOKE_MESSAGE_ID is required}
recipient_domain=${MAILPROOF_VERIFY_RECIPIENT:?MAILPROOF_VERIFY_RECIPIENT is required}
recipient_domain=${recipient_domain#*@}
state=${MAILPROOF_SMOKE_STATE:?MAILPROOF_SMOKE_STATE is required}
capability_key=${MAILPROOF_SMOKE_CAPABILITY_KEY:?MAILPROOF_SMOKE_CAPABILITY_KEY is required}
expected_delta=${MAILPROOF_SMOKE_EXPECTED_DELTA:-1}
count_maildir() {
	find /var/mail/verification/new -maxdepth 1 -type f -print0 | awk 'BEGIN { RS = "\\0" } END { print NR }'
}

before=$(count_maildir)

# Provision a random test-only capability in the disposable Compose
# state. This exercises the real capability/SPF admission path rather than the
# recipient access map that previously short-circuited policy evaluation.
recipient=$(
	MAILPROOF_SMOKE_STATE=${state} MAILPROOF_SMOKE_CAPABILITY_KEY=${capability_key} MAILPROOF_SMOKE_RECIPIENT_DOMAIN=${recipient_domain} python3 - <<'PY'
import base64
import hashlib
import hmac
import os
import secrets
import sqlite3

state = os.environ["MAILPROOF_SMOKE_STATE"]
key_path = os.environ["MAILPROOF_SMOKE_CAPABILITY_KEY"]
domain = os.environ["MAILPROOF_SMOKE_RECIPIENT_DOMAIN"]
submitter_id = "00000000000000000000000000000001"
capability_id = "00000000000000000000000000000002"
address = "smoke@smoke.mailproof.test"
capability = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
with open(key_path, "rb") as source:
    digest = hmac.new(source.read(), capability.encode(), hashlib.sha256).digest()
with sqlite3.connect(state, timeout=10) as database:
    database.execute("PRAGMA foreign_keys=ON")
    database.execute(
        "INSERT OR IGNORE INTO submitters(submitter_id,canonical_address,status,created_at,verified_at,policy_version,minute_limit,hour_limit,day_limit) VALUES(?,?,'active',unixepoch(),unixepoch(),'v1',5,30,100)",
        (submitter_id, address),
    )
    database.execute(
        "UPDATE submitters SET status='active',verified_at=unixepoch(),revoked_at=NULL WHERE submitter_id=?",
        (submitter_id,),
    )
    database.execute(
        "INSERT INTO submission_capabilities(capability_id,submitter_id,digest,key_id,activated_at,revoked_at) VALUES(?,?,?,'smoke-v1',unixepoch(),NULL) ON CONFLICT(capability_id) DO UPDATE SET digest=excluded.digest,activated_at=excluded.activated_at,revoked_at=NULL",
        (capability_id, submitter_id, digest),
    )
print(f"verify+{capability}@{domain}")
PY
)

# Admission snapshots refresh on a bounded poll; wait for the new synthetic
# identity before opening the SMTP transaction.
sleep 6
# smtplib reads each response before advancing, unlike a one-way nc pipeline.
MAILPROOF_SMOKE_RECIPIENT=${recipient} MAILPROOF_SMOKE_MESSAGE_ID=${message_id} python3 - <<'PY'
import os
import smtplib

recipient = os.environ["MAILPROOF_SMOKE_RECIPIENT"]
message_id = os.environ["MAILPROOF_SMOKE_MESSAGE_ID"]
sender = "smoke@smoke.mailproof.test"
message = (
    f"From: {sender}\r\nTo: {recipient}\r\nSubject: Mailproof smoke\r\n"
    f"Message-ID: <{message_id}>\r\n\r\nMailproof smoke fixture.\r\n"
)
with smtplib.SMTP("postfix", 25, timeout=15) as client:
    client.sendmail(sender, [recipient], message)
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
