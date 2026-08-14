#!/usr/bin/env bash
set -Eeuo pipefail

mkdir -p -- /var/mail/verification
chown mailproof:mailproof /var/mail/verification
dovecot -n
exec dovecot -F
