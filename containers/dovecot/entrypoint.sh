#!/usr/bin/env bash
set -Eeuo pipefail

mkdir -p -- /var/mail/verification/{cur,new,tmp}
chown mailproof:mailproof /var/mail/verification /var/mail/verification/{cur,new,tmp}
dovecot -n
exec dovecot -F
