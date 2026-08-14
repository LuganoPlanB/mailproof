#!/usr/bin/env bash
set -Eeuo pipefail

postconf -e 'maillog_file = /var/log/mailproof/postfix.log'
postmap /runtime/secrets/postfix-recipient-access
postfix check
exec postfix start-fg
