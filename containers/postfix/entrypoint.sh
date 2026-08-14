#!/usr/bin/env bash
set -Eeuo pipefail

postconf -e 'maillog_file = /var/log/mailproof/postfix.log'
postfix check
exec postfix start-fg
