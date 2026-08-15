#!/usr/bin/env bash
set -Eeuo pipefail

postfix check
exec postfix start-fg
