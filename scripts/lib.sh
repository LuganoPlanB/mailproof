#!/usr/bin/env bash
set -Eeuo pipefail

mailproof_require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'required command is unavailable: %s\n' "$1" >&2
    return 127
  }
}

mailproof_log() {
  local observed_at
  observed_at=$(date --iso-8601=seconds)
  printf '%s %s\n' "${observed_at}" "$*" >&2
}
