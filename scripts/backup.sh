#!/usr/bin/env bash
set -Eeuo pipefail

usage() { printf '%s\n' 'usage: backup.sh --dry-run|--confirm --output DIRECTORY' >&2; }
mode=''
output=''
while (($#)); do
  case $1 in
    --dry-run|--confirm) [[ -z ${mode} ]] || { usage; exit 2; }; mode=$1 ;;
    --output) shift; (($#)) || { usage; exit 2; }; output=$1 ;;
    *) usage; exit 2 ;;
  esac
  shift
done
[[ -n ${mode} && -n ${output} ]] || { usage; exit 2; }
if [[ ${mode} == --dry-run ]]; then
  printf 'would create a SQLite online backup and copy immutable artifacts, Maildir, ingress logs, runtime keys, and configuration to %q\n' "${output}"
  exit 0
fi
command -v docker >/dev/null 2>&1 || { printf '%s\n' 'required command is unavailable: docker' >&2; exit 127; }
[[ ! -e ${output} ]] || { printf '%s\n' 'backup output must not already exist' >&2; exit 1; }
mkdir -p -- "${output}"
docker compose exec -T collector sh -c 'sqlite3 /state/mailproof.sqlite ".backup /state/mailproof.backup.sqlite"'
docker compose cp collector:/state/mailproof.backup.sqlite "${output}/mailproof.sqlite"
docker compose cp collector:/artifacts "${output}/artifacts"
docker compose cp dovecot:/var/mail/verification "${output}/maildir"
docker compose cp postfix:/var/log/mailproof "${output}/postfix-log"
docker compose cp init:/runtime "${output}/runtime"
cp -a -- config "${output}/config"
find "${output}" -type f -print0 | sort -z | xargs -0 sha256sum > "${output}/SHA256SUMS"
printf 'backup complete: %s\n' "${output}"
