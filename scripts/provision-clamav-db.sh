#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  printf '%s\n' 'usage: provision-clamav-db.sh --dry-run|--confirm --url HTTPS_URL --sha256 HEX --version VERSION [--database NAME]' >&2
}

mode=''
url=''
expected_sha256=''
version=''
database='main'
while (($#)); do
  case $1 in
    --dry-run|--confirm) [[ -z ${mode} ]] || { usage; exit 2; }; mode=$1 ;;
    --url) shift; (($#)) || { usage; exit 2; }; url=$1 ;;
    --sha256) shift; (($#)) || { usage; exit 2; }; expected_sha256=$1 ;;
    --version) shift; (($#)) || { usage; exit 2; }; version=$1 ;;
    --database) shift; (($#)) || { usage; exit 2; }; database=$1 ;;
    *) usage; exit 2 ;;
  esac
  shift
done
[[ -n ${mode} && -n ${url} && -n ${expected_sha256} && -n ${version} ]] || { usage; exit 2; }
[[ ${url} == https://* ]] || { printf '%s\n' 'database URL must use HTTPS' >&2; exit 2; }
[[ ${expected_sha256} =~ ^[0-9a-f]{64}$ ]] || { printf '%s\n' 'SHA-256 must be lowercase hexadecimal' >&2; exit 2; }
[[ ${database} =~ ^(main|daily|bytecode)$ ]] || { printf '%s\n' 'database must be main, daily, or bytecode' >&2; exit 2; }

if [[ ${mode} == --dry-run ]]; then
  printf 'would download %s, verify SHA-256, record version %q, and stage %s.cvd in the named clamav-db volume\n' "${url}" "${version}" "${database}"
  exit 0
fi
for command in curl docker sha256sum; do command -v "${command}" >/dev/null 2>&1 || { printf 'required command is unavailable: %s\n' "${command}" >&2; exit 127; }; done

stage_dir=$(mktemp -d)
cleanup() { rm -rf -- "${stage_dir}"; }
trap cleanup EXIT
curl --fail --location --proto '=https' --tlsv1.2 --output "${stage_dir}/${database}.cvd" "${url}"
actual_sha256=$(sha256sum "${stage_dir}/${database}.cvd" | awk '{print $1}')
[[ ${actual_sha256} == "${expected_sha256}" ]] || { printf '%s\n' 'ClamAV database digest mismatch; nothing was published' >&2; exit 1; }
printf '{"schema":"mailproof.clamav-database/v1","database":"%s","version":"%s","sha256":"%s","source":"%s"}\n' \
  "${database}" "${version}" "${actual_sha256}" "${url}" > "${stage_dir}/provenance.json"

# The init container owns the named volume. `compose cp` copies only the
# verified staged files and replaces neither runtime secrets nor other volumes.
docker compose create init >/dev/null
docker compose cp "${stage_dir}/." init:/clamav-db
printf 'verified ClamAV %s database %s (%s) staged; restart clamav to validate its signed CVD contents\n' "${database}" "${version}" "${actual_sha256}"
