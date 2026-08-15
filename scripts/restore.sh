#!/usr/bin/env bash
set -Eeuo pipefail

usage() { printf '%s\n' 'usage: restore.sh --dry-run|--confirm --input DIRECTORY' >&2; }
mode=''
input=''
while (($#)); do
	case $1 in
	--dry-run | --confirm)
		[[ -z ${mode} ]] || {
			usage
			exit 2
		}
		mode=$1
		;;
	--input)
		shift
		(($#)) || {
			usage
			exit 2
		}
		input=$1
		;;
	*)
		usage
		exit 2
		;;
	esac
	shift
done
[[ -n ${mode} && -n ${input} ]] || {
	usage
	exit 2
}
[[ -f ${input}/SHA256SUMS ]] || {
	printf '%s\n' 'backup manifest is missing' >&2
	exit 1
}
if [[ ${mode} == --dry-run ]]; then
	printf 'would verify and restore %q into a stopped, clean Compose project; Redis and Unbound caches are intentionally excluded\n' "${input}"
	exit 0
fi
command -v docker >/dev/null 2>&1 || {
	printf '%s\n' 'required command is unavailable: docker' >&2
	exit 127
}
(cd -- "${input}" && sha256sum --check SHA256SUMS)
docker compose down
docker compose up -d init
docker compose cp "${input}/mailproof.sqlite" collector:/state/mailproof.sqlite
docker compose cp "${input}/artifacts/." collector:/artifacts
docker compose cp "${input}/maildir/." dovecot:/var/mail/verification
docker compose cp "${input}/postfix-log/." postfix:/var/log/mailproof
docker compose cp "${input}/runtime/." init:/runtime
printf '%s\n' 'restore copied verified authority. Start the full graph, then run scripts/smoke.sh --confirm.'
