#!/usr/bin/env bash
set -Eeuo pipefail

# shellcheck source=lib.sh
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "${script_dir}/lib.sh"

usage() { printf '%s\n' 'usage: smoke.sh --dry-run|--confirm [--clean]' >&2; }
mode=''
clean=false
while (($#)); do
	case $1 in
	--dry-run | --confirm)
		[[ -z ${mode} ]] || {
			usage
			exit 2
		}
		mode=$1
		;;
	--clean) clean=true ;;
	*)
		usage
		exit 2
		;;
	esac
	shift
done
[[ -n ${mode} ]] || {
	usage
	exit 2
}
mailproof_require_command docker
if [[ ${mode} == --dry-run ]]; then
	printf '%s\n' 'would wait for Compose health and submit one synthetic SMTP fixture'
	exit 0
fi

message_id="mailproof-smoke-$(date +%s)-$$"
diagnostics() {
	status=$?
	if ((status != 0)); then
		mailproof_log 'smoke failed; concise service diagnostics follow'
		docker compose ps >&2 || true
		docker compose logs --tail=40 postfix dovecot collector >&2 || true
	fi
	exit "${status}"
}
trap diagnostics EXIT

for attempt in $(seq 1 30); do
	compose_state=$(docker compose ps --format json 2>/dev/null || true)
	if printf '%s' "${compose_state}" | grep -q '"Service":"postfix".*"Health":"healthy"' &&
		printf '%s' "${compose_state}" | grep -q '"Service":"dovecot".*"Health":"healthy"'; then
		break
	fi
	((attempt < 30)) || {
		mailproof_log 'timed out waiting for Postfix/Dovecot health'
		exit 1
	}
	sleep 2
done

MAILPROOF_SMOKE_MESSAGE_ID=${message_id} docker compose --profile smoke run --rm smoke
if [[ ${clean} == true ]]; then
	mailproof_log 'cleaning only this Compose project; named volumes are retained'
	docker compose down
fi
mailproof_log "fixture accepted with Message-ID ${message_id}"
