#!/usr/bin/env bash
set -Eeuo pipefail

usage() { printf '%s\n' 'usage: init.sh --dry-run|--confirm --report-recipient ADDRESS' >&2; }
mode=''
report_recipient=''
while (($#)); do
	case $1 in
	--dry-run | --confirm)
		[[ -z ${mode} ]] || {
			usage
			exit 2
		}
		mode=$1
		;;
	--report-recipient)
		shift
		(($#)) || {
			usage
			exit 2
		}
		report_recipient=$1
		;;
	*)
		usage
		exit 2
		;;
	esac
	shift
done
[[ -n ${mode} && -n ${report_recipient} ]] || {
	usage
	exit 2
}
if [[ ${mode} == --dry-run ]]; then
	printf 'would initialize runtime directories for report recipient %q\n' "${report_recipient}"
	exit 0
fi
MAILPROOF_REPORT_RECIPIENT=${report_recipient} docker compose run --rm init
