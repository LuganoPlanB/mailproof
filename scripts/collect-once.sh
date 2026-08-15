#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
	printf '%s\n' 'usage: collect-once.sh --dry-run|--confirm' >&2
}

mode=''
while (($#)); do
	case $1 in
	--dry-run | --confirm)
		[[ -z ${mode} ]] || {
			usage
			exit 2
		}
		mode=$1
		;;
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

if [[ ${mode} == --dry-run ]]; then
	printf '%s\n' 'would run one Maildir collection sweep'
	exit 0
fi

exec docker compose run --rm collector collect --once
