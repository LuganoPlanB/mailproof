#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
	printf '%s\n' 'usage: drain.sh --dry-run|--confirm [--max-jobs N] [--max-runtime DURATION]' >&2
}

mode=''
max_jobs=''
max_runtime=''
while (($#)); do
	case $1 in
	--dry-run | --confirm)
		[[ -z ${mode} ]] || {
			usage
			exit 2
		}
		mode=$1
		;;
	--max-jobs)
		shift
		(($#)) || {
			usage
			exit 2
		}
		max_jobs=$1
		;;
	--max-runtime)
		shift
		(($#)) || {
			usage
			exit 2
		}
		max_runtime=$1
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
[[ -z ${max_jobs} || ${max_jobs} =~ ^[0-9]+$ ]] || {
	usage
	exit 2
}

args=(worker --drain)
[[ -n ${max_jobs} ]] && args+=(--max-jobs "${max_jobs}")
[[ -n ${max_runtime} ]] && args+=(--max-runtime "${max_runtime}")
if [[ ${mode} == --dry-run ]]; then
	printf 'would run docker compose run --rm worker'
	printf ' %q' "${args[@]}"
	printf '\n'
	exit 0
fi

exec docker compose run --rm worker "${args[@]}"
