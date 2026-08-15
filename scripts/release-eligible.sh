#!/usr/bin/env bash
set -Eeuo pipefail

usage() { printf '%s\n' 'usage: release-eligible.sh BASE [HEAD]' >&2; }

base=${1:-}
head=${2:-HEAD}
((1 <= $# && $# <= 2)) || {
	usage
	exit 2
}

git rev-parse --verify --quiet "${base}^{commit}" >/dev/null || {
	printf 'invalid release base: %s\n' "${base}" >&2
	exit 2
}
git rev-parse --verify --quiet "${head}^{commit}" >/dev/null || {
	printf 'invalid release head: %s\n' "${head}" >&2
	exit 2
}

commit_list=$(git rev-list --reverse --first-parent "${base}..${head}")
commits=()
if [[ -n ${commit_list} ]]; then
	mapfile -t commits <<<"${commit_list}"
fi
docs_subject='^docs(\([^)]*\))?:'
for commit in "${commits[@]}"; do
	subject=$(git show --no-patch --format=%s "${commit}")
	if [[ ${subject} =~ ${docs_subject} ]]; then
		continue
	fi

	if git diff --quiet "${commit}^" "${commit}" -- . ':(exclude)README.md' ':(exclude)docs/**'; then
		continue
	else
		status=$?
		((status == 1)) || exit "${status}"
		printf '%s\n' true
		exit 0
	fi
done

printf '%s\n' false
