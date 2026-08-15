#!/usr/bin/env bash
set -Eeuo pipefail

database_dir=/var/lib/clamav
mode=${MAILPROOF_CLAMAV_PROVISION:-none}
database=${MAILPROOF_CLAMAV_DATABASE:-main}
url=${MAILPROOF_CLAMAV_DATABASE_URL:-}
expected_sha256=${MAILPROOF_CLAMAV_DATABASE_SHA256:-}
version=${MAILPROOF_CLAMAV_DATABASE_VERSION:-}

write_provenance() {
	local digest=$1 source=$2
	printf '{"schema":"mailproof.clamav-database/v1","database":"%s","version":"%s","sha256":"%s","source":"%s"}\n' \
		"${database}" "${version}" "${digest}" "${source}" >"${database_dir}/provenance.json"
}

provision_artifact() {
	[[ ${url} == https://* ]] || {
		printf '%s\n' 'artifact mode requires MAILPROOF_CLAMAV_DATABASE_URL using HTTPS' >&2
		return 2
	}
	[[ ${expected_sha256} =~ ^[0-9a-f]{64}$ ]] || {
		printf '%s\n' 'artifact mode requires lowercase MAILPROOF_CLAMAV_DATABASE_SHA256' >&2
		return 2
	}
	[[ -n ${version} && ${database} =~ ^(main|daily|bytecode)$ ]] || {
		printf '%s\n' 'artifact mode requires version and a valid database name' >&2
		return 2
	}
	local temporary actual
	temporary=$(mktemp "${database_dir}/.${database}.XXXXXX")
	trap 'rm -f -- "${temporary}"' RETURN
	curl --fail --location --proto '=https' --tlsv1.2 --output "${temporary}" "${url}"
	actual=$(sha256sum "${temporary}" | awk '{print $1}')
	[[ ${actual} == "${expected_sha256}" ]] || {
		printf '%s\n' 'ClamAV artifact digest mismatch; refusing publication' >&2
		return 1
	}
	mv -f -- "${temporary}" "${database_dir}/${database}.cvd"
	write_provenance "${actual}" "${url}"
}

provision_latest() {
	# This is deliberately opt-in: definitions are mutable and not reproducible.
	freshclam --datadir="${database_dir}" --stdout
	local digest
	digest=$(sha256sum "${database_dir}"/*.cvd | sha256sum | awk '{print $1}')
	version="freshclam-latest-$(date -u +%Y%m%dT%H%M%SZ)"
	write_provenance "${digest}" "freshclam"
}

case ${1:-once} in
once)
	case ${mode} in
	none) printf '%s\n' 'ClamAV provisioning disabled; an existing verified database is required' ;;
	artifact) provision_artifact ;;
	latest) provision_latest ;;
	*)
		printf 'unknown MAILPROOF_CLAMAV_PROVISION: %s\n' "${mode}" >&2
		exit 2
		;;
	esac
	;;
update-loop)
	[[ ${mode} == latest ]] || {
		printf '%s\n' 'clamav updater requires MAILPROOF_CLAMAV_PROVISION=latest' >&2
		exit 2
	}
	interval=${MAILPROOF_CLAMAV_UPDATE_INTERVAL_SECONDS:-21600}
	[[ ${interval} =~ ^[1-9][0-9]*$ ]] || {
		printf '%s\n' 'update interval must be a positive integer' >&2
		exit 2
	}
	while true; do
		set +e
		provision_latest
		update_status=$?
		set -e
		if ((update_status != 0)); then
			printf '%s\n' 'freshclam update failed; keeping prior database' >&2
		fi
		sleep "${interval}"
	done
	;;
*)
	printf '%s\n' 'usage: mailproof-clamav-provisioner {once|update-loop}' >&2
	exit 2
	;;
esac
