#!/usr/bin/env bash
set -Eeuo pipefail
usage() { printf '%s\n' 'usage: rspamd-check.sh --message FILE --ip IP --helo NAME --from ADDRESS --queue-id ID [--detached]' >&2; }
message='' ip='' helo='' from='' queue=''
while (($#)); do
	case $1 in --message)
		shift
		message=${1:-}
		;;
	--ip)
		shift
		ip=${1:-}
		;;
	--helo)
		shift
		helo=${1:-}
		;;
	--from)
		shift
		from=${1:-}
		;;
	--queue-id)
		shift
		queue=${1:-}
		;;
	--detached) : ;; *)
		usage
		exit 2
		;;
	esac
	shift
done
[[ -r ${message} ]] || {
	usage
	exit 2
}
metadata=$(printf '{"ip":"%s","helo":"%s","from":"%s","queue_id":"%s","hostname":"postfix.mailproof.test","rcpt":"verify@mailproof.test"}' "${ip}" "${helo}" "${from}" "${queue}")
curl --fail --silent --show-error --max-time 30 -H 'Content-Type: message/rfc822' -H "Settings: {\"pass_all\":true,\"ext_urls\":true,\"metadata\":${metadata}}" --data-binary "@${message}" http://rspamd:11333/checkv3
