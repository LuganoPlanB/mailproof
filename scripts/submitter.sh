#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
usage() { printf '%s\n' 'usage: submitter.sh add --report-recipient ADDRESS --dry-run|--confirm | revoke --submitter-id ID --dry-run|--confirm | list-redacted' >&2; }
action=${1:-}
shift || true
runtime=${MAILPROOF_RUNTIME:-runtime}
registry="${runtime}/secrets/submitters.json"
access="${runtime}/secrets/postfix-recipient-access"
mode=''
recipient=''
submitter_id=''
while (($#)); do
	case $1 in --dry-run | --confirm) mode=$1 ;; --report-recipient)
		shift
		recipient=${1:-}
		;;
	--submitter-id)
		shift
		submitter_id=${1:-}
		;;
	*)
		usage
		exit 2
		;;
	esac
	shift
done
case "${action}" in
list-redacted)
	python3 - "${registry}" <<'PY'
import json,sys
for x in json.load(open(sys.argv[1])): print({'submitterId':x['submitterId'],'tokenHash':x['tokenHash'][:12]+'…','revoked':x['revoked']})
PY
	;;
add | revoke)
	[[ -n ${mode} && -f ${registry} && -f ${access} ]] || {
		usage
		exit 2
	}
	[[ ${mode} == --dry-run ]] && {
		printf 'would %s submitter registry and access map\n' "${action}"
		exit 0
	}
	exec 9>"${registry}.lock"
	flock -x 9
	python3 - "${action}" "${registry}" "${access}" "${recipient}" "${submitter_id}" <<'PY'
import hashlib,json,os,secrets,sys,tempfile
a,reg,mapf,rcpt,sid=sys.argv[1:]
x=json.load(open(reg))
old=open(mapf).read().splitlines()
if a=='add':
 if not rcpt or '\n' in rcpt or '\r' in rcpt: raise SystemExit('invalid report recipient')
 token=secrets.token_hex(16); sid=secrets.token_hex(12); x.append({'submitterId':sid,'tokenHash':hashlib.sha256(token.encode()).hexdigest(),'reportRecipient':rcpt,'revoked':False}); old.append('verify+'+token+'@mailproof.test OK # '+sid); print('verify+'+token+'@mailproof.test',file=sys.stderr); print('submitter-id='+sid)
else:
 found=False
 for i in x:
  if i['submitterId']==sid: i['revoked']=True; found=True
 if not found: raise SystemExit('unknown submitter id')
 old=[line for line in old if not line.endswith('# '+sid)]
fd,tmp=tempfile.mkstemp(dir=os.path.dirname(reg)); os.write(fd,json.dumps(x,separators=(',',':')).encode()); os.fsync(fd); os.close(fd); os.replace(tmp,reg)
open(mapf,'w').write('\n'.join(old)+'\n')
PY
	postmap "${access}"
	postfix reload
	;;
*)
	usage
	exit 2
	;;
esac
