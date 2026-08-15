ARG DEBIAN_BASE
FROM ${DEBIAN_BASE}
ARG DEBIAN_SNAPSHOT
ARG OPENSSL_VERSION
RUN set -eux; rm -f /etc/apt/sources.list.d/debian.sources; printf '%s\n' "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/ trixie main" > /etc/apt/sources.list; apt-get -o Acquire::Check-Valid-Until=false update; DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "openssl=${OPENSSL_VERSION}"; rm -rf /var/lib/apt/lists/*
