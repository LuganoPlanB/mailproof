ARG DEBIAN_BASE
FROM ${DEBIAN_BASE}
ARG DEBIAN_SNAPSHOT
ARG PACKAGES
RUN set -eux; rm -f /etc/apt/sources.list.d/debian.sources; printf '%s\n' "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/ trixie main" > /etc/apt/sources.list; apt-get -o Acquire::Check-Valid-Until=false update; DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ${PACKAGES}; rm -rf /var/lib/apt/lists/*
COPY containers/analyzer/entrypoint.sh /usr/local/bin/mailproof-analyzer
COPY containers/analyzer/olefy.py /usr/local/lib/mailproof-olefy.py
ENTRYPOINT ["/usr/local/bin/mailproof-analyzer"]
