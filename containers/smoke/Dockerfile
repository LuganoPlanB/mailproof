ARG DEBIAN_BASE=debian@sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258
FROM ${DEBIAN_BASE}
ARG NETCAT_OPENBSD_VERSION
ARG PYTHON3_VERSION
ARG DEBIAN_SNAPSHOT
RUN set -eux; \
    rm -f /etc/apt/sources.list.d/debian.sources; \
    printf '%s\n' \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/ trixie main" \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}/ trixie-security main" \
      > /etc/apt/sources.list; \
    apt-get -o Acquire::Check-Valid-Until=false update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "netcat-openbsd=${NETCAT_OPENBSD_VERSION}" "python3=${PYTHON3_VERSION}"; \
    rm -rf /var/lib/apt/lists/*
COPY containers/smoke/entrypoint.sh /usr/local/bin/mailproof-smoke
RUN chmod 0755 /usr/local/bin/mailproof-smoke
ENTRYPOINT ["/usr/local/bin/mailproof-smoke"]
