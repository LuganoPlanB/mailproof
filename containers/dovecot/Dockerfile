ARG DEBIAN_BASE=debian@sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258
FROM ${DEBIAN_BASE}
ARG DOVECOT_VERSION
ARG DEBIAN_SNAPSHOT
RUN set -eux; \
    rm -f /etc/apt/sources.list.d/debian.sources; \
    printf '%s\n' \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/ trixie main" \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}/ trixie-security main" \
      > /etc/apt/sources.list; \
    apt-get -o Acquire::Check-Valid-Until=false update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "dovecot-lmtpd=${DOVECOT_VERSION}" "dovecot-sieve=${DOVECOT_VERSION}"; \
    rm -rf /var/lib/apt/lists/*; \
    groupadd --gid 1000 mailproof; \
    useradd --uid 1000 --gid 1000 --home-dir /var/mail/verification --no-create-home --shell /usr/sbin/nologin mailproof
COPY containers/dovecot/entrypoint.sh /usr/local/bin/mailproof-dovecot
RUN chmod 0755 /usr/local/bin/mailproof-dovecot
ENTRYPOINT ["/usr/local/bin/mailproof-dovecot"]
