ARG DEBIAN_BASE
FROM ${DEBIAN_BASE}
ARG DEBIAN_SNAPSHOT
ARG CLAMAV_VERSION
ARG CURL_VERSION
ARG CA_CERTIFICATES_VERSION
RUN set -eux; \
    rm -f /etc/apt/sources.list.d/debian.sources; \
    printf '%s\n' "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}/ trixie main" > /etc/apt/sources.list; \
    apt-get -o Acquire::Check-Valid-Until=false update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      "clamav-freshclam=${CLAMAV_VERSION}" "curl=${CURL_VERSION}" "ca-certificates=${CA_CERTIFICATES_VERSION}"; \
    rm -rf /var/lib/apt/lists/*
COPY containers/clamav-provisioner/entrypoint.sh /usr/local/bin/mailproof-clamav-provisioner
RUN chmod 0755 /usr/local/bin/mailproof-clamav-provisioner
ENTRYPOINT ["/usr/local/bin/mailproof-clamav-provisioner"]
