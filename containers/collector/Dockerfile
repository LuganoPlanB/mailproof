ARG DEBIAN_BASE=debian@sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258
FROM ${DEBIAN_BASE}
RUN groupadd --gid 1000 mailproof && useradd --uid 1000 --gid 1000 --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin mailproof
USER mailproof:mailproof
CMD ["sleep", "infinity"]
