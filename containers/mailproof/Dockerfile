ARG GO_BUILDER=golang:1.26.5-bookworm@sha256:53eeac89074db483fdf0ab3be1df32bf6e47562263d2d0d6baa7f26acb4957dd
ARG DEBIAN_BASE=debian@sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258
FROM ${GO_BUILDER} AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/mailproof ./cmd/mailproof

FROM ${DEBIAN_BASE}
RUN groupadd --gid 1000 mailproof && useradd --uid 1000 --gid 1000 --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin mailproof
COPY --from=build /out/mailproof /usr/local/bin/mailproof
USER mailproof:mailproof
ENTRYPOINT ["/usr/local/bin/mailproof"]
