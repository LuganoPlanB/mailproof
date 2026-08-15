# Release qualification

Published release images target Linux amd64. Other Linux architectures build
the matching tag natively from source when every pinned base image and Debian
package is available. CI uses Docker Engine 27.0+ and Docker Compose 2.30+.
Build the Go binary with `-trimpath` and fixed version metadata; compare two
clean binary SHA-256 digests. Image digest differences must be recorded with
their base-image and package-lock cause.

Release gates are Compose config/build/smoke, Rspamd config and Lua fixtures,
`go test ./...`, `go test -race ./...`, `go vet ./...`, `govulncheck ./...`,
`staticcheck ./...`, ShellCheck, schema/fixture validation, image/SBOM/license
and vulnerability scans. The release bundle includes source, binary and image
digests, SBOMs, module/license inventory, capability ADR, and compatibility
matrix. Scanner exceptions are accepted only from `config/security-exceptions.yml`
with an owner, expiry, rationale, and compensating control.

Successful `quality` runs on `main` trigger `.github/workflows/release.yml`.
The first release is `v0.1.0`; later versions are calculated from conventional
commits by the pinned `ietf-tools/semver-action`. Before creating a GitHub
release, CI builds every unique Compose image for Linux amd64, pushes it as a
versioned component tag in the public `ghcr.io/luganoplanb/mailproof` package,
logs out of GHCR, pulls it
anonymously, and smoke-tests the complete published graph. Each release
contains an image-only Compose file whose versioned GHCR tags have been
replaced by immutable repository digests, plus an adjacent SHA-256 checksum.
The release value remains embedded in `mailproof version` and the OCI image
version labels.

Source builds use `compose.yaml` plus the automatically loaded
`compose.override.yaml`. Release consumers set `COMPOSE_FILE` to the downloaded
Compose asset, which intentionally bypasses the build override while retaining
the matching tag's reviewed configuration files and operator scripts.

GHCR creates a new container package as private and provides no documented API
for changing that visibility. A repository administrator must therefore make
the `mailproof` package public once in its GitHub package settings after the
first image push. The first release run stops with an explicit error until this
one-time setting is complete; all later releases verify it automatically.

Every `main` commit runs a lightweight change-classification job. The code,
security, build, and Compose smoke jobs are skipped when all changes are
confined to `README.md` or `docs/`, or when commits use a `docs:` or
conventional `docs(scope):` prefix. Release calculation follows the same rule.
A commit that changes both software and documentation remains eligible unless
it explicitly uses a documentation prefix.
