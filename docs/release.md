# Release qualification

The supported deployment target is Linux amd64 and arm64 when every pinned
Debian package is published for that architecture. CI uses Docker Engine 27.0+
and Docker Compose 2.30+. Build the Go binary with `-trimpath` and fixed version
metadata; compare two clean binary SHA-256 digests. Image digest differences
must be recorded with their base-image and package-lock cause.

Release gates are Compose config/build/smoke, Rspamd config and Lua fixtures,
`go test ./...`, `go test -race ./...`, `go vet ./...`, `govulncheck ./...`,
`staticcheck ./...`, ShellCheck, schema/fixture validation, image/SBOM/license
and vulnerability scans. The release bundle includes source, binary and image
digests, SBOMs, module/license inventory, capability ADR, and compatibility
matrix. Scanner exceptions are accepted only from `config/security-exceptions.yml`
with an owner, expiry, rationale, and compensating control.

Successful `quality` runs on `main` trigger `.github/workflows/release.yml`.
The first release is `v0.1.0`; later versions are calculated from conventional
commits by the pinned `ietf-tools/semver-action`. Each GitHub release contains a
Compose file with `MAILPROOF_VERSION` stamped into its application-image build
arguments and an adjacent SHA-256 checksum. The same value is embedded in the
`mailproof version` output and the OCI image version label.
