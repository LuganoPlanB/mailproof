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
