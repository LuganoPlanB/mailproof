# Mailproof agent guide

## What this repository is

Mailproof is a Go 1.26.6 service and hardened Docker Compose deployment for
accepting verification mail, preserving the delivered bytes, running analyzers,
and producing signed evidence reports. The module is
`github.com/luganoplanb/mailproof`; the executable entry point is
`cmd/mailproof`.

The production path is Postfix -> Dovecot LMTP -> verification Maildir ->
singleton collector -> immutable artifact archive and SQLite queue -> parallel
workers/analyzers -> reporter -> Postfix. Read the accepted ADRs in `docs/adr/`
before changing this path or the meaning of evidence.

## Non-negotiable invariants

- The exact Maildir file delivered by Postfix/Dovecot is sealed before analysis.
  Analyzers may append immutable run results but must never alter that original.
- SMTP transaction facts are a separate trusted local record. Message-supplied
  routing and authentication headers remain untrusted unless a versioned rule
  explicitly accepts them.
- Exactly one top-level `message/rfc822` child selects detached verification;
  none selects the delivered original; more than one is INDETERMINATE. Never
  apply wrapper SPF/envelope facts to a detached child.
- Delivery IDs, message digests, selection IDs, and run IDs are distinct. Do not
  collapse duplicate message bytes into one delivery or overwrite an old run.
- Queue work uses SQLite leases. Replays create new runs, unknown replies are
  quarantined, and schema migrations are forward-only.
- The collector is a singleton. Stop the continuous Compose collector before a
  scheduled `collect --once` run; competing collectors deliberately exit 3.
  Use `compose run --no-deps` for maintenance probes against an already-started
  graph so Compose does not rerun `init` or re-evaluate unrelated dependencies.
- Reporter signing material is confined to the read-only runtime volume and the
  report network. Keep analyzer, scanner, mail, report, and public network
  boundaries intact.
- Admission accepts only an active submitter capability bound to the observed
  envelope sender and SPF pass. Selected-subject sender allowlisting is a
  separate post-DATA eligibility check and must never authenticate a detached
  child or route replies from message headers.
- Result and rejection rows are rebuildable projections; signed immutable
  artifacts remain authoritative. Keep the results API internal, token-gated,
  bounded, and free of raw mail, addresses, peer IPs, capabilities, and keys.
- Missing or invalid scanner data is unavailable/indeterminate, never a clean
  result. Security exceptions must be declared in
  `config/security-exceptions.yml` with owner, expiry, rationale, and a
  compensating control.

## Repository map

- `cmd/mailproof/`: CLI/service composition and command dispatch.
- `internal/analyzers/`: content, crypto, DNS, and Rspamd evidence adapters.
- `internal/artifact/`: immutable artifact storage.
- `internal/evidence/`: policy, provenance, projections, publication, and
  analyzer orchestration.
- `internal/ingress/`: transaction-to-delivery correlation.
- `internal/queue/`: SQLite schema, leases, retries, replay, and quarantine.
- `internal/report/`: rendering, replies, signing, and verification.
- `internal/admission/`, `internal/submitter/`, `internal/results/`: trusted
  sender admission, enrolled identity, rejection/result projections, and the
  authenticated internal read API.
- `compose.yaml`, `containers/`, `config/`: production topology, images, pinned
  versions, and service configuration.
- `compose.override.yaml`: automatically loaded source-build definitions. The
  base `compose.yaml` is intentionally image-only so it can be released as a
  pull-based deployment without local build instructions.
- `scripts/`: operator orchestration; `tests/shell/`: Bats contracts.
- `docs/adr/` and `docs/runbooks/`: architectural authority and operations.

## Editing rules

- Keep hostile mail, DNS, URL, archive, and cryptographic parsing in Go or the
  dedicated analyzers, never shell.
- Bash is orchestration glue: use `set -Eeuo pipefail`, quote values, pass paths
  as arguments, use `mktemp -d` plus cleanup traps, and keep traversal NUL-safe.
  Do not use `eval` or source mail-derived data.
- State-changing scripts must offer `--dry-run` and require explicit
  `--confirm`. Preserve these contracts when adding operations.
- Run `shfmt -w scripts containers` after every shell edit. CI checks the whole
  directories, including container entrypoints, with shfmt's defaults.
- Pin base images and Debian/Python dependencies through `config/versions.env`
  and the existing lock files. Avoid floating versions in release paths.
- `MAILPROOF_VERSION` flows from Compose into the Mailproof binary and OCI image
  label. Releases bootstrap at `v0.1.0`, then use conventional commits through
  the SHA-pinned `ietf-tools/semver-action`; keep released Compose files stamped
  and accompanied by their SHA-256 checksum.
- Release images are public Linux amd64 tags under the single
  `ghcr.io/luganoplanb/mailproof` package. Build and push every unique image before
  creating the GitHub release, make the released Compose file digest-pinned,
  and smoke-test it after logging out of GHCR. Other architectures build from
  source through the automatically merged Compose override.
- Documentation changes run only the lightweight CI classifier: `docs:`
  commits and changes limited to `README.md` or `docs/` must skip code-quality,
  build, Compose smoke, and software release jobs. Keep both quality and release
  eligibility centralized in `scripts/release-eligible.sh`.
- Preserve Compose hardening (`no-new-privileges`, dropped capabilities,
  read-only filesystems, resource limits) and expose a host port only through
  Postfix unless an accepted ADR changes the boundary.
- ClamAV is the resource exception: its configurable default is 4 GiB and must
  remain at least 3 GiB for current signature databases. Do not apply the shared
  512 MiB service limit to `clamav`.
- Keep healthchecks within the commands actually installed by each minimal
  image. Postfix, Unbound, and ClamAV intentionally use Bash `/dev/tcp`; the
  minimal images do not install the previous `nc` or `clamdscan` probes.
- In shell orchestration, query container health with `docker compose ps -q`
  plus `docker inspect --format`; do not scrape Compose JSON formatting.
- Unbound requires the pinned `dns-root-data` package and an installed
  `/var/lib/unbound/root.key` for the Debian default DNSSEC configuration. Its
  bootstrap capabilities are needed to bind port 53, create runtime files, and
  drop to the package user.
- Add focused tests beside changed Go packages. Update Bats/contract tests for
  observable shell or Compose changes. Update an ADR when changing an accepted
  evidence or capability decision.

## Verification

The authoritative CI workflow is `.github/workflows/quality.yml`. Before
pushing, run the relevant subset; for release- or CI-facing changes, mirror all
commands when the required tools are available:

```bash
go mod verify
test -z "$(gofmt -l cmd internal)"
go test ./...
go test -race ./...
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@latest ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
shellcheck --enable=all --shell=bash scripts/*.sh containers/*/entrypoint.sh
shfmt -d scripts containers
bats tests/shell
bash tests/mail-ingress-contract.sh
docker compose --env-file config/versions.env config --quiet
docker compose --env-file config/versions.env build --pull
```

The dependent remote `compose-smoke` job builds and starts the complete graph,
runs `rspamadm configtest`, performs SMTP smoke delivery, exercises collection
and worker drain, and always tears the graph down. A local operational smoke run
uses dry-run first, then explicit confirmation as documented in
`docs/runbooks/compose.md`.

## Operational safety

- Generated `runtime/`, artifacts, Maildir, SQLite/WAL, ingress logs, token
  registry, signing keys, and committed configuration are authoritative or
  secret state. Do not edit, delete, or commit generated runtime contents.
- Never run `docker compose down -v`; it destroys authoritative named volumes.
- Backup and restore must start with the scripts' dry-run mode. Restore only to
  a fresh project and verify the checksum manifest before writing volumes.
- Redis and Unbound are disposable caches and are not backup inputs. Retention
  must use a supported command after a verified backup, never direct volume-file
  deletion.
