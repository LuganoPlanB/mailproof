#!/usr/bin/env bats

@test "final graph validates with pinned environment" {
  run docker compose --env-file config/versions.env config --quiet
  [ "$status" -eq 0 ]
}

@test "only Postfix publishes a host port" {
  run docker compose --env-file config/versions.env config
  [ "$status" -eq 0 ]
  [ "$(printf '%s\n' "$output" | grep -c 'published:')" -eq 1 ]
}

@test "hardening and service graph are declared" {
  run docker compose --env-file config/versions.env config
  [ "$status" -eq 0 ]
  [[ "$output" == *"reporter:"* ]]
  [[ "$output" == *"no-new-privileges:true"* ]]
  [[ "$output" == *"cap_drop:"* ]]
  [[ "$output" == *"read_only: true"* ]]
  [[ "$output" == *"target: /etc/rspamd/plugins.d"* ]]
}

@test "admission, collector, and results API have bounded private wiring" {
  run docker compose --env-file config/versions.env config --format json
  [ "$status" -eq 0 ]
  config=$output

  run python3 -c 'import json, sys; services=json.loads(sys.argv[1])["services"]; admission=services["admission"]; collector=services["collector"]; api=services["results-api"]; assert set(admission["networks"]) == {"mail"}; assert "--admission-stamp-key" in collector["command"]; assert "--subject-domain-allowlist" in collector["command"]; assert set(api["networks"]) == {"analytics"}; assert "ports" not in api; assert any(volume["target"] == "/artifacts" and volume["read_only"] for volume in api["volumes"]); assert "results-api-token" in api["healthcheck"]["test"][-1]' "$config"
  [ "$status" -eq 0 ]
}

@test "dashboard profile confines browser and control services to their least-privilege networks" {
  run docker compose --env-file config/versions.env --profile dashboard config --format json
  [ "$status" -eq 0 ]
  config=$output

  run python3 -c 'import json, sys; s=json.loads(sys.argv[1])["services"]; analytics=s["analytics-projector"]; intel=s["intel-projector"]; dashboard=s["dashboard"]; control=s["control-api"]; assert analytics["network_mode"] == "none" and "networks" not in analytics; assert intel["network_mode"] == "none" and "networks" not in intel; assert set(dashboard["networks"]) == {"analytics", "management"}; assert set(control["networks"]) == {"management"}; assert dashboard["ports"][0]["host_ip"] == "127.0.0.1"; assert dashboard["ports"][0]["published"] == "3000"; assert "--host=0.0.0.0" in dashboard["command"]; assert "--listen=:8081" in control["command"]; assert all(v.get("read_only") for v in dashboard["volumes"]); assert {v["target"] for v in dashboard["volumes"]} == {"/runtime/secrets/results-api-token", "/runtime/secrets/control-api-token", "/runtime/secrets/dashboard-session-hmac-key"}; assert "/state" not in {v["target"] for v in dashboard["volumes"]}; assert "/artifacts" not in {v["target"] for v in dashboard["volumes"]}; assert "/dev/tcp" not in " ".join(dashboard["healthcheck"]["test"] + control["healthcheck"]["test"]); assert not set(dashboard["networks"]) & {"public", "mail", "analyzer", "scanner", "report"}; assert not set(control["networks"]) & {"public", "mail", "analyzer", "scanner", "report"}' "$config"
  [ "$status" -eq 0 ]
}

@test "init bootstraps a validated selected-subject policy from deployment configuration" {
  run python3 -c 'from pathlib import Path; compose=Path("compose.yaml").read_text(); init=Path("containers/init/entrypoint.sh").read_text(); env=Path(".env.example").read_text(); assert "MAILPROOF_SUBJECT_SENDER_DOMAIN_ALLOWLIST" in compose; assert "subject-sender-domain-allowlist" in init; assert "MAILPROOF_SUBJECT_SENDER_DOMAIN_ALLOWLIST=lugano.ch" in env; assert "chmod 0600" in init'
  [ "$status" -eq 0 ]
}

@test "init provisions separated dashboard and control keys with owner-only modes" {
  run python3 -c 'from pathlib import Path; text=Path("containers/init/entrypoint.sh").read_text(); names=("control-api-token", "control-confirmation-hmac-key", "dashboard-session-hmac-key", "indicator-hmac-key", "report-verification-key.pem"); assert all(name in text for name in names); assert "openssl pkey" in text; assert "chmod 0711" in text; assert "chmod 0700" in text; assert "chmod 0600" in text; assert "chown -R 1000:1000 -- \"${runtime}/secrets\" \"${runtime}/config\"" in text'
  [ "$status" -eq 0 ]
}

@test "ClamAV has its documented memory floor" {
  run docker compose --env-file config/versions.env config --format json
  [ "$status" -eq 0 ]
  config=$output

  run python3 -c 'import json, sys; assert int(json.loads(sys.argv[1])["services"]["clamav"]["deploy"]["resources"]["limits"]["memory"]) >= 3 * 1024**3' "$config"
  [ "$status" -eq 0 ]
}

@test "daemon healthchecks use tools present in their images" {
  run docker compose --env-file config/versions.env config --format json
  [ "$status" -eq 0 ]
  config=$output

  run python3 -c 'import json, sys; services=json.loads(sys.argv[1])["services"]; assert "/dev/tcp/127.0.0.1/25" in services["postfix"]["healthcheck"]["test"][-1]; assert "/dev/tcp/127.0.0.1/53" in services["unbound"]["healthcheck"]["test"][-1]; assert "/dev/tcp/127.0.0.1/3310" in services["clamav"]["healthcheck"]["test"][-1]; assert "nPING" in services["clamav"]["healthcheck"]["test"][-1]' "$config"
  [ "$status" -eq 0 ]
}

@test "Unbound has a pinned DNSSEC trust anchor and bootstrap capabilities" {
  run docker compose --env-file config/versions.env config --format json
  [ "$status" -eq 0 ]
  config=$output

  run python3 -c 'import json, sys; service=json.loads(sys.argv[1])["services"]["unbound"]; assert "dns-root-data=2025080400~deb13u1" in service["build"]["args"]["PACKAGES"]; assert set(service["cap_add"]) == {"CHOWN", "NET_BIND_SERVICE", "SETGID", "SETUID"}' "$config"
  [ "$status" -eq 0 ]
}

@test "CI stops the singleton collector before a one-shot sweep" {
  run python3 -c 'from pathlib import Path; workflow=Path(".github/workflows/quality.yml").read_text(); assert workflow.index("docker compose stop collector") < workflow.index("docker compose run --rm --no-deps collector collect --once"); assert "docker compose run --rm --no-deps worker worker --drain" in workflow; assert "docker compose ps -q results-api" in workflow; assert ".State.Health.Status" in workflow'
  [ "$status" -eq 0 ]
}

@test "application images receive the configured release version" {
  run env MAILPROOF_VERSION=v0.1.0 docker compose --env-file config/versions.env config --format json
  [ "$status" -eq 0 ]
  config=$output

  run python3 -c 'import json, sys; service=json.loads(sys.argv[1])["services"]["collector"]; assert service["image"] == "ghcr.io/luganoplanb/mailproof:v0.1.0-app"; assert service["build"]["args"]["MAILPROOF_VERSION"] == "v0.1.0"; assert service["build"]["labels"]["org.opencontainers.image.version"] == "v0.1.0"' "$config"
  [ "$status" -eq 0 ]
}

@test "source Compose builds while the release definition is image-only" {
  run env MAILPROOF_VERSION=v9.8.7 docker compose --env-file config/versions.env -f compose.yaml config --format json
  [ "$status" -eq 0 ]
  config=$output

  run python3 -c 'import json, sys; services=json.loads(sys.argv[1])["services"]; assert all("build" not in service for service in services.values()); assert services["collector"]["image"] == "ghcr.io/luganoplanb/mailproof:v9.8.7-app"' "$config"
  [ "$status" -eq 0 ]

  run python3 -c 'from pathlib import Path; dockerfiles={str(p) for p in Path("containers").glob("*/Dockerfile")}; override=Path("compose.override.yaml").read_text(); assert dockerfiles; assert all(path in override for path in dockerfiles); assert all((name+":") in override for name in ("results-api", "analytics-projector", "intel-projector", "dashboard", "control-api")); assert "build: *mailproof-build" in override'
  [ "$status" -eq 0 ]
}

@test "release workflow publishes public amd64 images before the release" {
  run python3 -c 'from pathlib import Path; workflow=Path(".github/workflows/release.yml").read_text(); assert "ietf-tools/semver-action@c90370b2958652d71c06a3484129a4d423a6d8a8" in workflow; assert "RELEASE_VERSION=v0.1.0" in workflow; assert "MAILPROOF_VERSION:-dev" in workflow; assert "MAILPROOF_IMAGE:-ghcr.io/luganoplanb/mailproof" in workflow; assert "workflow_run.head_sha == github.sha" in workflow; assert "scripts/release-eligible.sh" in workflow; assert "packages: write" in workflow; assert "DOCKER_DEFAULT_PLATFORM: linux/amd64" in workflow; assert "docker compose --env-file config/versions.env --profile smoke push" in workflow; assert "visibility=$(gh api" in workflow; assert "docker logout ghcr.io" in workflow; assert "mailproof@sha256:" in workflow; assert workflow.index("Smoke-test the published release images") < workflow.index("Create the GitHub release"); assert "sha256sum \"$(basename" in workflow; assert "gh release create" in workflow'
  [ "$status" -eq 0 ]
}

@test "quality skips code jobs for documentation-only changes" {
  run python3 -c 'from pathlib import Path; workflow=Path(".github/workflows/quality.yml").read_text(); assert "Classify software changes" in workflow; assert "scripts/release-eligible.sh" in workflow; assert "if: needs.classify.outputs.software == '\''true'\''" in workflow; assert "needs: [classify, go-and-shell]" in workflow; assert "--profile smoke build --pull" in workflow'
  [ "$status" -eq 0 ]
}

@test "remote quality smoke includes the dashboard profile and isolated browser checks" {
  run python3 -c 'from pathlib import Path; workflow=Path(".github/workflows/quality.yml").read_text(); assert "--profile smoke --profile dashboard build --pull" in workflow; assert "--profile dashboard up -d --wait" in workflow; assert "npm --prefix tests/browser ci" in workflow; assert "DASHBOARD_URL=http://localhost:3000 npm --prefix tests/browser test -- compose.spec.js" in workflow; assert "npm --prefix tests/browser test -- dashboard.spec.js" in workflow; spec=Path("tests/browser/dashboard.spec.js").read_text(); assert "BROWSER_EVIDENCE_DIR" in spec and "test-results/evidence" in spec; compose=Path("tests/browser/compose.spec.js").read_text(); assert "unexpected" in compose and "dashboardURL" in compose'
  [ "$status" -eq 0 ]
}

@test "dashboard operations handoff documents private access, recovery, and passkeys" {
  run python3 -c 'from pathlib import Path; text=Path("docs/runbooks/dashboard.md").read_text(); required=("127.0.0.1:3000:3000", "SSH tunnel", "--public-origin", "unauthenticated", "--dry-run", "indicator-HMAC", "X-Forwarded-*", "WebAuthn RP ID"); assert all(item in text for item in required); backup=Path("docs/runbooks/backup-restore.md").read_text(); assert all(item in backup for item in ("dashboard-session-hmac-key", "control-api-token", "indicator-hmac-key")); readme=Path("README.md").read_text(); assert "dashboard operations runbook" in readme'
  [ "$status" -eq 0 ]
}

@test "backup and restore runbooks expose dry-run-first commands" {
  run scripts/backup.sh --dry-run --output /tmp/mailproof-backup
  [ "$status" -eq 0 ]
  [[ "$output" == *"would create a SQLite online backup"* ]]

  backup_dir="$(mktemp -d)"
  touch "${backup_dir}/SHA256SUMS"
  run scripts/restore.sh --dry-run --input "${backup_dir}"
  rm -rf -- "${backup_dir}"
  [ "$status" -eq 0 ]
  [[ "$output" == *"would verify and restore"* ]]
}
