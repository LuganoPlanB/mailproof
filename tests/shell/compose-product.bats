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
  run python3 -c 'from pathlib import Path; workflow=Path(".github/workflows/quality.yml").read_text(); assert workflow.index("docker compose stop collector") < workflow.index("docker compose run --rm --no-deps collector collect --once"); assert "docker compose run --rm --no-deps worker worker --drain" in workflow'
  [ "$status" -eq 0 ]
}

@test "application images receive the configured release version" {
  run env MAILPROOF_VERSION=v0.1.0 docker compose --env-file config/versions.env config --format json
  [ "$status" -eq 0 ]
  config=$output

  run python3 -c 'import json, sys; service=json.loads(sys.argv[1])["services"]["collector"]; assert service["build"]["args"]["MAILPROOF_VERSION"] == "v0.1.0"; assert service["build"]["labels"]["org.opencontainers.image.version"] == "v0.1.0"' "$config"
  [ "$status" -eq 0 ]
}

@test "release workflow bootstraps and stamps v0.1.0" {
  run python3 -c 'from pathlib import Path; workflow=Path(".github/workflows/release.yml").read_text(); assert "ietf-tools/semver-action@c90370b2958652d71c06a3484129a4d423a6d8a8" in workflow; assert "RELEASE_VERSION=v0.1.0" in workflow; assert "MAILPROOF_VERSION:-dev" in workflow; assert "workflow_run.head_sha == github.sha" in workflow; assert "scripts/release-eligible.sh" in workflow; assert "sha256sum \"$(basename" in workflow; assert "gh release create" in workflow'
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
