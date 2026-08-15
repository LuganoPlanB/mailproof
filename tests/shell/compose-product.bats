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
