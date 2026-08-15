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
  [[ "$output" == *"mailproof.lua:/etc/rspamd/plugins.d/mailproof.lua:ro"* ]]
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
