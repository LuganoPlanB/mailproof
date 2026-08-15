#!/usr/bin/env bats

@test "init dry-run accepts a report recipient containing shell metacharacters" {
  run bash scripts/init.sh --dry-run --report-recipient 'name space;$(not-executed)@example.org'
  [ "$status" -eq 0 ]
  [[ "$output" == *'would initialize runtime directories'* ]]
}

@test "smoke requires an explicit mode" {
  run bash scripts/smoke.sh
  [ "$status" -eq 2 ]
}

@test "smoke recognizes healthy services without parsing Compose JSON" {
  docker() {
    if [[ $1 == compose && $2 == ps && $3 == -q ]]; then
      printf '%s-id\n' "$4"
    elif [[ $1 == inspect && $2 == --format ]]; then
      printf '%s\n' healthy
    elif [[ $1 == compose && $2 == --profile && $3 == smoke ]]; then
      return 0
    else
      return 1
    fi
  }
  export -f docker

  run bash scripts/smoke.sh --confirm

  [ "$status" -eq 0 ]
  [[ "$output" == *"fixture accepted with Message-ID"* ]]
}
