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
