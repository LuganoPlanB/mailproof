#!/usr/bin/env bats

setup() {
  repo=$(mktemp -d)
  git -C "$repo" init --quiet
  git -C "$repo" config user.email test@mailproof.invalid
  git -C "$repo" config user.name Mailproof-Test
  mkdir -p "$repo/docs" "$repo/internal"
  printf '%s\n' initial >"$repo/README.md"
  printf '%s\n' initial >"$repo/docs/index.md"
  printf '%s\n' initial >"$repo/internal/app.go"
  git -C "$repo" add .
  git -C "$repo" commit --quiet -m 'feat: initial'
  base=$(git -C "$repo" rev-parse HEAD)
  classifier=$BATS_TEST_DIRNAME/../../scripts/release-eligible.sh
}

teardown() {
  rm -rf -- "$repo"
}

@test "README-only changes do not release" {
  printf '%s\n' updated >"$repo/README.md"
  git -C "$repo" commit --quiet -am 'chore: improve introduction'

  run bash -c 'cd "$1" && "$2" "$3" HEAD' _ "$repo" "$classifier" "$base"

  [ "$status" -eq 0 ]
  [ "$output" = false ]
}

@test "docs directory changes do not release" {
  printf '%s\n' updated >"$repo/docs/index.md"
  git -C "$repo" commit --quiet -am 'chore: refresh website copy'

  run bash -c 'cd "$1" && "$2" "$3" HEAD' _ "$repo" "$classifier" "$base"

  [ "$status" -eq 0 ]
  [ "$output" = false ]
}

@test "docs conventional commits do not release code changes" {
  printf '%s\n' updated >"$repo/internal/app.go"
  git -C "$repo" commit --quiet -am 'docs: explain implementation'

  run bash -c 'cd "$1" && "$2" "$3" HEAD' _ "$repo" "$classifier" "$base"

  [ "$status" -eq 0 ]
  [ "$output" = false ]
}

@test "scoped docs commits do not release code changes" {
  printf '%s\n' updated >"$repo/internal/app.go"
  git -C "$repo" commit --quiet -am 'docs(readme): explain implementation'

  run bash -c 'cd "$1" && "$2" "$3" HEAD' _ "$repo" "$classifier" "$base"

  [ "$status" -eq 0 ]
  [ "$output" = false ]
}

@test "non-documentation code changes release" {
  printf '%s\n' updated >"$repo/internal/app.go"
  git -C "$repo" commit --quiet -am 'fix: correct implementation'

  run bash -c 'cd "$1" && "$2" "$3" HEAD' _ "$repo" "$classifier" "$base"

  [ "$status" -eq 0 ]
  [ "$output" = true ]
}

@test "mixed code and documentation changes release" {
  printf '%s\n' updated >"$repo/README.md"
  printf '%s\n' updated >"$repo/internal/app.go"
  git -C "$repo" commit --quiet -am 'feat: update behavior and guide'

  run bash -c 'cd "$1" && "$2" "$3" HEAD' _ "$repo" "$classifier" "$base"

  [ "$status" -eq 0 ]
  [ "$output" = true ]
}
