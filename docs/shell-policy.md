# Shell and mblaze policy

Shell is orchestration glue, never a parser for hostile mail, DNS, URLs,
archives, or cryptographic data. Scripts use Bash strict mode, quote values,
pass paths as arguments, and use `mktemp -d` with cleanup traps. State-changing
operations expose `--dry-run` and require an explicit `--confirm`; no script
uses `eval` or sources mail-derived data. Traversal is NUL-safe where needed.

`mblaze` is optional read-only operator inspection tooling. Its display output
is never parsed into security evidence or policy input.
