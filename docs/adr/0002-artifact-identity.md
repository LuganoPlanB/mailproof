# ADR 0002: Artifact identity and immutable layout

## Status

Accepted for the v1 Compose spine.

## Decision

Content, delivery, subject selection, and analysis run have separate identities.

```text
artifacts/messages/<sha256>.eml
artifacts/deliveries/<delivery-id>/ingress.json
artifacts/deliveries/<delivery-id>/subjects.json
artifacts/runs/<run-id>/analysis/{responses/,evidence.json,verdict.json}
artifacts/runs/<run-id>/report/{manifest.json,manifest.sig,...}
```

`<sha256>` identifies one distinct byte sequence and is stored once.
`ingress.json` binds one delivery to its outer digest and locally observed SMTP
context. `subjects.json` binds the selected subject digest, part path, and
`auth_context_scope` (`local_ingress` or `detached`), or records
`selection_error=multiple_top_level_rfc822` with no selected digest.

Each worker publishes immutable analysis and each reporter publishes immutable
reports. A selection-error run runs no subject analyzers and deterministically
yields INDETERMINATE. SQLite indexes lifecycle only; immutable files are the
audit record.

`delivery-id` and `run-id` are independently generated using `crypto/rand` as
128 random bits encoded in 32 lowercase hexadecimal characters. A database
uniqueness constraint detects collisions and generation retries. Duplicate
bytes never overwrite a delivery or run. A replay always creates a new run.

## Resolution examples

Two deliveries with the same outer digest have distinct delivery IDs and may
have different peers. One delivery can have zero, one, or two attached-message
selection outcomes. Multiple policy/analyzer versions produce different run IDs
for the same delivery. Any ID resolves through its binding to all relevant
digests without conflating those entities.
