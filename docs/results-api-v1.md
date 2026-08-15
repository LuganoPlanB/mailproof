# Results API v1 contract

This is ADR 0004's published internal language. Omitted values are unavailable,
not clean. Timestamps are RFC 3339 UTC; IDs are opaque lowercase hexadecimal.

## Resource schemas

```json
{"schema_version":"mailproof.result/v1","run_id":"a1b2c3d4e5f60708a1b2c3d4e5f60708","delivery_id":"b1b2c3d4e5f60708a1b2c3d4e5f60708","submitter_id":"c1b2c3d4e5f60708a1b2c3d4e5f60708","occurred_at":"2026-08-15T14:37:15Z","outcome":"COMPLETE","selected_subject_domain":"lugano.ch","verdict":"INDETERMINATE","policy_version":"v2","artifact":{"status":"signed","id":"sha256:..."}}
```

```json
{"schema_version":"mailproof.rejection-decision/v1","decision_id":"d1b2c3d4e5f60708a1b2c3d4e5f60708","submitter_id":"c1b2c3d4e5f60708a1b2c3d4e5f60708","occurred_at":"2026-08-15T14:37:15Z","stage":"subject_preflight","reason_code":"subject.sender_not_allowed","policy_version":"v2","notarization":{"status":"queued"}}
```

`notarization.status` is `queued`, `signed`, `failed`, or `unavailable`;
only `signed` claims a signed artifact. A projection never contains email
addresses, peer IPs, headers, bodies, capabilities, challenges, keys, or report
recipients.

## Collections, errors, and aggregates

`GET /v1/results` and `/v1/decisions` use:

```json
{"schema_version":"mailproof.page/v1","items":[],"next_cursor":"opaque-or-null"}
```

`limit` defaults to 50, accepts 1--100, and `cursor` is opaque. Exact bounded
filters are run/decision ID, submitter ID, outcome, rejection stage/reason,
selected-subject domain, verdict, policy version, and UTC range. Ordering is
`(occurred_at, id)`; the cursor freezes that ordering and its filters so new
rows never reshuffle an in-progress traversal. Singular endpoints return their
resource directly. Errors are generic:

```json
{"schema_version":"mailproof.error/v1","code":"invalid_filter","message":"request cannot be processed"}
```

Permitted error codes are `unauthorized`, `not_found`, `invalid_filter`,
`invalid_cursor`, `range_too_large`, `page_too_large`, and
`temporarily_unavailable`. `/healthz` returns
`{"schema_version":"mailproof.health/v1","status":"ok"}`.

`GET /v1/analytics/summary` requires `from`, `to`, and `interval=hour|day`.
Maximum ranges are 31 UTC days for hours and 366 UTC days for days. It returns
only counts grouped by UTC bucket, `outcome`, `verdict`, `rejection_stage`,
and `reason_code`; absent dimensions are null and never inferred.

```json
{"schema_version":"mailproof.analytics-summary/v1","interval":"day","from":"2026-08-01T00:00:00Z","to":"2026-08-02T00:00:00Z","buckets":[{"start":"2026-08-01T00:00:00Z","outcome":"COMPLETE","verdict":"INDETERMINATE","rejection_stage":null,"reason_code":null,"count":1}]}
```

