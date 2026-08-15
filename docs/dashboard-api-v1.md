# Dashboard API and browser contract v1

Dashboard is a private HTML/HTMX client of internal results/control APIs; it
does not expose SQLite, raw artifacts, mail, headers, addresses, peer IPs,
tokens, or keys. These are internal, bearer-authenticated read contracts—not
browser endpoints—and unknown JSON fields are rejected by the dashboard client.

## Common read-model envelope and request bounds

Every model has `schema_version`, `generated_at`, `data_through`, and `as_of`
as RFC3339 UTC timestamps. `generated_at` is projection construction time,
`data_through` is the latest included durable event time (or `null` for an
observation-only panel), and `as_of` is the source observation time. Every
response has `freshness:{state:"fresh"|"stale"|"partial"|"unavailable",
reason_code,stale_after_seconds}`. A typed safe value is
`{value:number|string|boolean|null,unit,display_status:"known"|"unknown"|"not_applicable"}`;
it never contains an address, raw indicator, message/header text, peer IP,
credential, artifact body, or key.

The dashboard client requests the following internal routes. `from`/`to` are
UTC half-open RFC3339 range bounds (maximum 366 days); `interval` is
`minute|hour|day`; `limit` defaults to 50 and is at most 100; ranked and series
arrays are at most 50 and 6 respectively. Filter values are normalized,
allow-listed status/type/domain values (maximum 100); unknown filter names or
values fail `invalid_filter`. A cursor is integrity-protected and binds route,
filters, sort, and page size.

| Internal client request | Model |
| --- | --- |
| `GET /v1/dashboard/overview?from=&to=` | overview |
| `GET /v1/dashboard/funnel?from=&to=` | funnel |
| `GET /v1/dashboard/series?metric=&from=&to=&interval=` | time series |
| `GET /v1/dashboard/operations` | operations |
| `GET /v1/dashboard/campaigns?from=&to=&status=&cursor=&limit=` | campaigns page |
| `GET /v1/dashboard/campaigns/{campaign_id}?members_cursor=&members_limit=` | campaign detail |
| `GET /v1/control/policy?cursor=&limit=&type=&status=&from=&to=` | effective policy page |
| `GET /v1/control/audit?cursor=&limit=&type=&status=&from=&to=` | audit page |

## Canonical JSON shapes

Overview is `mailproof.dashboard.overview/v1`; `cards` contains exactly the
six named scalar kinds `recipient_hits`, `admitted`, `completed`, `rejected`,
`in_flight`, and `p95_latency_ms`; distributions are bounded ranked
`{key,label,count}` values, campaigns are safe summaries, and alerts contain
`{code,severity,label,as_of}` only.

```json
{"schema_version":"mailproof.dashboard.overview/v1","generated_at":"...Z","data_through":"...Z","as_of":"...Z","freshness":{"state":"fresh","reason_code":null,"stale_after_seconds":300},"range":{"from":"...Z","to":"...Z"},"cards":[{"kind":"recipient_hits","safe_value":{"value":12,"unit":"count","display_status":"known"}}],"distributions":{"verdicts":[{"key":"FAILED","label":"Failed","count":2}],"rejections":[]},"active_campaigns":[{"campaign_id":"opaque","status":"active","hit_count":2}],"alerts":[]}
```

Funnel is `mailproof.dashboard.funnel/v1`. Stages are ordered and fixed:
`recipient_hit`, `policy_accepted`, `admitted`, `run_started`, `run_completed`,
and `report_delivered`; each has `{stage,count,entity_kind,route_filter}`. It
also returns `reconciliation:{equation,holds,explanation}` so a partial/stale
funnel never silently claims a complete total.

```json
{"schema_version":"mailproof.dashboard.funnel/v1","generated_at":"...Z","data_through":"...Z","as_of":"...Z","freshness":{"state":"partial","reason_code":"late_data","stale_after_seconds":300},"range":{"from":"...Z","to":"...Z"},"stages":[{"stage":"recipient_hit","count":12,"entity_kind":"recipient_evaluation","route_filter":{"stage":"recipient_hit"}}],"reconciliation":{"equation":"recipient_hits = sum(policy_outcomes)","holds":true,"explanation":null}}
```

Time series is `mailproof.dashboard.series/v1`: one requested metric, its
interval/range, and at most six named series. Each series has bounded UTC
`points:[{start,end,safe_value}]`; absent intervals are explicit
`display_status:"unknown"`, not fabricated zeroes.

```json
{"schema_version":"mailproof.dashboard.series/v1","generated_at":"...Z","data_through":"...Z","as_of":"...Z","freshness":{"state":"fresh","reason_code":null,"stale_after_seconds":300},"metric":"completed","interval":"hour","range":{"from":"...Z","to":"...Z"},"series":[{"key":"all","label":"Completed","points":[{"start":"...Z","end":"...Z","safe_value":{"value":3,"unit":"count","display_status":"known"}}]}]}
```

Operations is `mailproof.dashboard.operations/v1` with ordered sections
`queue_worker`, `analyzers`, `signing_report_delivery`, and `freshness`. A
section is `{kind,title,observation_at,data_through:null,values,alerts}` where
`values` are typed safe values and analyzer items are
`{analyzer,status,latency_ms,observation_at}`. Current-state observations are
marked observational and may be unavailable; no host CPU/RAM or Docker metric
is permitted.

Campaigns page is `mailproof.dashboard.campaigns/v1` with the common envelope,
request `filters`, and `{items,next_cursor}`. An item is
`{campaign_id,algorithm_version,status,first_seen,last_seen,hit_count,
affected_submitter_count,risk_distribution,verdict_distribution}`. IDs are
opaque; distributions are bounded, privacy-reduced, and exact counts only.
Campaign detail is `mailproof.dashboard.campaign/v1`, with the same common
envelope plus `campaign` (the item fields), ordered `grouping_reasons`,
`activity` series, `safe_indicators`, distributions, and a separately bounded
`members:{items,next_cursor}`. A member is only
`{run_id,completed_at,verdict,category,risk,grouping_reason_ids}`; it supplies
the opaque investigation destination, never a raw member message.

Effective policy is `mailproof.dashboard.policy/v1` and returns
`{effective_version,filters,items,next_cursor}`; each typed item is
`{policy_id,type,status,scope,expiry,version,updated_at}`. Audit is
`mailproof.dashboard.audit/v1` and returns `{filters,items,next_cursor}` in
strict reverse chronological order; an item is
`{command_id,occurred_at,command_type,result_code,policy_version,before_digest,
after_digest,actor_kind:"unauthenticated-local",session_correlation_id}`.
Both use the control API's cursor and 50/100 bounds; policy details and audit
detail are retrieved by their opaque IDs under the same bounded filter context.

## Forbidden-field inventory

No dashboard model, client request, fragment, error, cache entry, or wireframe
may include raw mail/body/attachment, raw headers, SMTP envelope, email address,
peer IP, capability, bearer token, session/CSRF/confirmation token, signing or
MAC key, SQLite query/row, artifact path/content, or un-reduced campaign
indicator. Internal errors are generic codes; browser requests cannot select an
internal URL, route, projection field, or authorization credential.

## Browser routes

`GET /healthz`, `GET /readyz`, `GET /`, `GET /operations`, `GET /campaigns`,
`GET /campaigns/{campaign_id}`, `GET /investigations`,
`GET /investigations/results/{run_id}`, `GET /investigations/decisions/{decision_id}`,
`GET /policy`, `GET /audit`, `GET /audit/{command_id}`, `POST /policy/preview`,
and `POST /policy/confirm` are canonical. Health reports process status only.
Readiness makes bounded authenticated calls to every configured upstream and
returns only generic status. GET pages return a full page or that route's
fragment for `HX-Request: true`; POST routes return validation/preview/success
fragments for HTMX and 303 PRG for ordinary forms.

`mailproof dashboard` requires `--results-url`, `--results-token-file`, and
`--session-key-file`; `--control-url` and `--control-token-file` are an optional
pair. Neither means explicit read-only mode and Policy/Audit routes/navigation
are omitted; exactly one is startup failure. Internal URLs parse once at start
as absolute HTTP(S) origins with no credentials/path/query/fragment and are
never browser input. Both internal clients use 1s connect, 2s response-header,
3s total deadlines, 2MiB response limits, strict JSON decoding, no redirects,
and no automatic retry. Browser/control servers use the limits in ADR 0005.

Required negative cases: malformed CIDR/domain; maximum filters/ranges;
unsupported command; stale version; expired preview; replayed confirmation;
internal outage; and every forbidden sensitive field. These contracts preserve
domain commands so a future authenticated actor replaces only the actor binding,
not policy semantics.
