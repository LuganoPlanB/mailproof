# Dashboard metrics v1

This dictionary is the published language of the analytics bounded context.
Analytics is a rebuildable projection; immutable artifacts, decisions, signed
reports, and policy/audit records remain authoritative. Times and windows are
UTC half-open intervals `[from,to)`.

## Sources and retention

Durable producers append immutable `analytics_events` rows with an event ID and
idempotency key; their projector creates `analytics_minute`, `analytics_hour`,
and `analytics_day` buckets. Proposed producers are `policy-service`,
`admission`, `collector`, `queue`, `worker`, and `reporter`. Authoritative
foreign keys refer to `deliveries`, `runs`, `decisions`, `reports`, and policy
audit rows; duplicate message bytes stay distinct because each delivery ID is
distinct. Observations (`analytics_observations`) are disposable current state,
not evidence, and are not retained.

Raw events/minute buckets retain 31 days, hourly buckets 366 days, and daily
buckets 5 years (all configurable defaults). Retention never deletes results,
decisions, campaigns, policy, or audit authority. A bucket is stale when its
projector watermark is more than 5 minutes behind its `as_of`; an analyzer
observation is stale after twice its collection interval (default 2 minutes).

| Metric (unit) | Durable source / increment | Dimensions; timestamp; retention/rebuild |
| --- | --- | --- |
| Recipient hits (count) | `policy_recipient_hit` from policy-service when a verification recipient is evaluated | outcome; event time; durable, 31d/366d/5y, rebuildable |
| Policy outcomes (count) | `policy_outcome` after policy verdict | outcome/reason; event time; durable, rebuildable |
| Admitted/deferred/rejected (count) | `admission_decision` when durable decision row is committed | decision/stage/reason/policy version; decision time; durable, rebuildable |
| Subject-preflight rejections (count) | `admission_decision` at `subject_preflight` commit | reason/policy version; decision time; durable, rebuildable |
| Runs started/completed (count) | `run_started` / `run_completed` on run state commit | outcome/verdict; run time; durable, rebuildable |
| Verdicts (count) | `run_completed` with final verdict | verdict/category; completion time; durable, rebuildable |
| Report/rejection delivery state (count) | `report_delivery_state` / `rejection_delivery_state` on state commit | state/reason; event time; durable, rebuildable |
| Signing backlog (count) | current `signing_backlog` observation | state; observation time; observational, not retained |
| Queue depth/age (count/seconds) | current `queue_pressure` observation | queue; observation time; observational, not retained |
| Worker throughput (runs/minute) | `run_completed` count divided by UTC window seconds | worker class; completion time; durable, rebuildable |
| Analyzer availability/latency (ratio/ms) | `analyzer_observation` at probe/result boundary | analyzer/status; observation time; observational, not retained |
| Unique submitters (count) | distinct `submitter_id` in `admission_decision=admitted` | policy version; decision time; durable, rebuildable |
| Selected-subject domains (count) | `admission_decision` after trusted selection | exact selected domain; decision time; durable, rebuildable |
| Capacity headroom (slots) | `capacity_observation` = configured concurrency minus in-flight | worker class; observation time; observational, not retained |

Dimensions have bounded vocabularies; domain is an exact normalized selected
subject domain, never a raw address. Unknown is literal `unknown`; absent is
`null`; neither is silently merged. Dashboard queries cap range to 366 days,
ranked values to 50, series to six, and filter cardinality to 100 values.

Latency p95 is calculated from a bounded exponential histogram, not retained
per-message samples: duration counts are folded into millisecond buckets
`[1,2), [2,4), …, [65536,131072)` with the last bucket capped at 24 hours.
The reported percentile is the lower bound of the first bucket whose cumulative
count reaches 95%; absent observations are `unknown` rather than zero.

## Funnel and reconciliation

The clickable funnel is `recipient_hit → policy_outcome=accepted →
admission_decision=admitted → run_started → run_completed →
report_delivery_state=delivered`; each stage is a count of distinct durable
entity IDs, respectively recipient evaluation, delivery, delivery, run, run,
and report. Links retain the same UTC window and add the stage filter.

For any window: `recipient_hits = Σ policy outcomes`; `admitted + deferred +
rejected = Σ admission decisions`; `subject_preflight_rejections = count(stage
= subject_preflight)`; `completed ≤ started + runs_already_in_flight_at_from`;
and `delivered + pending + failed = report state changes whose current state was
observed in the window`. A retry adds state events but does not add a delivery,
decision, or run; a replay has a new run ID; late notarization joins its original
event-time bucket, and recomputes previously published buckets. A run for a
detached `message/rfc822` child never receives wrapper SPF/envelope dimensions.

Event-time drives durable buckets; observation-time drives live panels. Empty
is zero observed events, unknown is an unavailable/unspecified value, and a
late event is marked `late=true` until its affected buckets are rebuilt.

## Campaigns

A campaign candidate is a completed signed run with deterministic `FAILED`
verdict and an allow-listed verified-evidence category: phishing,
impersonation, malicious-link, or malicious-attachment. Clean, indeterminate,
and unavailable runs remain searchable but create no grouping edges.

`campaigns/v1` is a versioned deterministic connected component over
privacy-reduced indicators and accepted strong edges. It records its algorithm
version, sorted member run IDs, first/last seen, hit count, affected submitter
count, verdict/risk distribution, and each explicit grouping reason. Component
supersession is explicit; counts describe grouped observations, never an actor,
attribution probability, or shared sender identity.

## Canonical reconciliation examples

One happy delivery yields 1 at every funnel stage. A policy rejection yields
one hit/outcome and no delivery; a subject-preflight rejection yields one
delivery/decision and no run. Retried report delivery adds delivery-state events
only. Identical bytes delivered twice yield two delivery IDs. An unavailable
analyzer produces availability `unknown` and an indeterminate/unavailable run,
never clean. Queue backlog and capacity use observations only. At midnight UTC,
an event at `00:00:00Z` belongs to the new bucket; the prior bucket excludes it.
