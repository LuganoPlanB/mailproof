# Dashboard information architecture v1

The dashboard uses safe indicators and opaque identifiers only. Every time is
UTC and labeled `UTC`; color augments text/status labels and never carries a
meaning alone. Shared filters are UTC `[from,to)`, bounded status/type/domain,
and cursor; click-through preserves them. Loading/error/stale states appear in
the affected panel below its title (stale includes `as of UTC`), while empty
states explain the active filter and offer a clear-filter link.

## Navigation and page order

| Page | Ordered content and destination |
| --- | --- |
| Overview `/` | Six cards: hits, admitted, completed, rejected, in-flight, p95 latency; traffic/latency lines and staged admission funnel; verdict/rejection horizontal bars; active campaigns; alerts. Cards/funnel stages link to Investigations with the matching filter. |
| Operations `/operations` | Queue/worker, analyzers, signing/report delivery, freshness. Each links to the corresponding filtered Investigation or Audit row. |
| Campaigns `/campaigns` | Ranked campaign table to detail. |
| Campaign detail `/campaigns/{campaign_id}` | Identity/status, grouping reasons, activity, safe indicators, distributions, paginated members. Members link to result detail. |
| Investigations `/investigations` | Filter → table → result/decision detail journey. |
| Policy `/policy` | Effective version, submitters/quotas, allowlist, blocks, command preview. |
| Audit `/audit` | Reverse-chronological command table to command detail. |

Panel titles include concise help text: “event time, UTC”, “current observation,
not retained”, “safe indicators only”, or “requires confirmation” as relevant.
Lines are exclusively time series, horizontal bars ranked distributions, and a
labeled staged bar is exclusively the funnel. Cards are headline scalars;
identifiers/actions always use tables. No pie/donut, 3D, animation, color-only
state, or more than six simultaneous series is permitted.

Desktop is two columns: main narrative left, supporting panels right. Narrow is
one column in the exact listed reading order; at 200% it remains a single
column, wrapping labels and using horizontal table overflow only after the
identifier/action columns remain visible.

## Primary-field mapping

| Accepted metric/control | One primary component |
| --- | --- |
| hits, admitted, completed, rejected, in-flight, p95 | Overview six cards |
| traffic, latency, funnel, verdict/rejection distributions | Overview series/funnel/bars |
| campaigns and campaign fields | Campaigns table / Campaign detail sections |
| queue, workers, analyzers, signing/report, freshness, headroom | Operations ordered panels |
| results/decisions and safe indicators | Investigations table/detail |
| effective policy, quotas, allowlist, blocks, preview/confirm | Policy ordered panels |
| audit records | Audit reverse-chronological table/detail |

Wireframes are deterministic SVG documents in `docs/dashboard/wireframes/`.
They encode named components and reading order rather than live values. The
1440×900 overview reserves the active-campaign row within the viewport.
