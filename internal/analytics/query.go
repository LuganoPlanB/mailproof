package analytics

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ErrInvalidQuery deliberately does not disclose which internal metric or
// projection was rejected. HTTP adapters map it to their generic bad request.
var ErrInvalidQuery = errors.New("invalid analytics query")

const (
	maxSeries = 12
	maxCards  = 24
)

// Query is the single bounded request shared by dashboard HTTP adapters and
// the repository. Values are closed vocabulary only; it cannot carry labels,
// mail content, addresses, or SQL fragments.
type Query struct {
	From, To  time.Time
	Interval  string
	Metric    string
	Dimension string
	Series    []string
	Cards     []string
}

type Value struct {
	Key      string    `json:"key"`
	State    string    `json:"state"`
	Count    int64     `json:"count"`
	OldestAt time.Time `json:"oldest_at,omitempty"`
}

type Bucket struct {
	Start  time.Time `json:"start"`
	Values []Value   `json:"values"`
}

type Snapshot struct {
	GeneratedAt   time.Time `json:"generated_at"`
	DataThrough   time.Time `json:"data_through,omitempty"`
	ObservedAt    time.Time `json:"observed_at,omitempty"`
	HighWatermark int64     `json:"high_watermark,omitempty"`
	ProjectionLag int64     `json:"projection_lag_seconds,omitempty"`
	P95LatencyMS  int64     `json:"p95_latency_ms,omitempty"`
	LatencyKnown  bool      `json:"latency_known"`
	Partial       bool      `json:"partial"`
	Stale         bool      `json:"stale"`
	Values        []Value   `json:"values"`
	Buckets       []Bucket  `json:"buckets"`
}

// Repository is the driven read port adapter over privacy-safe projections.
// It never reads artifacts, source mail, SMTP facts, or capabilities.
type Repository struct {
	DB  *sql.DB
	Now func() time.Time
}

func (r Repository) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

func (r Repository) context(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if r.DB == nil {
		return nil, nil, ErrInvalidQuery
	}
	child, cancel := context.WithTimeout(ctx, 2*time.Second)
	return child, cancel, nil
}

func validate(q Query) error {
	if q.From.IsZero() || q.To.IsZero() || !q.To.After(q.From) || (q.Interval != "minute" && q.Interval != "hour" && q.Interval != "day") || len(q.Series) > maxSeries || len(q.Cards) > maxCards {
		return ErrInvalidQuery
	}
	from, to := q.From.UTC(), q.To.UTC()
	if !from.Equal(from.Truncate(intervalDuration(q.Interval))) || !to.Equal(to.Truncate(intervalDuration(q.Interval))) {
		return ErrInvalidQuery
	}
	max := map[string]time.Time{
		"minute": from.AddDate(0, 0, 31),
		"hour":   from.AddDate(0, 0, 366),
		"day":    from.AddDate(5, 0, 0),
	}[q.Interval]
	if to.After(max) || !allowedMetric(q.Metric) || !allowedDimension(q.Dimension) || !uniqueAllowed(q.Series, allowedMetric) || !uniqueAllowed(q.Cards, allowedMetric) {
		return ErrInvalidQuery
	}
	return nil
}

func intervalDuration(interval string) time.Duration {
	if interval == "minute" {
		return time.Minute
	}
	if interval == "hour" {
		return time.Hour
	}
	return 24 * time.Hour
}

func allowedMetric(v string) bool {
	if v == "" {
		return true
	}
	for _, x := range []string{"admission_decision", "subject_preflight", "run_started", "run_lifecycle", "run_completed", "analyzer_observation", "report_delivery_state", "rejection_delivery_state"} {
		if v == x {
			return true
		}
	}
	return false
}
func allowedDimension(v string) bool {
	if v == "" {
		return true
	}
	for _, x := range []string{"outcome", "stage", "reason", "state", "queue", "worker", "analyzer"} {
		if v == x {
			return true
		}
	}
	return false
}
func uniqueAllowed(values []string, allowed func(string) bool) bool {
	seen := map[string]bool{}
	for _, v := range values {
		if !allowed(v) || seen[v] {
			return false
		}
		seen[v] = true
	}
	return true
}

// Series returns UTC-aligned, bounded rollup buckets. Empty buckets are
// present with zero values so callers can distinguish an observed zero from a
// missing/partial projection through Snapshot.Partial and DataThrough.
func (r Repository) Series(ctx context.Context, q Query) (Snapshot, error) {
	if err := validate(q); err != nil {
		return Snapshot{}, err
	}
	ctx, cancel, err := r.context(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	defer cancel()
	metrics := q.Series
	if len(metrics) == 0 {
		metrics = []string{q.Metric}
	}
	if len(metrics) == 0 {
		return Snapshot{}, ErrInvalidQuery
	}
	placeholders := strings.TrimRight(strings.Repeat("?,", len(metrics)), ",")
	args := []any{q.Interval, q.From.UTC().Unix(), q.To.UTC().Unix()}
	for _, m := range metrics {
		args = append(args, m)
	}
	dimension := "''"
	if q.Dimension != "" {
		// Dimension is selected only from the fixed vocabulary validated above;
		// it is never request text interpolated into SQL.
		dimension = `COALESCE(NULLIF(json_extract(dimension_key,'$.` + q.Dimension + `'),''),'unknown')`
	}
	rows, err := r.DB.QueryContext(ctx, `SELECT bucket_start,metric,`+dimension+`,SUM(event_count),MAX(source_high_watermark) FROM metric_rollups WHERE granularity=? AND bucket_start>=? AND bucket_start<? AND metric IN (`+placeholders+`) GROUP BY bucket_start,metric,`+dimension+` ORDER BY bucket_start,metric,`+dimension, args...)
	if err != nil {
		return Snapshot{}, fmt.Errorf("analytics series: %w", err)
	}
	defer rows.Close()
	byBucket := map[int64]map[string]int64{}
	var watermark, dataThrough int64
	for rows.Next() {
		var bucket, count, high int64
		var metric, value string
		if err := rows.Scan(&bucket, &metric, &value, &count, &high); err != nil {
			return Snapshot{}, err
		}
		if byBucket[bucket] == nil {
			byBucket[bucket] = map[string]int64{}
		}
		key := metric
		if q.Dimension != "" {
			key += ":" + value
		}
		byBucket[bucket][key] += count
		if high > watermark {
			watermark = high
		}
		if bucket > dataThrough {
			dataThrough = bucket
		}
	}
	if err := rows.Err(); err != nil {
		return Snapshot{}, err
	}
	s := r.snapshot(watermark, dataThrough)
	for at := q.From.UTC(); at.Before(q.To.UTC()); at = at.Add(intervalDuration(q.Interval)) {
		values := make([]Value, 0, len(metrics))
		for _, metric := range metrics {
			if q.Dimension == "" {
				values = append(values, Value{Key: metric, State: "known", Count: byBucket[at.Unix()][metric]})
				continue
			}
			for key, count := range byBucket[at.Unix()] {
				if strings.HasPrefix(key, metric+":") {
					values = append(values, Value{Key: key, State: "known", Count: count})
				}
			}
		}
		sort.Slice(values, func(i, j int) bool { return values[i].Key < values[j].Key })
		s.Buckets = append(s.Buckets, Bucket{Start: at, Values: values})
	}
	return s, nil
}

func (r Repository) snapshot(watermark, dataThrough int64) Snapshot {
	s := Snapshot{GeneratedAt: r.now(), HighWatermark: watermark}
	if watermark == 0 {
		s.Partial = true
		return s
	}
	s.DataThrough = time.Unix(dataThrough, 0).UTC()
	s.ProjectionLag = int64(s.GeneratedAt.Sub(s.DataThrough).Seconds())
	s.Stale = s.ProjectionLag > int64((5 * time.Minute).Seconds())
	return s
}

// Overview, Funnel, and Operations expose purpose-built, finite dashboard
// shapes rather than generic pagination over authoritative records.
func (r Repository) Overview(ctx context.Context, q Query) (Snapshot, error) {
	if q.Dimension != "" {
		return Snapshot{}, ErrInvalidQuery
	}
	s, err := r.aggregate(ctx, q, "")
	if err != nil {
		return Snapshot{}, err
	}
	p95, known, err := r.latencyP95(ctx, q)
	if err != nil {
		return Snapshot{}, err
	}
	s.P95LatencyMS, s.LatencyKnown = p95, known
	return s, nil
}
func (r Repository) Funnel(ctx context.Context, q Query) (Snapshot, error) {
	if q.Dimension != "" && q.Dimension != "stage" {
		return Snapshot{}, ErrInvalidQuery
	}
	return r.aggregate(ctx, q, "stage")
}

func (r Repository) aggregate(ctx context.Context, q Query, dimension string) (Snapshot, error) {
	if err := validate(q); err != nil {
		return Snapshot{}, err
	}
	ctx, cancel, err := r.context(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	defer cancel()
	metrics := q.Cards
	if len(metrics) == 0 {
		metrics = []string{"admission_decision", "run_started", "run_completed", "report_delivery_state", "rejection_delivery_state"}
	}
	placeholders := strings.TrimRight(strings.Repeat("?,", len(metrics)), ",")
	args := []any{q.Interval, q.From.UTC().Unix(), q.To.UTC().Unix()}
	for _, m := range metrics {
		args = append(args, m)
	}
	selectKey := "metric"
	group := "metric"
	if dimension != "" {
		selectKey = `COALESCE(NULLIF(json_extract(dimension_key,'$.` + dimension + `'),''),'unknown')`
		group = selectKey
	}
	rows, err := r.DB.QueryContext(ctx, `SELECT `+selectKey+`,SUM(event_count),MAX(source_high_watermark),MAX(bucket_start) FROM metric_rollups WHERE granularity=? AND bucket_start>=? AND bucket_start<? AND metric IN (`+placeholders+`) GROUP BY `+group+` ORDER BY `+group, args...)
	if err != nil {
		return Snapshot{}, fmt.Errorf("analytics aggregate: %w", err)
	}
	defer rows.Close()
	var watermark, dataThrough int64
	s := Snapshot{}
	for rows.Next() {
		var v Value
		var high, bucket int64
		if err := rows.Scan(&v.Key, &v.Count, &high, &bucket); err != nil {
			return Snapshot{}, err
		}
		if v.Key == "" {
			v.Key = "unknown"
		}
		v.State = "known"
		s.Values = append(s.Values, v)
		if high > watermark {
			watermark = high
		}
		if bucket > dataThrough {
			dataThrough = bucket
		}
	}
	if err := rows.Err(); err != nil {
		return Snapshot{}, err
	}
	s2 := r.snapshot(watermark, dataThrough)
	s2.Values = s.Values
	return s2, nil
}

func (r Repository) Operations(ctx context.Context, q Query) (Snapshot, error) {
	if q.Dimension != "" || q.Metric != "" || len(q.Series) != 0 || len(q.Cards) != 0 {
		return Snapshot{}, ErrInvalidQuery
	}
	if err := validate(q); err != nil {
		return Snapshot{}, err
	}
	ctx, cancel, err := r.context(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	defer cancel()
	// Each statement uses a dedicated indexed current-state path; no queue rows
	// are mounted and no historical result/artifact data is selected.
	queries := []struct{ key, sql string }{
		{"queued", `SELECT COUNT(*),MIN(created_at) FROM runs WHERE state='queued'`},
		{"analysis_leased", `SELECT COUNT(*),MIN(created_at) FROM runs WHERE state='analysis_leased'`},
		{"report_pending", `SELECT COUNT(*),MIN(created_at) FROM runs WHERE state='report_pending'`},
		{"report_leased", `SELECT COUNT(*),MIN(created_at) FROM runs WHERE state='report_leased'`},
		{"rejection_pending", `SELECT COUNT(*),MIN(created_at) FROM rejection_work_items WHERE state='pending'`},
	}
	now := r.now()
	s := Snapshot{GeneratedAt: now, ObservedAt: now, DataThrough: now}
	for _, query := range queries {
		var count int64
		var oldest sql.NullInt64
		if err := r.DB.QueryRowContext(ctx, query.sql).Scan(&count, &oldest); err != nil {
			return Snapshot{}, fmt.Errorf("analytics current state: %w", err)
		}
		value := Value{Key: query.key, State: "known", Count: count}
		if oldest.Valid {
			value.OldestAt = time.Unix(oldest.Int64, 0).UTC()
		}
		s.Values = append(s.Values, value)
	}
	sort.Slice(s.Values, func(i, j int) bool { return s.Values[i].Key < s.Values[j].Key })
	return s, nil
}

// latencyP95 derives a bounded exponential histogram from durable event
// aggregates. It never returns or persists individual samples: each query row
// is an equal-duration count, then folded into documented [2^n,2^(n+1)) ms
// buckets (with a 24-hour cap). Source events retain only their normal 31-day
// lifecycle, so older windows intentionally report latency as unknown.
func (r Repository) latencyP95(ctx context.Context, q Query) (int64, bool, error) {
	if q.To.Sub(q.From) > 31*24*time.Hour {
		return 0, false, nil
	}
	ctx, cancel, err := r.context(ctx)
	if err != nil {
		return 0, false, err
	}
	defer cancel()
	rows, err := r.DB.QueryContext(ctx, `SELECT duration_ms,COUNT(*) FROM analytics_events WHERE event_type='analyzer_observation' AND occurred_at>=? AND occurred_at<? AND duration_ms>0 GROUP BY duration_ms`, q.From.UTC().Unix(), q.To.UTC().Unix())
	if err != nil {
		return 0, false, fmt.Errorf("analytics latency histogram: %w", err)
	}
	defer rows.Close()
	buckets := make([]int64, 18) // [1,2), ... [65536,131072) and capped tail.
	var total int64
	for rows.Next() {
		var duration, count int64
		if err := rows.Scan(&duration, &count); err != nil {
			return 0, false, err
		}
		index := 0
		for bound := int64(2); duration >= bound && index < len(buckets)-1; bound *= 2 {
			index++
		}
		buckets[index] += count
		total += count
	}
	if err := rows.Err(); err != nil {
		return 0, false, err
	}
	if total == 0 {
		return 0, false, nil
	}
	target := (95*total + 99) / 100
	var seen int64
	for index, count := range buckets {
		seen += count
		if seen >= target {
			return int64(1) << index, true, nil
		}
	}
	return int64(1) << (len(buckets) - 1), true, nil
}
