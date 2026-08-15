package analytics_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/luganoplanb/mailproof/internal/analytics"
	"github.com/luganoplanb/mailproof/internal/queue"
)

func TestRepositorySeriesIsBoundedAndUTCFilled(t *testing.T) {
	db, err := queue.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := db.Exec(`INSERT INTO metric_rollups(bucket_start,granularity,metric,outcome,schema_version,dimension_key,event_count,source_high_watermark) VALUES(?,?,?,?,?,?,?,?),(?,?,?,?,?,?,?,?)`, from.Unix(), "hour", "run_started", "analysis", 1, `{"stage":"admission"}`, 2, 3, from.Unix(), "hour", "run_started", "analysis", 1, `{"stage":"quota"}`, 1, 3); err != nil {
		t.Fatal(err)
	}
	r := analytics.Repository{DB: db, Now: func() time.Time { return from.Add(3 * time.Hour) }}
	dimensioned, err := r.Series(context.Background(), analytics.Query{From: from, To: from.Add(time.Hour), Interval: "hour", Series: []string{"run_started"}, Dimension: "stage"})
	if err != nil || len(dimensioned.Buckets[0].Values) != 2 || dimensioned.Buckets[0].Values[0].Key != "run_started:admission" {
		t.Fatalf("dimensioned=%+v err=%v", dimensioned, err)
	}
	s, err := r.Series(context.Background(), analytics.Query{From: from, To: from.Add(2 * time.Hour), Interval: "hour", Series: []string{"run_started"}})
	if err != nil || len(s.Buckets) != 2 || s.Buckets[0].Values[0].Count != 3 || s.Buckets[1].Values[0].Count != 0 || s.Partial {
		t.Fatalf("snapshot=%+v err=%v", s, err)
	}
	for _, q := range []analytics.Query{
		{From: from, To: from.Add(32 * 24 * time.Hour), Interval: "minute", Series: []string{"run_started"}},
		{From: from, To: from.Add(time.Hour), Interval: "hour", Series: make([]string, 13)},
		{From: from.Add(time.Second), To: from.Add(time.Hour), Interval: "hour", Series: []string{"run_started"}},
	} {
		if _, err := r.Series(context.Background(), q); err != analytics.ErrInvalidQuery {
			t.Fatalf("query accepted: %+v err=%v", q, err)
		}
	}
}

func TestRepositoryLatencyHistogramAndFreshness(t *testing.T) {
	db, err := queue.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i, duration := range []int64{1, 2, 2, 4, 4, 4, 8, 8, 8, 8, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16} {
		if _, err := db.Exec(`INSERT INTO analytics_events(producer,source_type,source_id,event_type,schema_version,occurred_at,outcome,dimension_key,duration_ms,payload_digest) VALUES('worker','run',?,'analyzer_observation',1,?,'ok','{}',?,?)`, fmt.Sprintf("latency-%d", i), from.Unix(), duration, fmt.Sprintf("digest-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO metric_rollups(bucket_start,granularity,metric,outcome,schema_version,dimension_key,event_count,source_high_watermark) VALUES(?,?,?,?,?,?,?,?)`, from.Unix(), "hour", "run_started", "analysis", 1, "{}", 1, 20); err != nil {
		t.Fatal(err)
	}
	q := analytics.Query{From: from, To: from.Add(time.Hour), Interval: "hour"}
	fresh, err := (analytics.Repository{DB: db, Now: func() time.Time { return from.Add(5 * time.Minute) }}).Overview(context.Background(), q)
	if err != nil || !fresh.LatencyKnown || fresh.P95LatencyMS != 16 || fresh.Stale || fresh.Partial {
		t.Fatalf("fresh=%+v err=%v", fresh, err)
	}
	stale, err := (analytics.Repository{DB: db, Now: func() time.Time { return from.Add(5*time.Minute + time.Second) }}).Overview(context.Background(), q)
	if err != nil || !stale.Stale {
		t.Fatalf("stale=%+v err=%v", stale, err)
	}
	unknown, err := (analytics.Repository{DB: db}).Overview(context.Background(), analytics.Query{From: from, To: from.AddDate(0, 2, 0), Interval: "day"})
	if err != nil || unknown.LatencyKnown {
		t.Fatalf("unknown=%+v err=%v", unknown, err)
	}
}

func TestRepositoryOperationsUsesCurrentStateOnly(t *testing.T) {
	db, err := queue.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`INSERT INTO deliveries(delivery_id,message_digest,source_key,collected_at) VALUES('d','x','x',1); INSERT INTO runs(run_id,delivery_id,state,created_at) VALUES('r','d','queued',1)`); err != nil {
		t.Fatal(err)
	}
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s, err := (analytics.Repository{DB: db, Now: func() time.Time { return from }}).Operations(context.Background(), analytics.Query{From: from, To: from.Add(time.Hour), Interval: "hour"})
	if err != nil || s.ObservedAt.IsZero() || len(s.Values) != 5 {
		t.Fatalf("snapshot=%+v err=%v", s, err)
	}
}

func TestDashboardIndexesAreSelected(t *testing.T) {
	db, err := queue.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	rows, err := db.Query(`EXPLAIN QUERY PLAN SELECT bucket_start,metric,SUM(event_count),MAX(source_high_watermark) FROM metric_rollups WHERE granularity=? AND bucket_start>=? AND bucket_start<? AND metric IN (?) GROUP BY bucket_start,metric ORDER BY bucket_start,metric`, "hour", 0, 3600, "run_started")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan strings.Builder
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(detail)
	}
	if !strings.Contains(plan.String(), "metric_rollups_dashboard") {
		t.Fatalf("dashboard index not selected: %s", plan.String())
	}
}
