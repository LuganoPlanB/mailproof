package analytics_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/luganoplanb/mailproof/internal/analytics"
	"github.com/luganoplanb/mailproof/internal/queue"
)

func TestLifecycleIsAllowListedAndIdempotent(t *testing.T) {
	db, err := queue.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Unix(1700000000, 0).UTC()
	e, err := analytics.NewLifecycle("queue", "run", "run-1", "run_started", "analysis", now)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		tx, err := db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if err := analytics.InsertTx(context.Background(), tx, e); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM analytics_events").Scan(&n); err != nil || n != 1 {
		t.Fatalf("events=%d err=%v", n, err)
	}
	if _, err := analytics.NewLifecycle("queue", "run", "run-2", "metric", "arbitrary", now); err == nil {
		t.Fatal("arbitrary event accepted")
	}
}

func TestRolledBackAuthoritativeTransitionHasNoEvent(t *testing.T) {
	db, err := queue.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	e, _ := analytics.NewLifecycle("queue", "run", "rollback", "run_started", "analysis", time.Now())
	if err := analytics.InsertTx(context.Background(), tx, e); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM analytics_events").Scan(&n); err != nil || n != 0 {
		t.Fatalf("events=%d,%v", n, err)
	}
}

func TestConcurrentDuplicateProducersInsertOnce(t *testing.T) {
	db, err := queue.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e, _ := analytics.NewLifecycle("queue", "run", "same", "run_started", "analysis", time.Now())
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tx, err := db.Begin()
			if err != nil {
				return
			}
			defer tx.Rollback()
			if analytics.InsertTx(context.Background(), tx, e) == nil {
				_ = tx.Commit()
			}
		}()
	}
	wg.Wait()
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM analytics_events").Scan(&n); err != nil || n != 1 {
		t.Fatalf("events=%d,%v", n, err)
	}
}

func TestProjectOnceIsRestartSafe(t *testing.T) {
	db, err := queue.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	e, _ := analytics.NewLifecycle("queue", "run", "run-1", "run_started", "analysis", time.Unix(1700000000, 0))
	if err := analytics.InsertTx(context.Background(), tx, e); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if n, err := analytics.ProjectOnce(context.Background(), db, 100); err != nil || n != 1 {
		t.Fatalf("first projection=%d,%v", n, err)
	}
	if n, err := analytics.ProjectOnce(context.Background(), db, 100); err != nil || n != 0 {
		t.Fatalf("restart projection=%d,%v", n, err)
	}
	var n int
	if err := db.QueryRow("SELECT event_count FROM metric_rollups WHERE granularity='day'").Scan(&n); err != nil || n != 1 {
		t.Fatalf("day count=%d err=%v", n, err)
	}
}

func TestProjectOnceHonorsBatchAndUTCBoundaries(t *testing.T) {
	db, err := queue.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for i, at := range []time.Time{time.Date(2023, 11, 14, 23, 59, 59, 0, time.UTC), time.Date(2023, 11, 15, 0, 0, 0, 0, time.UTC)} {
		tx, err := db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		e, err := analytics.NewLifecycle("queue", "run", string(rune('a'+i)), "run_started", "analysis", at)
		if err != nil {
			t.Fatal(err)
		}
		if err := analytics.InsertTx(context.Background(), tx, e); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := analytics.ProjectOnce(context.Background(), db, 1); err != nil || n != 1 {
		t.Fatalf("first batch=%d,%v", n, err)
	}
	if n, err := analytics.ProjectOnce(context.Background(), db, 1); err != nil || n != 1 {
		t.Fatalf("second batch=%d,%v", n, err)
	}
	var buckets int
	if err := db.QueryRow("SELECT COUNT(*) FROM metric_rollups WHERE granularity='day'").Scan(&buckets); err != nil || buckets != 2 {
		t.Fatalf("UTC day buckets=%d,%v", buckets, err)
	}
}

func TestAnalyticsSchemaCannotStoreSensitiveMailFields(t *testing.T) {
	db, err := queue.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query("PRAGMA table_info(analytics_events)")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var def any
		if err := rows.Scan(&cid, &name, &typ, &notNull, &def, &pk); err != nil {
			t.Fatal(err)
		}
		switch name {
		case "address", "peer_ip", "subject", "url", "capability", "payload":
			t.Fatalf("sensitive column %q", name)
		}
	}
}

func TestProjectionIsIndependentOfInsertionOrder(t *testing.T) {
	makeDB := func(order []int) string {
		db, err := queue.Open(context.Background(), ":memory:")
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		times := []time.Time{time.Unix(1700000000, 0), time.Unix(1700000060, 0), time.Unix(1700000120, 0)}
		for _, i := range order {
			tx, _ := db.Begin()
			e, _ := analytics.NewLifecycle("queue", "run", string(rune('a'+i)), "run_started", "analysis", times[i])
			if err := analytics.InsertTx(context.Background(), tx, e); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
		}
		for {
			n, err := analytics.ProjectOnce(context.Background(), db, 1)
			if err != nil {
				t.Fatal(err)
			}
			if n == 0 {
				break
			}
		}
		var out string
		if err := db.QueryRow(`SELECT group_concat(granularity||':'||bucket_start||':'||event_count,'|') FROM (SELECT granularity,bucket_start,event_count FROM metric_rollups ORDER BY granularity,bucket_start)`).Scan(&out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if a, b := makeDB([]int{0, 1, 2}), makeDB([]int{2, 0, 1}); a != b {
		t.Fatalf("rollups differ: %q != %q", a, b)
	}
}

func TestLateEventAndCrashBoundaries(t *testing.T) {
	db, err := queue.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	insert := func(id string, at time.Time) {
		tx, _ := db.Begin()
		e, _ := analytics.NewLifecycle("queue", "run", id, "run_started", "analysis", at)
		if err := analytics.InsertTx(context.Background(), tx, e); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	insert("first", time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC))
	if _, err := analytics.ProjectOnce(context.Background(), db, 10); err != nil {
		t.Fatal(err)
	}
	// A simulated crash before commit leaves no event/cursor advancement.
	tx, _ := db.Begin()
	e, _ := analytics.NewLifecycle("queue", "run", "crashed", "run_started", "analysis", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
	if err := analytics.InsertTx(context.Background(), tx, e); err != nil {
		t.Fatal(err)
	}
	_ = tx.Rollback()
	if n, err := analytics.ProjectOnce(context.Background(), db, 10); err != nil || n != 0 {
		t.Fatalf("pre-commit crash=%d,%v", n, err)
	}
	// A late committed event is projected into its original UTC bucket; restart
	// after cursor commit is a no-op.
	insert("late", time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
	if n, err := analytics.ProjectOnce(context.Background(), db, 10); err != nil || n != 1 {
		t.Fatalf("late=%d,%v", n, err)
	}
	if n, err := analytics.ProjectOnce(context.Background(), db, 10); err != nil || n != 0 {
		t.Fatalf("post-commit restart=%d,%v", n, err)
	}
	var days int
	if err := db.QueryRow("SELECT COUNT(*) FROM metric_rollups WHERE granularity='day'").Scan(&days); err != nil || days != 2 {
		t.Fatalf("late buckets=%d,%v", days, err)
	}
}

func TestProjectOnceRejectsUnknownBatch(t *testing.T) {
	db, err := queue.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := analytics.ProjectOnce(context.Background(), db, 0); err == nil {
		t.Fatal("zero batch accepted")
	}
	if _, err := analytics.NewLifecycle("unknown", "run", "id", "run_started", "x", time.Now()); err == nil {
		t.Fatal("unknown producer accepted")
	}
}
