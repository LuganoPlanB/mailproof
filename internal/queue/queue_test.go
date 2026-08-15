package queue

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestClaimDoesNotDoubleClaim(t *testing.T) {
	db, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	if _, err := db.Exec(`INSERT INTO deliveries VALUES ('d', 'digest', 'source', ?); INSERT INTO runs(run_id,delivery_id,state,created_at) VALUES ('r','d','queued',?)`, now.Unix(), now.Unix()); err != nil {
		t.Fatal(err)
	}
	first, err := Claim(context.Background(), db, "one", "analysis", now, time.Minute)
	if err != nil || first == nil {
		t.Fatalf("first claim = %v, %v", first, err)
	}
	second, err := Claim(context.Background(), db, "two", "analysis", now, time.Minute)
	if err != nil || second != nil {
		t.Fatalf("second claim = %v, %v", second, err)
	}
}

func TestScaledWorkersClaimEachRunOnce(t *testing.T) {
	db, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	for index := range 4 {
		delivery := fmt.Sprintf("d%d", index)
		run := fmt.Sprintf("r%d", index)
		if err := EnqueueCollection(context.Background(), db, delivery, "digest", delivery, run, now); err != nil {
			t.Fatal(err)
		}
	}
	claimed := make(chan string, 4)
	var group sync.WaitGroup
	for worker := range 4 {
		group.Add(1)
		go func(worker int) {
			defer group.Done()
			run, err := Claim(context.Background(), db, fmt.Sprintf("worker-%d", worker), "analysis", now, time.Minute)
			if err != nil || run == nil {
				return
			}
			claimed <- run.ID
		}(worker)
	}
	group.Wait()
	close(claimed)
	unique := map[string]bool{}
	for id := range claimed {
		unique[id] = true
	}
	if len(unique) != 4 {
		t.Fatalf("unique claims=%d, want 4", len(unique))
	}
}

func TestClaimRecoversExpiredLease(t *testing.T) {
	db, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	if _, err := db.Exec(`INSERT INTO deliveries VALUES ('d', 'digest', 'source', ?)`, now.Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO runs(run_id,delivery_id,state,lease_owner,lease_until,created_at) VALUES ('r','d','analysis_leased','dead',?,?)`, now.Add(-time.Minute).Unix(), now.Unix()); err != nil {
		t.Fatal(err)
	}
	run, err := Claim(context.Background(), db, "live", "analysis", now, time.Minute)
	if err != nil || run == nil || run.ID != "r" {
		t.Fatalf("Claim() = %#v, %v", run, err)
	}
}

func TestRetryMovesAnalysisToDeadAtLimit(t *testing.T) {
	db, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now()
	if _, err := db.Exec(`INSERT INTO deliveries VALUES ('d','x','s',?)`, now.Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO runs(run_id,delivery_id,state,created_at) VALUES ('r','d','queued',?)`, now.Unix()); err != nil {
		t.Fatal(err)
	}
	if err := Retry(context.Background(), db, "r", "analysis", "failure", now, 1); err != nil {
		t.Fatal(err)
	}
	var state string
	if err := db.QueryRow(`SELECT state FROM runs WHERE run_id='r'`).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != AnalysisDead {
		t.Fatalf("state=%s", state)
	}
}

func TestReportClaimRenewAndFinish(t *testing.T) {
	db, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now()
	if _, err := db.Exec(`INSERT INTO deliveries VALUES ('d','x','s',?)`, now.Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO runs(run_id,delivery_id,state,created_at) VALUES ('r','d','report_pending',?)`, now.Unix()); err != nil {
		t.Fatal(err)
	}
	run, err := Claim(context.Background(), db, "owner", "report", now, time.Minute)
	if err != nil || run == nil {
		t.Fatalf("claim=%v err=%v", run, err)
	}
	if err := Renew(context.Background(), db, "r", "owner", now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := FinishReport(context.Background(), db, "r", "owner", Complete); err != nil {
		t.Fatal(err)
	}
}

func TestUnknownReplyIsQuarantinedAndCanOnlyBeExplicitlyRedelivered(t *testing.T) {
	db, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now()
	if _, err := db.Exec(`INSERT INTO deliveries VALUES ('d','x','s',?)`, now.Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO runs(run_id,delivery_id,state,created_at) VALUES ('r','d','report_pending',?)`, now.Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := Claim(context.Background(), db, "owner", "report", now, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := QuarantineReply(context.Background(), db, "r", "owner", "smtp_outcome_unknown"); err != nil {
		t.Fatal(err)
	}
	if err := Redeliver(context.Background(), db, "r"); err != nil {
		t.Fatal(err)
	}
	if err := Redeliver(context.Background(), db, "r"); err == nil {
		t.Fatal("non-dead run was redelivered")
	}
}

func TestMigrationRecordsVersion(t *testing.T) {
	db, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var version int
	if err := db.QueryRow(`SELECT version FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 1 {
		t.Fatalf("version=%d", version)
	}
}

func TestCollectorLeaseRejectsCompetingOwner(t *testing.T) {
	db, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now()
	ok, err := AcquireCollectorLease(context.Background(), db, "one", now, time.Minute)
	if err != nil || !ok {
		t.Fatal(err)
	}
	ok, err = AcquireCollectorLease(context.Background(), db, "two", now, time.Minute)
	if err != nil || ok {
		t.Fatalf("competing lease=%v err=%v", ok, err)
	}
}
