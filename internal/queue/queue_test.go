package queue

import (
	"context"
	"database/sql"
	"errors"
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
	if _, err := db.Exec(`INSERT INTO deliveries(delivery_id,message_digest,source_key,collected_at) VALUES ('d', 'digest', 'source', ?); INSERT INTO runs(run_id,delivery_id,state,created_at) VALUES ('r','d','queued',?)`, now.Unix(), now.Unix()); err != nil {
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
	if _, err := db.Exec(`INSERT INTO deliveries(delivery_id,message_digest,source_key,collected_at) VALUES ('d', 'digest', 'source', ?)`, now.Unix()); err != nil {
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
	if _, err := db.Exec(`INSERT INTO deliveries(delivery_id,message_digest,source_key,collected_at) VALUES ('d','x','s',?)`, now.Unix()); err != nil {
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
	if _, err := db.Exec(`INSERT INTO deliveries(delivery_id,message_digest,source_key,collected_at) VALUES ('d','x','s',?)`, now.Unix()); err != nil {
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
	if _, err := db.Exec(`INSERT INTO deliveries(delivery_id,message_digest,source_key,collected_at) VALUES ('d','x','s',?)`, now.Unix()); err != nil {
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
	if err := db.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 7 {
		t.Fatalf("version=%d", version)
	}
}

func TestReportAttemptRecordsKnownAndUnknownOutcomes(t *testing.T) {
	db, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Unix(1700000000, 0).UTC()
	if _, err := db.Exec(`INSERT INTO submitters(submitter_id,canonical_address,status,created_at,policy_version,minute_limit,hour_limit,day_limit) VALUES('submitter','verified@example.test','active',?,'v1',1,1,1)`, now.Unix()); err != nil {
		t.Fatal(err)
	}
	destination := ReportDestination{SubmitterID: "submitter", ReplyAddress: "verified@example.test"}
	if err := EnqueueAdmittedCollection(context.Background(), db, "delivery", "digest", "source", "run", destination, now); err != nil {
		t.Fatal(err)
	}
	attempt, err := BeginReportAttempt(context.Background(), db, "run", destination, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := FinishReportAttempt(context.Background(), db, attempt, "unknown", "smtp", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var outcome, capability string
	if err := db.QueryRow(`SELECT outcome, error_class FROM report_delivery_attempts WHERE attempt_id=?`, attempt).Scan(&outcome, &capability); err != nil {
		t.Fatal(err)
	}
	if outcome != "unknown" || capability != "smtp" {
		t.Fatalf("attempt=%q/%q", outcome, capability)
	}
}

func TestAdmittedDeliverySnapshotsDestinationForReplayAndRevocation(t *testing.T) {
	db, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Unix(1700000000, 0).UTC()
	if _, err := db.Exec(`INSERT INTO submitters(submitter_id,canonical_address,status,created_at,policy_version,minute_limit,hour_limit,day_limit) VALUES('submitter','verified@example.test','active',?,'v1',1,1,1)`, now.Unix()); err != nil {
		t.Fatal(err)
	}
	destination, err := SnapshotReportDestination(context.Background(), db, "submitter")
	if err != nil {
		t.Fatal(err)
	}
	if err := EnqueueAdmittedCollection(context.Background(), db, "delivery", "digest", "source", "run", destination, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE submitters SET status='revoked',canonical_address='changed@example.test' WHERE submitter_id='submitter'`); err != nil {
		t.Fatal(err)
	}
	if err := Replay(context.Background(), db, "delivery", "replay", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	for _, runID := range []string{"run", "replay"} {
		got, err := ReportDestinationForRun(context.Background(), db, runID)
		if err != nil || got != destination {
			t.Fatalf("destination for %s = %#v, %v", runID, got, err)
		}
	}
}

func TestLegacyDeliverySuppressesAutomaticReply(t *testing.T) {
	db, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now()
	if _, err := db.Exec(`INSERT INTO deliveries(delivery_id,message_digest,source_key,collected_at) VALUES('legacy','digest','source',?)`, now.Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO runs(run_id,delivery_id,state,created_at) VALUES('run','legacy','report_pending',?)`, now.Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := ReportDestinationForRun(context.Background(), db, "run"); !errors.Is(err, ErrNoReportDestination) {
		t.Fatalf("lookup error = %v, want ErrNoReportDestination", err)
	}
}

func TestRecordRejectedCollectionEnqueuesNotarization(t *testing.T) {
	db, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Unix(1700000000, 0).UTC()
	if err := RecordRejectedCollection(context.Background(), db, "delivery", "digest", "source", "decision", "stamp_invalid", now); err != nil {
		t.Fatal(err)
	}
	var deliveries, work int
	if err := db.QueryRow("SELECT COUNT(*) FROM deliveries").Scan(&deliveries); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM rejection_work_items WHERE kind='notarize' AND state='pending'").Scan(&work); err != nil {
		t.Fatal(err)
	}
	if deliveries != 1 || work != 1 {
		t.Fatalf("deliveries=%d work=%d", deliveries, work)
	}
}

func TestAdmittedRejectedDeliveryRetainsVerifiedDestination(t *testing.T) {
	db, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Unix(1700000000, 0).UTC()
	if _, err := db.Exec(`INSERT INTO submitters(submitter_id,canonical_address,status,created_at,policy_version,minute_limit,hour_limit,day_limit) VALUES('submitter','verified@example.test','active',?,'v1',1,1,1)`, now.Unix()); err != nil {
		t.Fatal(err)
	}
	destination := ReportDestination{SubmitterID: "submitter", ReplyAddress: "verified@example.test"}
	if err := RecordAdmittedRejectedCollection(context.Background(), db, "delivery", "digest", "source", "decision", "sender_denied", destination, now); err != nil {
		t.Fatal(err)
	}
	var submitterID, replyAddress string
	if err := db.QueryRow(`SELECT submitter_id,reply_address FROM deliveries WHERE delivery_id='delivery'`).Scan(&submitterID, &replyAddress); err != nil {
		t.Fatal(err)
	}
	if submitterID != destination.SubmitterID || replyAddress != destination.ReplyAddress {
		t.Fatalf("destination=%q/%q", submitterID, replyAddress)
	}
}

func TestMigrationFromVersionOnePreservesQueueRows(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);
INSERT INTO schema_migrations VALUES(1,1);
CREATE TABLE deliveries(delivery_id TEXT PRIMARY KEY,message_digest TEXT NOT NULL,source_key TEXT NOT NULL UNIQUE,collected_at INTEGER NOT NULL);
CREATE TABLE runs(run_id TEXT PRIMARY KEY,delivery_id TEXT NOT NULL,state TEXT NOT NULL,analysis_attempts INTEGER NOT NULL DEFAULT 0,report_attempts INTEGER NOT NULL DEFAULT 0,not_before INTEGER NOT NULL DEFAULT 0,lease_owner TEXT,lease_until INTEGER,last_error TEXT NOT NULL DEFAULT '',created_at INTEGER NOT NULL);
CREATE TABLE collector_lease(singleton INTEGER PRIMARY KEY,owner TEXT NOT NULL,until INTEGER NOT NULL);
INSERT INTO deliveries VALUES('delivery','digest','source',1);
INSERT INTO runs(run_id,delivery_id,state,created_at) VALUES('run','delivery','queued',1);`); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := db.QueryRow("SELECT COUNT(*) FROM deliveries WHERE delivery_id='delivery'").Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("preserved deliveries=%d err=%v", rows, err)
	}
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatalf("idempotent migration: %v", err)
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
