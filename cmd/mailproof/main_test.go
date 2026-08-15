package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luganoplanb/mailproof/internal/queue"
)

func TestStatusRequiresJSON(t *testing.T) {
	if err := run(context.Background(), []string{"status"}); err == nil {
		t.Fatal("status accepted missing --json")
	}
}

func TestAnalyticsCommandsRequireExplicitModeAndRetentionBackup(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "analytics.sqlite")
	if err := run(context.Background(), []string{"analytics", "rebuild", "--state", state, "--dry-run"}); err != nil {
		t.Fatalf("rebuild dry-run: %v", err)
	}
	if err := run(context.Background(), []string{"analytics", "retain", "--state", state, "--dry-run"}); err == nil {
		t.Fatal("retain dry-run accepted absent backup marker")
	}
	db, err := queue.Open(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	if err := run(context.Background(), []string{"analytics", "retain", "--state", state, "--confirm"}); err == nil {
		t.Fatal("retain accepted absent backup marker")
	}
	if err := run(context.Background(), []string{"analytics", "rebuild", "--state", state, "--confirm"}); err != nil {
		t.Fatalf("rebuild confirm: %v", err)
	}
}

func TestAnalyticsProjectorLeaseExclusionAndShutdown(t *testing.T) {
	state := filepath.Join(t.TempDir(), "analytics.sqlite")
	db, err := queue.Open(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ok, err := acquireAnalyticsLease(context.Background(), db, "one", time.Now(), time.Minute)
	if err != nil || !ok {
		t.Fatalf("first lease=%v,%v", ok, err)
	}
	if ok, err = acquireAnalyticsLease(context.Background(), db, "two", time.Now(), time.Minute); err != nil || ok {
		t.Fatalf("second lease=%v,%v", ok, err)
	}
	releaseAnalyticsLease(context.Background(), db, "one")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := run(ctx, []string{"analytics-projector", "--state", state, "--watch", "--poll-interval=1ms"}); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("graceful shutdown: %v", err)
	}
}

func TestAnalyticsRebuildAndRetentionContracts(t *testing.T) {
	state := filepath.Join(t.TempDir(), "analytics.sqlite")
	db, err := queue.Open(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := db.Exec(`INSERT INTO analytics_events(producer,source_type,source_id,event_type,schema_version,occurred_at,outcome,duration_ms,payload_digest) VALUES('queue','run','old','run_started',1,?,'analysis',0,'digest'); UPDATE analytics_cursor SET event_id=1 WHERE singleton=1; INSERT INTO analytics_backup_markers(marker_id,verified_at,manifest_digest) VALUES(1,?,'digest')`, now.AddDate(0, 0, -32).Unix(), now.Unix()); err != nil {
		t.Fatal(err)
	}
	// A dry run never mutates append-only input.
	if err := run(context.Background(), []string{"analytics", "retain", "--state", state, "--dry-run"}); err != nil {
		t.Fatal(err)
	}
	var before int
	if err := db.QueryRow("SELECT COUNT(*) FROM analytics_events").Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), []string{"analytics", "rebuild", "--state", state, "--confirm"}); err != nil {
		t.Fatal(err)
	}
	var incremental string
	if err := db.QueryRow("SELECT group_concat(granularity||':'||bucket_start||':'||event_count) FROM metric_rollups").Scan(&incremental); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), []string{"analytics", "rebuild", "--state", state, "--dry-run"}); err != nil {
		t.Fatal(err)
	}
	var afterDry string
	if err := db.QueryRow("SELECT group_concat(granularity||':'||bucket_start||':'||event_count) FROM metric_rollups").Scan(&afterDry); err != nil {
		t.Fatal(err)
	}
	if incremental != afterDry {
		t.Fatal("rebuild dry-run mutated rollups")
	}
	// Supply complete coarser buckets, then retention may compact only analytics input.
	if _, err := db.Exec(`INSERT OR IGNORE INTO metric_rollups VALUES(0,'minute','run_started','analysis',1,'{}',1,1),(0,'hour','run_started','analysis',1,'{}',1,1),(0,'day','run_started','analysis',1,'{}',1,1)`); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), []string{"analytics", "retain", "--state", state, "--confirm"}); err != nil {
		t.Fatal(err)
	}
	var remaining int
	if err := db.QueryRow("SELECT COUNT(*) FROM analytics_events").Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if before != 1 || remaining != 0 {
		t.Fatalf("retention events before/after=%d/%d", before, remaining)
	}
	db.Close()
}

func TestAnalyticsRebuildRequiresStrictHalfOpenUTCWindow(t *testing.T) {
	state := filepath.Join(t.TempDir(), "analytics.sqlite")
	for _, args := range [][]string{{"analytics", "rebuild", "--state", state, "--dry-run", "--from=2024-01-01T00:00:00+01:00", "--to=2024-01-02T00:00:00Z"}, {"analytics", "rebuild", "--state", state, "--dry-run", "--from=2024-01-02T00:00:00Z", "--to=2024-01-01T00:00:00Z"}, {"analytics", "rebuild", "--state", state, "--dry-run", "--from=2024-01-01T10:00:00Z", "--to=2024-01-01T11:00:00Z"}} {
		if err := run(context.Background(), args); err == nil {
			t.Fatal("invalid rebuild window accepted")
		}
	}
}

func TestSubmitterDryRunDoesNotRequireStateOrSecrets(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "missing.sqlite")
	key := filepath.Join(dir, "missing-key")
	if err := run(context.Background(), []string{"submitter", "challenge", "--email", "operator@example.org", "--state", state, "--capability-key", key, "--dry-run", "--json"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dry-run created state: %v", err)
	}
}
func TestCollectRejectsConflictingModes(t *testing.T) {
	if err := run(context.Background(), []string{"collect", "--once", "--watch"}); err == nil {
		t.Fatal("collect accepted conflicting modes")
	}
}
func TestCollectOnceEmptyMaildir(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "new")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), []string{"collect", "--once", "--source", source, "--artifacts", filepath.Join(dir, "artifacts"), "--state", filepath.Join(dir, "state.sqlite")}); err != nil {
		t.Fatal(err)
	}
}

func TestCollectWatchFindsMailArrivingAfterFirstSweep(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "new")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(25 * time.Millisecond)
		_ = os.WriteFile(filepath.Join(source, "new-message"), []byte("Subject: later\r\n\r\nbody"), 0o600)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	state := filepath.Join(dir, "state.sqlite")
	stampKey := filepath.Join(dir, "admission-stamp-key")
	if err := os.WriteFile(stampKey, []byte("01234567890123456789012345678901"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(ctx, []string{"collect", "--watch", "--max-jobs", "2", "--source", source, "--artifacts", filepath.Join(dir, "artifacts"), "--state", state, "--admission-stamp-key", stampKey}); err != nil {
		t.Fatal(err)
	}
	db, err := queue.Open(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM deliveries").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("deliveries=%d, want 1", count)
	}
}

func TestCollectWatchRepeatsEmptySweep(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "new")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := run(ctx, []string{"collect", "--watch", "--max-jobs", "2", "--source", source, "--artifacts", filepath.Join(dir, "artifacts"), "--state", filepath.Join(dir, "state.sqlite")}); err != nil {
		t.Fatal(err)
	}
}

func TestCollectRejectsSecondCollector(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state.sqlite")
	db, err := queue.Open(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if ok, err := queue.AcquireCollectorLease(context.Background(), db, "other", time.Now(), time.Minute); err != nil || !ok {
		t.Fatalf("acquire lease: %v, %v", ok, err)
	}
	if err := run(context.Background(), []string{"collect", "--once", "--source", filepath.Join(dir, "new"), "--artifacts", filepath.Join(dir, "artifacts"), "--state", state}); !errors.Is(err, errCollectorLeaseHeld) {
		t.Fatalf("collect error = %v, want lease held", err)
	}
}

func TestWorkerDrainProcessesDueJobsAndStops(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state.sqlite")
	artifacts := filepath.Join(dir, "artifacts")
	message := []byte("From: sender@example.test\r\nSubject: test\r\n\r\nbody\r\n")
	sum := sha256.Sum256(message)
	digest := hex.EncodeToString(sum[:])
	if err := os.MkdirAll(filepath.Join(artifacts, "messages"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(artifacts, "messages", digest+".eml"), message, 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := queue.Open(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := queue.EnqueueCollection(context.Background(), db, "delivery", digest, "source", "run", now); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), []string{"worker", "--drain", "--state", state, "--artifacts", artifacts, "--rspamd", "http://127.0.0.1:1"}); err != nil {
		t.Fatal(err)
	}
	db, err = queue.Open(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var stateValue string
	if err := db.QueryRow("SELECT state FROM runs WHERE run_id='run'").Scan(&stateValue); err != nil {
		t.Fatal(err)
	}
	if stateValue != queue.ReportPending {
		t.Fatalf("state=%q, want %q", stateValue, queue.ReportPending)
	}
	if _, err := os.Stat(filepath.Join(artifacts, "runs", "run", "analysis", "evidence.json")); err != nil {
		t.Fatalf("analysis evidence was not published: %v", err)
	}
}

func TestReporterDrainSignsArtifactsAndSuppressesEmptyRecipient(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state.sqlite")
	artifacts := filepath.Join(dir, "artifacts")
	message := []byte("From: sender@example.test\r\nSubject: report\r\n\r\nbody\r\n")
	sum := sha256.Sum256(message)
	digest := hex.EncodeToString(sum[:])
	if err := os.MkdirAll(filepath.Join(artifacts, "messages"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(artifacts, "messages", digest+".eml"), message, 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := queue.Open(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.EnqueueCollection(context.Background(), db, "delivery", digest, "source", "run", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), []string{"worker", "--drain", "--state", state, "--artifacts", artifacts, "--rspamd", "http://127.0.0.1:1"}); err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "report-signing-key.pem")
	if err := os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	recipient := filepath.Join(dir, "recipient")
	if err := os.WriteFile(recipient, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), []string{"reporter", "--drain", "--state", state, "--artifacts", artifacts, "--signing-key", key, "--report-recipient-file", recipient}); err != nil {
		t.Fatal(err)
	}
	db, err = queue.Open(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var got string
	if err := db.QueryRow("SELECT state FROM runs WHERE run_id='run'").Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != queue.ReplySuppressed {
		t.Fatalf("state=%q, want %q", got, queue.ReplySuppressed)
	}
	for _, name := range []string{"report.json", "report.txt", "report.html", "manifest.json", "manifest.sig"} {
		if _, err := os.Stat(filepath.Join(artifacts, "runs", "run", "report", name)); err != nil {
			t.Fatalf("%s missing: %v", name, err)
		}
	}
}

func TestWorkerStopsOnShutdown(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state.sqlite")
	db, err := queue.Open(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	if err := run(ctx, []string{"worker", "--state", state}); err != nil {
		t.Fatal(err)
	}
}

func TestStableExitCodes(t *testing.T) {
	if got := exitCode(errCollectorLeaseHeld); got != 3 {
		t.Fatalf("lease exit code=%d", got)
	}
	if got := exitCode(errors.New("invalid flag")); got != 2 {
		t.Fatalf("usage exit code=%d", got)
	}
}

func TestReplayCreatesNewRunWithoutChangingOriginal(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state.sqlite")
	db, err := queue.Open(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.EnqueueCollection(context.Background(), db, "delivery", "digest", "source", "original", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), []string{"replay", "--run", "original", "--json", "--state", state}); err != nil {
		t.Fatal(err)
	}
	db, err = queue.Open(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM runs WHERE delivery_id='delivery'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("runs=%d, want 2", count)
	}
}
