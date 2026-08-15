// Package queue owns the durable SQLite lifecycle for analysis runs.
package queue

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

const (
	Queued          = "queued"
	AnalysisLeased  = "analysis_leased"
	ReportPending   = "report_pending"
	ReportLeased    = "report_leased"
	Complete        = "complete"
	ReplySuppressed = "reply_suppressed"
	AnalysisDead    = "analysis_dead"
	ReportDead      = "report_dead"
)

type Run struct {
	ID, DeliveryID, State string
	Attempt               int
	LeaseUntil            time.Time
}

// EnqueueCollection atomically records an immutable delivery and its first run.
// Repeating the same delivery ID is idempotent; it never mutates prior rows.
func EnqueueCollection(ctx context.Context, db *sql.DB, deliveryID, digest, sourceKey, runID string, now time.Time) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin collection: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO deliveries(delivery_id,message_digest,source_key,collected_at) VALUES(?,?,?,?) ON CONFLICT(source_key) DO NOTHING`, deliveryID, digest, sourceKey, now.Unix()); err != nil {
		return fmt.Errorf("insert delivery: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO runs(run_id,delivery_id,state,created_at) VALUES(?,?,?,?) ON CONFLICT(run_id) DO NOTHING`, runID, deliveryID, Queued, now.Unix()); err != nil {
		return fmt.Errorf("insert run: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit collection: %w", err)
	}
	return nil
}

func Collected(ctx context.Context, db *sql.DB, sourceKey string) (bool, error) {
	var n int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM deliveries WHERE source_key=?", sourceKey).Scan(&n); err != nil {
		return false, fmt.Errorf("lookup collection: %w", err)
	}
	return n > 0, nil
}

func Open(ctx context.Context, path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, fmt.Errorf("open queue database: %w", err)
	}
	if path == ":memory:" {
		db.SetMaxOpenConns(1)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping queue database: %w", err)
	}
	if err := Migrate(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func Migrate(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS deliveries (
 delivery_id TEXT PRIMARY KEY, message_digest TEXT NOT NULL, source_key TEXT NOT NULL UNIQUE, collected_at INTEGER NOT NULL,
 UNIQUE(delivery_id));
 CREATE TABLE IF NOT EXISTS runs (
 run_id TEXT PRIMARY KEY, delivery_id TEXT NOT NULL REFERENCES deliveries(delivery_id),
 state TEXT NOT NULL CHECK(state IN ('queued','analysis_leased','report_pending','report_leased','complete','reply_suppressed','analysis_dead','report_dead')),
 analysis_attempts INTEGER NOT NULL DEFAULT 0, report_attempts INTEGER NOT NULL DEFAULT 0,
 not_before INTEGER NOT NULL DEFAULT 0, lease_owner TEXT, lease_until INTEGER, last_error TEXT NOT NULL DEFAULT '',
 created_at INTEGER NOT NULL, UNIQUE(delivery_id, run_id));

 CREATE INDEX IF NOT EXISTS runs_claim ON runs(state, not_before, lease_until);
 CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS collector_lease (singleton INTEGER PRIMARY KEY CHECK(singleton=1), owner TEXT NOT NULL, until INTEGER NOT NULL);
 INSERT OR IGNORE INTO schema_migrations(version, applied_at) VALUES (1, unixepoch());`)
	if err != nil {
		return fmt.Errorf("migrate queue database: %w", err)
	}
	return nil
}

func AcquireCollectorLease(ctx context.Context, db *sql.DB, owner string, now time.Time, duration time.Duration) (bool, error) {
	r, err := db.ExecContext(ctx, `INSERT INTO collector_lease(singleton,owner,until) VALUES(1,?,?) ON CONFLICT(singleton) DO UPDATE SET owner=excluded.owner,until=excluded.until WHERE collector_lease.until < ? OR collector_lease.owner=excluded.owner`, owner, now.Add(duration).Unix(), now.Unix())
	if err != nil {
		return false, fmt.Errorf("acquire collector lease: %w", err)
	}
	n, err := r.RowsAffected()
	return n == 1, err
}
func ReleaseCollectorLease(ctx context.Context, db *sql.DB, owner string) error { _,err:=db.ExecContext(ctx,"DELETE FROM collector_lease WHERE singleton=1 AND owner=?",owner);if err!=nil{return fmt.Errorf("release collector lease: %w",err)};return nil }

func Claim(ctx context.Context, db *sql.DB, owner, phase string, now time.Time, lease time.Duration) (*Run, error) {
	from, leased := Queued, AnalysisLeased
	if phase == "report" {
		from, leased = ReportPending, ReportLeased
	}
	if phase != "analysis" && phase != "report" {
		return nil, errors.New("unknown queue phase")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin claim: %w", err)
	}
	defer tx.Rollback()
	recovered, err := tx.ExecContext(ctx, `UPDATE runs SET state=CASE state WHEN 'analysis_leased' THEN 'queued' WHEN 'report_leased' THEN 'report_pending' END, lease_owner=NULL, lease_until=NULL WHERE state IN ('analysis_leased','report_leased') AND lease_until < ?`, now.Unix())
	if err != nil {
		return nil, fmt.Errorf("recover expired lease: %w", err)
	}
	recoveredCount, err := recovered.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("recovered lease rows: %w", err)
	}
	if recoveredCount > 0 {
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("commit lease recovery: %w", err)
		}
		return Claim(ctx, db, owner, phase, now, lease)
	}
	row := tx.QueryRowContext(ctx, `SELECT run_id, delivery_id, analysis_attempts, report_attempts FROM runs WHERE state=? AND not_before<=? ORDER BY created_at LIMIT 1`, from, now.Unix())
	var run Run
	var analysisAttempts, reportAttempts int
	if err := row.Scan(&run.ID, &run.DeliveryID, &analysisAttempts, &reportAttempts); errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("find due run: %w", err)
	}
	run.Attempt = analysisAttempts
	if phase == "report" {
		run.Attempt = reportAttempts
	}
	run.State, run.LeaseUntil = leased, now.Add(lease)
	result, err := tx.ExecContext(ctx, `UPDATE runs SET state=?, lease_owner=?, lease_until=? WHERE run_id=? AND state=?`, leased, owner, run.LeaseUntil.Unix(), run.ID, from)
	if err != nil {
		return nil, fmt.Errorf("claim run: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("claim rows affected: %w", err)
	}
	if n != 1 {
		return nil, nil
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit claim: %w", err)
	}
	return &run, nil
}

func FinishAnalysis(ctx context.Context, db *sql.DB, id, owner string) error {
	result, err := db.ExecContext(ctx, `UPDATE runs SET state='report_pending', lease_owner=NULL, lease_until=NULL WHERE run_id=? AND state='analysis_leased' AND lease_owner=?`, id, owner)
	if err != nil {
		return fmt.Errorf("finish analysis: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("finish analysis rows: %w", err)
	}
	if n != 1 {
		return errors.New("analysis lease not owned")
	}
	return nil
}

func Renew(ctx context.Context, db *sql.DB, id, owner string, until time.Time) error {
	r, err := db.ExecContext(ctx, "UPDATE runs SET lease_until=? WHERE run_id=? AND lease_owner=? AND state IN ('analysis_leased','report_leased')", until.Unix(), id, owner)
	if err != nil {
		return fmt.Errorf("renew lease: %w", err)
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return errors.New("lease not owned")
	}
	return nil
}
func Retry(ctx context.Context, db *sql.DB, id, phase, message string, notBefore time.Time, max int) error {
	if len(message) > 1024 {
		message = message[:1024]
	}
	column, next, dead := "analysis_attempts", "queued", "analysis_dead"
	if phase == "report" {
		column, next, dead = "report_attempts", "report_pending", "report_dead"
	}
	q := fmt.Sprintf("UPDATE runs SET state=CASE WHEN %s+1>=? THEN ? ELSE ? END,%s=%s+1,not_before=?,last_error=?,lease_owner=NULL,lease_until=NULL WHERE run_id=?", column, column, column)
	_, err := db.ExecContext(ctx, q, max, dead, next, notBefore.Unix(), message, id)
	if err != nil {
		return fmt.Errorf("retry run: %w", err)
	}
	return nil
}
func FinishReport(ctx context.Context, db *sql.DB, id, owner, state string) error {
	if state != "complete" && state != "reply_suppressed" {
		return errors.New("invalid report terminal state")
	}
	r, err := db.ExecContext(ctx, "UPDATE runs SET state=?,lease_owner=NULL,lease_until=NULL WHERE run_id=? AND state='report_leased' AND lease_owner=?", state, id, owner)
	if err != nil {
		return fmt.Errorf("finish report: %w", err)
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return errors.New("report lease not owned")
	}
	return nil
}

func Replay(ctx context.Context, db *sql.DB, deliveryID, runID string, now time.Time) error {
	_, err := db.ExecContext(ctx, `INSERT INTO runs(run_id,delivery_id,state,created_at) VALUES(?,?,?,?)`, runID, deliveryID, Queued, now.Unix())
	if err != nil {
		return fmt.Errorf("replay run: %w", err)
	}
	return nil
}
