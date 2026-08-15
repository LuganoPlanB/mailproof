package analytics

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// ProjectOnce advances the durable cursor atomically with minute/hour/day rollups.
func ProjectOnce(ctx context.Context, db *sql.DB, batch int) (int, error) {
	if batch < 1 || batch > 1000 {
		return 0, fmt.Errorf("batch size must be 1..1000")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var cursor int64
	if err := tx.QueryRowContext(ctx, `SELECT event_id FROM analytics_cursor WHERE singleton=1`).Scan(&cursor); err != nil {
		return 0, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT event_id,occurred_at,event_type,outcome,dimension_key FROM analytics_events WHERE event_id>? ORDER BY event_id LIMIT ?`, cursor, batch)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var id, at int64
		var metric, outcome, dimensions string
		if err := rows.Scan(&id, &at, &metric, &outcome, &dimensions); err != nil {
			return 0, err
		}
		t := time.Unix(at, 0).UTC()
		for _, level := range []struct {
			name string
			d    time.Duration
		}{{"minute", time.Minute}, {"hour", time.Hour}, {"day", 24 * time.Hour}} {
			bucket := t.Truncate(level.d).Unix()
			if _, err := tx.ExecContext(ctx, `INSERT INTO metric_rollups(bucket_start,granularity,metric,outcome,schema_version,event_count,source_high_watermark,dimension_key) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(bucket_start,granularity,metric,outcome,schema_version,dimension_key) DO UPDATE SET event_count=event_count+1,source_high_watermark=MAX(source_high_watermark,excluded.source_high_watermark)`, bucket, level.name, metric, outcome, SchemaVersion, 1, id, dimensions); err != nil {
				return 0, err
			}
		}
		cursor = id
		count++
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if count > 0 {
		if _, err := tx.ExecContext(ctx, `UPDATE analytics_cursor SET event_id=? WHERE singleton=1`, cursor); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return count, nil
}

// RebuildWindow atomically replaces only buckets touched by [from,to). It does
// not alter the global cursor, so a failed rebuild leaves active projections
// unchanged and unrelated history intact.
func RebuildWindow(ctx context.Context, db *sql.DB, from, to time.Time) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, level := range []struct {
		name string
		d    time.Duration
	}{{"minute", time.Minute}, {"hour", time.Hour}, {"day", 24 * time.Hour}} {
		if _, err := tx.ExecContext(ctx, "DELETE FROM metric_rollups WHERE granularity=? AND bucket_start>=? AND bucket_start<?", level.name, from.Truncate(level.d).Unix(), to.Truncate(level.d).Unix()); err != nil {
			return err
		}
	}
	rows, err := tx.QueryContext(ctx, "SELECT event_id,occurred_at,event_type,outcome,dimension_key FROM analytics_events WHERE occurred_at>=? AND occurred_at<? ORDER BY event_id", from.Unix(), to.Unix())
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, at int64
		var metric, outcome, dims string
		if err := rows.Scan(&id, &at, &metric, &outcome, &dims); err != nil {
			return err
		}
		t := time.Unix(at, 0).UTC()
		for _, level := range []struct {
			name string
			d    time.Duration
		}{{"minute", time.Minute}, {"hour", time.Hour}, {"day", 24 * time.Hour}} {
			if _, err := tx.ExecContext(ctx, `INSERT INTO metric_rollups(bucket_start,granularity,metric,outcome,schema_version,event_count,source_high_watermark,dimension_key) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(bucket_start,granularity,metric,outcome,schema_version,dimension_key) DO UPDATE SET event_count=event_count+1,source_high_watermark=MAX(source_high_watermark,excluded.source_high_watermark)`, t.Truncate(level.d).Unix(), level.name, metric, outcome, SchemaVersion, 1, id, dims); err != nil {
				return err
			}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return tx.Commit()
}
