// Package analytics owns privacy-safe, append-only lifecycle measurements.
package analytics

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const SchemaVersion = 1

// Event is deliberately unable to carry arbitrary dimensions or payloads.
// Source IDs are opaque service identifiers, never addresses or mail content.
type Event struct {
	Producer, SourceType, SourceID, Type string
	Outcome                              string
	OccurredAt                           time.Time
	DurationMS                           int64
	Dimensions                           Dimensions
}

// Dimensions is a closed, privacy-safe vocabulary. It deliberately has no
// free-form labels, addresses, message content, IPs, URLs, or capabilities.
type Dimensions struct{ PolicyVersion, Stage, Reason, Queue, Worker, Analyzer, State string }

func (d Dimensions) key() (string, error) {
	valid := func(v string, values ...string) bool {
		if v == "" {
			return true
		}
		for _, x := range values {
			if v == x {
				return true
			}
		}
		return false
	}
	if !valid(d.PolicyVersion, "v1") || !valid(d.Stage, "admission", "quota", "post_data", "subject_preflight") || !valid(d.Reason, "admitted", "rejected", "deferred", "quota_exceeded", "wrapper_sender_invalid", "selected_subject_ambiguous", "selected_subject_sender_denied", "analysis_dead", "report_dead") || !valid(d.Queue, "analysis", "report") || !valid(d.Worker, "analysis", "report") || !valid(d.Analyzer, "rspamd", "subject-selection") || !valid(d.State, "queued", "analysis_leased", "report_pending", "report_leased", "complete", "reply_suppressed", "analysis_dead", "report_dead", "started", "accepted", "failed", "unknown", "pending") {
		return "", errors.New("invalid analytics dimension")
	}
	b, e := json.Marshal(d)
	return string(b), e
}

func NewLifecycle(producer, sourceType, sourceID, eventType, outcome string, occurredAt time.Time) (Event, error) {
	if producer == "" || sourceID == "" || !allowed(producer, sourceType, eventType, outcome) {
		return Event{}, errors.New("invalid analytics lifecycle event")
	}
	return Event{Producer: producer, SourceType: sourceType, SourceID: sourceID, Type: eventType, Outcome: outcome, OccurredAt: occurredAt.UTC()}, nil
}

func allowed(producer, sourceType, eventType, outcome string) bool {
	if sourceType != "run" && sourceType != "delivery" && sourceType != "decision" {
		return false
	}
	if outcome == "" || len(outcome) > 64 {
		return false
	}
	switch producer {
	case "collector":
		return eventType == "subject_preflight"
	case "queue":
		return eventType == "run_started" || eventType == "run_lifecycle"
	case "admission":
		return eventType == "admission_decision"
	case "worker":
		return eventType == "run_completed" || eventType == "analyzer_observation"
	case "reporter":
		return eventType == "report_delivery_state" || eventType == "rejection_delivery_state"
	}
	return false
}

// InsertTx is the transaction-scoped driven port used by lifecycle owners.
func InsertTx(ctx context.Context, tx *sql.Tx, event Event) error {
	dimensionKey, err := event.Dimensions.key()
	if err != nil {
		return err
	}
	b, err := json.Marshal(struct {
		Producer, SourceType, SourceID, Type, Outcome string
		Schema                                        int        `json:"schema"`
		Dimensions                                    Dimensions `json:"dimensions"`
	}{event.Producer, event.SourceType, event.SourceID, event.Type, event.Outcome, SchemaVersion, event.Dimensions})
	if err != nil {
		return fmt.Errorf("canonical analytics event: %w", err)
	}
	digest := sha256.Sum256(b)
	if event.DurationMS < 0 || event.DurationMS > 86_400_000 {
		return errors.New("invalid analytics duration")
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO analytics_events(producer,source_type,source_id,event_type,schema_version,occurred_at,outcome,dimension_key,duration_ms,payload_digest) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(producer,source_type,source_id,event_type,schema_version) DO NOTHING`, event.Producer, event.SourceType, event.SourceID, event.Type, SchemaVersion, event.OccurredAt.Unix(), event.Outcome, dimensionKey, event.DurationMS, hex.EncodeToString(digest[:]))
	if err != nil {
		return fmt.Errorf("insert analytics event: %w", err)
	}
	return nil
}
