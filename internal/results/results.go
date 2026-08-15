// Package results defines privacy-reduced immutable read projections and their
// bounded repository queries. It deliberately has no dependency on HTTP or
// queue lifecycle code, so projections remain usable from the CLI and tests.
package results

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	MaxPageSize = 100
	maxRange    = 366 * 24 * time.Hour
)

var (
	ErrInvalidQuery  = errors.New("invalid results query")
	ErrInvalidCursor = errors.New("invalid results cursor")
)

type Record struct {
	RunID, DeliveryID, SubmitterID, Verdict, PolicyVersion, SchemaVersion, AuthScope string
	OccurredAt                                                                       time.Time
	SelectedSubjectStatus, RiskSummary, CategorySummary                              string
	UnavailableAnalyzers                                                             int
	ManifestDigest, ManifestPath, SourceArtifactDigests                              string
}

// InsertRecord is idempotent only for equivalent immutable facts. A different
// projection for a run is a conflict rather than an overwrite.
func InsertRecord(ctx context.Context, db *sql.DB, r Record) error {
	if r.RunID == "" || r.DeliveryID == "" || r.OccurredAt.IsZero() || r.Verdict == "" || r.ManifestDigest == "" || r.ManifestPath == "" || r.UnavailableAnalyzers < 0 {
		return ErrInvalidQuery
	}
	q := `INSERT INTO result_records(run_id,delivery_id,submitter_id,occurred_at,verdict,policy_version,schema_version,auth_scope,selected_subject_status,unavailable_analyzers,risk_summary,category_summary,manifest_digest,manifest_path,source_artifact_digests,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(run_id) DO NOTHING`
	res, err := db.ExecContext(ctx, q, r.RunID, r.DeliveryID, nullable(r.SubmitterID), r.OccurredAt.UTC().Unix(), r.Verdict, r.PolicyVersion, r.SchemaVersion, r.AuthScope, r.SelectedSubjectStatus, r.UnavailableAnalyzers, r.RiskSummary, r.CategorySummary, r.ManifestDigest, r.ManifestPath, r.SourceArtifactDigests, time.Now().UTC().Unix())
	if err != nil {
		return fmt.Errorf("insert result record: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("result rows affected: %w", err)
	}
	if n == 1 {
		return nil
	}
	var old Record
	var oldAt int64
	err = db.QueryRowContext(ctx, `SELECT run_id,delivery_id,COALESCE(submitter_id,''),occurred_at,verdict,policy_version,schema_version,auth_scope,selected_subject_status,unavailable_analyzers,risk_summary,category_summary,manifest_digest,manifest_path,source_artifact_digests FROM result_records WHERE run_id=?`, r.RunID).Scan(&old.RunID, &old.DeliveryID, &old.SubmitterID, &oldAt, &old.Verdict, &old.PolicyVersion, &old.SchemaVersion, &old.AuthScope, &old.SelectedSubjectStatus, &old.UnavailableAnalyzers, &old.RiskSummary, &old.CategorySummary, &old.ManifestDigest, &old.ManifestPath, &old.SourceArtifactDigests)
	if err != nil {
		return fmt.Errorf("read existing result record: %w", err)
	}
	old.OccurredAt = time.Unix(oldAt, 0).UTC()
	if old.DeliveryID == r.DeliveryID && old.Verdict == r.Verdict && old.ManifestDigest == r.ManifestDigest && old.ManifestPath == r.ManifestPath {
		return nil
	}
	return errors.New("conflicting immutable result record")
}

type Decision struct {
	ID, SubmissionID, DeliveryID, SubmitterID                        string
	OccurredAt                                                       time.Time
	Outcome, Stage, ReasonCode, PolicyVersion, SelectedSubjectDomain string
	SMTPClass                                                        int
	CanonicalJSON                                                    json.RawMessage
	CanonicalDigest, NotarizationStatus                              string
}

func InsertDecision(ctx context.Context, db *sql.DB, d Decision) error {
	if d.ID == "" || d.OccurredAt.IsZero() || d.Outcome == "" || d.Stage == "" || d.ReasonCode == "" || d.PolicyVersion == "" || len(d.CanonicalJSON) == 0 || d.CanonicalDigest == "" || d.NotarizationStatus == "" {
		return ErrInvalidQuery
	}
	_, err := db.ExecContext(ctx, `INSERT INTO decision_records(decision_id,submission_id,delivery_id,submitter_id,occurred_at,outcome,stage,reason_code,policy_version,selected_subject_domain,smtp_class,canonical_json,canonical_digest,notarization_status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(decision_id) DO NOTHING`, d.ID, nullable(d.SubmissionID), nullable(d.DeliveryID), nullable(d.SubmitterID), d.OccurredAt.UTC().Unix(), d.Outcome, d.Stage, d.ReasonCode, d.PolicyVersion, d.SelectedSubjectDomain, d.SMTPClass, []byte(d.CanonicalJSON), d.CanonicalDigest, d.NotarizationStatus)
	if err != nil {
		return fmt.Errorf("insert decision record: %w", err)
	}
	return nil
}

type Filter struct {
	ID, SubmitterID, Outcome, Stage, Reason, Verdict, PolicyVersion, SubjectDomain string
	From, To                                                                       time.Time
	Limit                                                                          int
	Cursor                                                                         string
}
type Page[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
}
type Repository struct {
	DB        *sql.DB
	CursorKey []byte
	Now       func() time.Time
}

type SummaryBucket struct {
	Start time.Time `json:"start"`
	Kind  string    `json:"kind"`
	Count int       `json:"count"`
}

// Summary returns non-sensitive outcome and verdict counts with fixed UTC bins.
func (r Repository) Summary(ctx context.Context, from, to time.Time, interval string) ([]SummaryBucket, error) {
	if from.IsZero() || to.IsZero() {
		return nil, ErrInvalidQuery
	}
	if _, err := r.validate(Filter{From: from, To: to}); err != nil {
		return nil, err
	}
	if interval != "hour" && interval != "day" {
		return nil, ErrInvalidQuery
	}
	format := "%Y-%m-%dT%H:00:00Z"
	if interval == "day" {
		format = "%Y-%m-%dT00:00:00Z"
	}
	rows, err := r.DB.QueryContext(ctx, `SELECT bucket,kind,COUNT(*) FROM (SELECT strftime(?,occurred_at,'unixepoch') AS bucket,verdict AS kind FROM result_records WHERE occurred_at>=? AND occurred_at<=? UNION ALL SELECT strftime(?,occurred_at,'unixepoch'),outcome||':'||stage||':'||reason_code FROM decision_records WHERE occurred_at>=? AND occurred_at<=?) GROUP BY bucket,kind ORDER BY bucket,kind`, format, from.UTC().Unix(), to.UTC().Unix(), format, from.UTC().Unix(), to.UTC().Unix())
	if err != nil {
		return nil, fmt.Errorf("summary query: %w", err)
	}
	defer rows.Close()
	var out []SummaryBucket
	for rows.Next() {
		var raw string
		var b SummaryBucket
		if err := rows.Scan(&raw, &b.Kind, &b.Count); err != nil {
			return nil, err
		}
		at, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return nil, err
		}
		b.Start = at
		out = append(out, b)
	}
	return out, rows.Err()
}

func (r Repository) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}
func (r Repository) validate(f Filter) (int, error) {
	if r.DB == nil || len(r.CursorKey) < 32 {
		return 0, ErrInvalidQuery
	}
	n := f.Limit
	if n == 0 {
		n = 50
	}
	if n < 1 || n > MaxPageSize || (!f.From.IsZero() && !f.To.IsZero() && (f.To.Before(f.From) || f.To.Sub(f.From) > maxRange)) || len(f.Cursor) > 1024 || len(f.ID) > 256 || len(f.SubmitterID) > 256 || len(f.Outcome) > 64 || len(f.Stage) > 64 || len(f.Reason) > 128 || len(f.Verdict) > 64 || len(f.PolicyVersion) > 64 || len(f.SubjectDomain) > 253 {
		return 0, ErrInvalidQuery
	}
	return n, nil
}

type cursor struct {
	At   int64  `json:"at"`
	ID   string `json:"id"`
	Exp  int64  `json:"exp"`
	Kind string `json:"kind"`
}

func (r Repository) cursorFor(kind, id string, at time.Time) string {
	c := cursor{at.UTC().Unix(), id, r.now().Add(24 * time.Hour).Unix(), kind}
	b, _ := json.Marshal(c)
	mac := hmac.New(sha256.New, r.CursorKey)
	mac.Write(b)
	return base64.RawURLEncoding.EncodeToString(append(b, mac.Sum(nil)...))
}
func (r Repository) parseCursor(kind, raw string) (cursor, error) {
	var z cursor
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(b) <= sha256.Size {
		return z, ErrInvalidCursor
	}
	body, tag := b[:len(b)-sha256.Size], b[len(b)-sha256.Size:]
	mac := hmac.New(sha256.New, r.CursorKey)
	mac.Write(body)
	if !hmac.Equal(tag, mac.Sum(nil)) || json.Unmarshal(body, &z) != nil || z.Kind != kind || z.ID == "" || z.Exp < r.now().Unix() {
		return z, ErrInvalidCursor
	}
	return z, nil
}

func (r Repository) Results(ctx context.Context, f Filter) (Page[Record], error) {
	n, err := r.validate(f)
	if err != nil {
		return Page[Record]{}, err
	}
	args := []any{}
	where := []string{"1=1"}
	add := func(q, v string) {
		if v != "" {
			where = append(where, q)
			args = append(args, v)
		}
	}
	add("run_id=?", f.ID)
	add("submitter_id=?", f.SubmitterID)
	add("verdict=?", f.Verdict)
	add("policy_version=?", f.PolicyVersion)
	if !f.From.IsZero() {
		where = append(where, "occurred_at>=?")
		args = append(args, f.From.UTC().Unix())
	}
	if !f.To.IsZero() {
		where = append(where, "occurred_at<=?")
		args = append(args, f.To.UTC().Unix())
	}
	if f.Cursor != "" {
		c, e := r.parseCursor("result", f.Cursor)
		if e != nil {
			return Page[Record]{}, e
		}
		where = append(where, "(occurred_at < ? OR (occurred_at=? AND run_id < ?))")
		args = append(args, c.At, c.At, c.ID)
	}
	args = append(args, n+1)
	rows, e := r.DB.QueryContext(ctx, `SELECT run_id,delivery_id,COALESCE(submitter_id,''),occurred_at,verdict,policy_version,schema_version,auth_scope,selected_subject_status,unavailable_analyzers,risk_summary,category_summary,manifest_digest,manifest_path,source_artifact_digests FROM result_records WHERE `+strings.Join(where, " AND ")+` ORDER BY occurred_at DESC,run_id DESC LIMIT ?`, args...)
	if e != nil {
		return Page[Record]{}, fmt.Errorf("query results: %w", e)
	}
	defer rows.Close()
	p := Page[Record]{}
	for rows.Next() {
		var x Record
		var at int64
		if e = rows.Scan(&x.RunID, &x.DeliveryID, &x.SubmitterID, &at, &x.Verdict, &x.PolicyVersion, &x.SchemaVersion, &x.AuthScope, &x.SelectedSubjectStatus, &x.UnavailableAnalyzers, &x.RiskSummary, &x.CategorySummary, &x.ManifestDigest, &x.ManifestPath, &x.SourceArtifactDigests); e != nil {
			return p, e
		}
		x.OccurredAt = time.Unix(at, 0).UTC()
		p.Items = append(p.Items, x)
	}
	if e = rows.Err(); e != nil {
		return p, e
	}
	if len(p.Items) > n {
		last := p.Items[n-1]
		p.Items = p.Items[:n]
		p.NextCursor = r.cursorFor("result", last.RunID, last.OccurredAt)
	}
	return p, nil
}

func (r Repository) Decisions(ctx context.Context, f Filter) (Page[Decision], error) {
	n, err := r.validate(f)
	if err != nil {
		return Page[Decision]{}, err
	}
	args := []any{}
	where := []string{"1=1"}
	add := func(q, v string) {
		if v != "" {
			where = append(where, q)
			args = append(args, v)
		}
	}
	add("decision_id=?", f.ID)
	add("submitter_id=?", f.SubmitterID)
	add("outcome=?", f.Outcome)
	add("stage=?", f.Stage)
	add("reason_code=?", f.Reason)
	add("policy_version=?", f.PolicyVersion)
	add("selected_subject_domain=?", f.SubjectDomain)
	if !f.From.IsZero() {
		where = append(where, "occurred_at>=?")
		args = append(args, f.From.UTC().Unix())
	}
	if !f.To.IsZero() {
		where = append(where, "occurred_at<=?")
		args = append(args, f.To.UTC().Unix())
	}
	if f.Cursor != "" {
		c, e := r.parseCursor("decision", f.Cursor)
		if e != nil {
			return Page[Decision]{}, e
		}
		where = append(where, "(occurred_at < ? OR (occurred_at=? AND decision_id < ?))")
		args = append(args, c.At, c.At, c.ID)
	}
	args = append(args, n+1)
	rows, e := r.DB.QueryContext(ctx, `SELECT decision_id,COALESCE(submission_id,''),COALESCE(delivery_id,''),COALESCE(submitter_id,''),occurred_at,outcome,stage,reason_code,policy_version,selected_subject_domain,smtp_class,canonical_json,canonical_digest,notarization_status FROM decision_records WHERE `+strings.Join(where, " AND ")+` ORDER BY occurred_at DESC,decision_id DESC LIMIT ?`, args...)
	if e != nil {
		return Page[Decision]{}, fmt.Errorf("query decisions: %w", e)
	}
	defer rows.Close()
	p := Page[Decision]{}
	for rows.Next() {
		var x Decision
		var at int64
		if e = rows.Scan(&x.ID, &x.SubmissionID, &x.DeliveryID, &x.SubmitterID, &at, &x.Outcome, &x.Stage, &x.ReasonCode, &x.PolicyVersion, &x.SelectedSubjectDomain, &x.SMTPClass, &x.CanonicalJSON, &x.CanonicalDigest, &x.NotarizationStatus); e != nil {
			return p, e
		}
		x.OccurredAt = time.Unix(at, 0).UTC()
		p.Items = append(p.Items, x)
	}
	if e = rows.Err(); e != nil {
		return p, e
	}
	if len(p.Items) > n {
		last := p.Items[n-1]
		p.Items = p.Items[:n]
		p.NextCursor = r.cursorFor("decision", last.ID, last.OccurredAt)
	}
	return p, nil
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
