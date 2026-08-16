package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/luganoplanb/mailproof/internal/analytics"
	"github.com/luganoplanb/mailproof/internal/control"
)

// ResultsClient is the typed, server-to-server read port. Its token is never
// accepted from, exposed to, or selected by a browser request.
type ResultsClient struct {
	BaseURL *url.URL
	Token   []byte
	HTTP    *http.Client
}

type ControlClient struct {
	BaseURL *url.URL
	Token   []byte
	HTTP    *http.Client
}
type Policy struct {
	SchemaVersion string      `json:"schema_version"`
	PolicyVersion int64       `json:"policy_version"`
	Items         []Rule      `json:"items"`
	Submitters    []Submitter `json:"submitters"`
	Bootstrap     Bootstrap   `json:"bootstrap"`
}
type Rule struct {
	ID      string `json:"rule_id"`
	Type    string `json:"rule_type"`
	Subject string `json:"subject"`
	Value   string `json:"value"`
	Version int64  `json:"version"`
	Expiry  *int64 `json:"expires_at,omitempty"`
}
type Bootstrap struct {
	Imported     bool                  `json:"imported"`
	SourceDigest string                `json:"source_digest"`
	ImportedAt   int64                 `json:"imported_at"`
	Observation  *BootstrapObservation `json:"observation,omitempty"`
}
type BootstrapObservation struct {
	SourceDigest string `json:"source_digest"`
	SourceCount  int    `json:"source_count"`
	Outcome      string `json:"outcome"`
	ObservedAt   int64  `json:"observed_at"`
}
type Submitter struct {
	ID            string `json:"submitter_id"`
	Status        string `json:"status"`
	PolicyVersion string `json:"policy_version"`
	Minute        int    `json:"minute_limit"`
	Hour          int    `json:"hour_limit"`
	Day           int    `json:"day_limit"`
}
type Audit struct {
	SchemaVersion string       `json:"schema_version"`
	Items         []AuditEvent `json:"items"`
}
type AuditEvent struct {
	CommandID    string `json:"command_id"`
	Actor        string `json:"actor"`
	SessionID    string `json:"session_id"`
	CommandType  string `json:"command_type"`
	Result       string `json:"result_code"`
	BeforeDigest string `json:"before_digest"`
	AfterDigest  string `json:"after_digest"`
	Reason       string `json:"reason"`
	CreatedAt    int64  `json:"created_at"`
}

func (c ControlClient) call(ctx context.Context, method, path string, in, out any) error {
	if c.BaseURL == nil || len(c.Token) < 32 {
		return errors.New("dashboard control client unavailable")
	}
	var body io.Reader
	if in != nil {
		b, e := json.Marshal(in)
		if e != nil {
			return e
		}
		body = strings.NewReader(string(b))
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	u := c.BaseURL.ResolveReference(&url.URL{Path: path})
	req, e := http.NewRequestWithContext(ctx, method, u.String(), body)
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+string(c.Token))
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	resp, e := client.Do(req)
	if e != nil {
		return errors.New("dashboard control unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return errors.New("dashboard control rejected request")
	}
	d := json.NewDecoder(io.LimitReader(resp.Body, 2<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return errors.New("invalid dashboard control response")
	}
	return nil
}
func (c ControlClient) Policy(ctx context.Context) (Policy, error) {
	var v Policy
	err := c.call(ctx, http.MethodGet, "/v1/control/policy", nil, &v)
	if err == nil && (v.SchemaVersion != control.SchemaVersion || v.PolicyVersion < 0 || v.Items == nil || v.Submitters == nil) {
		err = errors.New("invalid dashboard control policy")
	}
	return v, err
}
func (c ControlClient) Audit(ctx context.Context) (Audit, error) {
	var v Audit
	err := c.call(ctx, http.MethodGet, "/v1/control/audit", nil, &v)
	if err == nil && v.SchemaVersion != control.SchemaVersion {
		err = errors.New("invalid dashboard control audit")
	}
	return v, err
}
func (c ControlClient) AuditDetail(ctx context.Context, commandID string) (AuditEvent, error) {
	audit, err := c.Audit(ctx)
	if err != nil {
		return AuditEvent{}, err
	}
	for _, event := range audit.Items {
		if event.CommandID == commandID {
			return event, nil
		}
	}
	return AuditEvent{}, errors.New("audit event not found")
}
func (c ControlClient) Preview(ctx context.Context, s string, cmd control.Command) (control.Preview, error) {
	var v control.Preview
	err := c.call(ctx, http.MethodPost, "/v1/control/previews", map[string]any{"session_id": s, "command": cmd}, &v)
	if err == nil && (v.SchemaVersion != control.SchemaVersion || !v.DryRun || v.ConfirmationToken == "" || v.BeforeDigest == "" || v.AfterDigest == "" || v.ExpiresAt.IsZero() || v.NextVersion < v.CurrentVersion) {
		err = errors.New("invalid dashboard control preview")
	}
	return v, err
}
func (c ControlClient) Confirm(ctx context.Context, x control.Confirmation) (control.Result, error) {
	var v control.Result
	err := c.call(ctx, http.MethodPost, "/v1/control/confirmations", x, &v)
	if err == nil && (v.SchemaVersion != control.SchemaVersion || v.CommandID == "" || v.ResultCode != "applied" || v.PolicyVersion < 0) {
		err = errors.New("invalid dashboard control confirmation")
	}
	return v, err
}

func (c ResultsClient) Snapshot(ctx context.Context, route string) (analytics.Snapshot, error) {
	if c.BaseURL == nil || len(c.Token) < 32 {
		return analytics.Snapshot{}, errors.New("dashboard results client is unavailable")
	}
	u := c.BaseURL.ResolveReference(&url.URL{Path: route})
	query := u.Query()
	now := time.Now().UTC().Truncate(time.Hour)
	query.Set("from", now.Add(-24*time.Hour).Format(time.RFC3339))
	query.Set("to", now.Format(time.RFC3339))
	query.Set("interval", "hour")
	u.RawQuery = query.Encode()
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return analytics.Snapshot{}, err
	}
	req.Header.Set("Authorization", "Bearer "+string(c.Token))
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return analytics.Snapshot{}, errors.New("dashboard upstream unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return analytics.Snapshot{}, errors.New("dashboard upstream unavailable")
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 2<<20))
	decoder.DisallowUnknownFields()
	var response struct {
		SchemaVersion int                `json:"schema_version"`
		Filters       analytics.Query    `json:"filters"`
		Values        []analytics.Value  `json:"values"`
		Buckets       []analytics.Bucket `json:"buckets"`
		GeneratedAt   time.Time          `json:"generated_at"`
		DataThrough   time.Time          `json:"data_through"`
		ObservedAt    time.Time          `json:"observed_at"`
		HighWatermark int64              `json:"high_watermark"`
		ProjectionLag int64              `json:"projection_lag_seconds"`
		P95LatencyMS  int64              `json:"p95_latency_ms"`
		LatencyKnown  bool               `json:"latency_known"`
		Partial       bool               `json:"partial"`
		Stale         bool               `json:"stale"`
	}
	if err := decoder.Decode(&response); err != nil {
		return analytics.Snapshot{}, fmt.Errorf("decode dashboard projection: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF || response.SchemaVersion != 1 {
		return analytics.Snapshot{}, errors.New("invalid dashboard projection")
	}
	return analytics.Snapshot{
		GeneratedAt:   response.GeneratedAt,
		DataThrough:   response.DataThrough,
		ObservedAt:    response.ObservedAt,
		HighWatermark: response.HighWatermark,
		ProjectionLag: response.ProjectionLag,
		P95LatencyMS:  response.P95LatencyMS,
		LatencyKnown:  response.LatencyKnown,
		Partial:       response.Partial,
		Stale:         response.Stale,
		Values:        response.Values,
		Buckets:       response.Buckets,
	}, nil
}
