package results

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/luganoplanb/mailproof/internal/analytics"
)

// API is the internal driver adapter. It intentionally exposes projections,
// never raw artifacts, SMTP facts, capabilities, or report destinations.
type API struct {
	Repository Repository
	Dashboard  Dashboard
	Token      []byte
}

// Dashboard is the narrow analytics read port consumed by the internal HTTP
// adapter. Keeping it here makes the driver testable without SQLite access.
type Dashboard interface {
	Overview(context.Context, analytics.Query) (analytics.Snapshot, error)
	Funnel(context.Context, analytics.Query) (analytics.Snapshot, error)
	Series(context.Context, analytics.Query) (analytics.Snapshot, error)
	Operations(context.Context, analytics.Query) (analytics.Snapshot, error)
}

func (a API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.health)
	mux.HandleFunc("GET /v1/results", a.results)
	mux.HandleFunc("GET /v1/results/", a.result)
	mux.HandleFunc("GET /v1/decisions", a.decisions)
	mux.HandleFunc("GET /v1/decisions/", a.decision)
	mux.HandleFunc("GET /v1/analytics/summary", a.summary)
	mux.HandleFunc("GET /v1/dashboard/overview", a.overview)
	mux.HandleFunc("GET /v1/dashboard/funnel", a.funnel)
	mux.HandleFunc("GET /v1/dashboard/series", a.series)
	mux.HandleFunc("GET /v1/dashboard/operations", a.operations)
	mux.HandleFunc("GET /v1/campaigns", a.campaigns)
	mux.HandleFunc("GET /v1/campaigns/", a.campaign)
	return securityHeaders(auth(a.Token, mux))
}
func (a API) campaigns(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if !onlyQuery(q, "status", "projection_version", "cursor", "limit") {
		writeQueryError(w, ErrInvalidQuery)
		return
	}
	limit, err := pageLimit(q.Get("limit"))
	if err != nil {
		writeQueryError(w, err)
		return
	}
	p, err := a.Repository.Campaigns(r.Context(), CampaignFilter{Status: q.Get("status"), ProjectionVersion: q.Get("projection_version"), Cursor: q.Get("cursor"), Limit: limit})
	if err != nil {
		writeQueryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"schema_version": "mailproof.campaigns/v1", "items": p.Items, "next_cursor": p.NextCursor})
}
func (a API) campaign(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/campaigns/"), "/")
	if len(parts) < 1 || parts[0] == "" || len(parts) > 2 {
		writeQueryError(w, ErrInvalidQuery)
		return
	}
	if len(parts) == 1 {
		q := r.URL.Query()
		if !onlyQuery(q, "projection_version") || q.Get("projection_version") == "" {
			writeQueryError(w, ErrInvalidQuery)
			return
		}
		detail, err := a.Repository.CampaignDetail(r.Context(), parts[0], q.Get("projection_version"))
		if err != nil {
			writeQueryError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"schema_version": "mailproof.campaign/v1", "data": detail})
		return
	}
	if parts[1] != "members" {
		writeQueryError(w, ErrInvalidQuery)
		return
	}
	q := r.URL.Query()
	if !onlyQuery(q, "projection_version", "cursor", "limit") || q.Get("projection_version") == "" {
		writeQueryError(w, ErrInvalidQuery)
		return
	}
	limit, err := pageLimit(q.Get("limit"))
	if err != nil {
		writeQueryError(w, err)
		return
	}
	p, err := a.Repository.CampaignMembers(r.Context(), parts[0], q.Get("projection_version"), q.Get("cursor"), limit)
	if err != nil {
		writeQueryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"schema_version": "mailproof.campaign-members/v1", "items": p.Items, "next_cursor": p.NextCursor})
}

func pageLimit(raw string) (int, error) {
	if raw == "" {
		return 50, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > MaxPageSize {
		return 0, ErrInvalidQuery
	}
	return n, nil
}

func onlyQuery(q map[string][]string, names ...string) bool {
	allowed := make(map[string]bool, len(names))
	for _, name := range names {
		allowed[name] = true
	}
	for name, values := range q {
		if !allowed[name] || len(values) != 1 {
			return false
		}
	}
	return true
}

func (a API) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
func (a API) results(w http.ResponseWriter, r *http.Request) {
	f, err := filter(r)
	if err == nil {
		var p Page[Record]
		p, err = a.Repository.Results(r.Context(), f)
		if err == nil {
			writeJSON(w, http.StatusOK, p)
			return
		}
	}
	writeQueryError(w, err)
}
func (a API) decisions(w http.ResponseWriter, r *http.Request) {
	f, err := filter(r)
	if err == nil {
		var p Page[Decision]
		p, err = a.Repository.Decisions(r.Context(), f)
		if err == nil {
			writeJSON(w, http.StatusOK, p)
			return
		}
	}
	writeQueryError(w, err)
}
func (a API) result(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/results/")
	if id == "" || strings.Contains(id, "/") {
		writeQueryError(w, ErrInvalidQuery)
		return
	}
	q := r.URL.Query()
	q.Set("id", id)
	r.URL.RawQuery = q.Encode()
	a.results(w, r)
}
func (a API) decision(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/decisions/")
	if id == "" || strings.Contains(id, "/") {
		writeQueryError(w, ErrInvalidQuery)
		return
	}
	q := r.URL.Query()
	q.Set("id", id)
	r.URL.RawQuery = q.Encode()
	a.decisions(w, r)
}
func (a API) summary(w http.ResponseWriter, r *http.Request) {
	f, err := filter(r)
	if err == nil {
		interval := r.URL.Query().Get("interval")
		var buckets []SummaryBucket
		buckets, err = a.Repository.Summary(r.Context(), f.From, f.To, interval)
		if err == nil {
			writeJSON(w, http.StatusOK, map[string]any{"items": buckets})
			return
		}
	}
	writeQueryError(w, err)
}

func (a API) overview(w http.ResponseWriter, r *http.Request)   { a.dashboard(w, r, "overview") }
func (a API) funnel(w http.ResponseWriter, r *http.Request)     { a.dashboard(w, r, "funnel") }
func (a API) series(w http.ResponseWriter, r *http.Request)     { a.dashboard(w, r, "series") }
func (a API) operations(w http.ResponseWriter, r *http.Request) { a.dashboard(w, r, "operations") }

func (a API) dashboard(w http.ResponseWriter, r *http.Request, kind string) {
	q, err := dashboardQuery(r)
	if err == nil && a.Dashboard != nil {
		var snapshot analytics.Snapshot
		switch kind {
		case "overview":
			snapshot, err = a.Dashboard.Overview(r.Context(), q)
		case "funnel":
			snapshot, err = a.Dashboard.Funnel(r.Context(), q)
		case "series":
			snapshot, err = a.Dashboard.Series(r.Context(), q)
		case "operations":
			snapshot, err = a.Dashboard.Operations(r.Context(), q)
		}
		if err == nil {
			writeJSON(w, http.StatusOK, map[string]any{"schema_version": 1, "filters": q, "generated_at": snapshot.GeneratedAt, "data_through": snapshot.DataThrough, "observed_at": snapshot.ObservedAt, "high_watermark": snapshot.HighWatermark, "projection_lag_seconds": snapshot.ProjectionLag, "p95_latency_ms": snapshot.P95LatencyMS, "latency_known": snapshot.LatencyKnown, "partial": snapshot.Partial, "stale": snapshot.Stale, "values": snapshot.Values, "buckets": snapshot.Buckets})
			return
		}
	}
	writeQueryError(w, err)
}

func dashboardQuery(r *http.Request) (analytics.Query, error) {
	q := r.URL.Query()
	known := map[string]bool{"from": true, "to": true, "interval": true, "metric": true, "dimension": true, "series": true, "cards": true}
	for k, values := range q {
		if !known[k] || len(values) != 1 {
			return analytics.Query{}, analytics.ErrInvalidQuery
		}
	}
	from, err := time.Parse(time.RFC3339, q.Get("from"))
	if err != nil {
		return analytics.Query{}, analytics.ErrInvalidQuery
	}
	to, err := time.Parse(time.RFC3339, q.Get("to"))
	if err != nil {
		return analytics.Query{}, analytics.ErrInvalidQuery
	}
	split := func(raw string) []string {
		if raw == "" {
			return nil
		}
		return strings.Split(raw, ",")
	}
	return analytics.Query{From: from, To: to, Interval: q.Get("interval"), Metric: q.Get("metric"), Dimension: q.Get("dimension"), Series: split(q.Get("series")), Cards: split(q.Get("cards"))}, nil
}

func filter(r *http.Request) (Filter, error) {
	q := r.URL.Query()
	known := map[string]bool{"id": true, "submitter_id": true, "outcome": true, "stage": true, "reason": true, "verdict": true, "policy_version": true, "selected_subject_domain": true, "from": true, "to": true, "limit": true, "cursor": true, "interval": true}
	for k := range q {
		if !known[k] || len(q[k]) != 1 {
			return Filter{}, ErrInvalidQuery
		}
	}
	f := Filter{ID: q.Get("id"), SubmitterID: q.Get("submitter_id"), Outcome: q.Get("outcome"), Stage: q.Get("stage"), Reason: q.Get("reason"), Verdict: q.Get("verdict"), PolicyVersion: q.Get("policy_version"), SubjectDomain: q.Get("selected_subject_domain"), Cursor: q.Get("cursor")}
	if raw := q.Get("from"); raw != "" {
		v, e := time.Parse(time.RFC3339, raw)
		if e != nil {
			return f, ErrInvalidQuery
		}
		f.From = v
	}
	if raw := q.Get("to"); raw != "" {
		v, e := time.Parse(time.RFC3339, raw)
		if e != nil {
			return f, ErrInvalidQuery
		}
		f.To = v
	}
	if raw := q.Get("limit"); raw != "" {
		var n int
		if _, e := fmtSscanf(raw, &n); e != nil {
			return f, ErrInvalidQuery
		}
		f.Limit = n
	}
	return f, nil
}

// fmtSscanf is retained as a tiny seam to keep request parsing testable.
var fmtSscanf = func(s string, n *int) (int, error) { return fmt.Sscanf(s, "%d", n) }

func auth(token []byte, next http.Handler) http.Handler {
	digest := sha256.Sum256(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		raw := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if len(token) < 32 || !strings.HasPrefix(raw, prefix) {
			genericUnauthorized(w)
			return
		}
		candidate := sha256.Sum256([]byte(strings.TrimPrefix(raw, prefix)))
		if hmac.Equal(digest[:], candidate[:]) {
			next.ServeHTTP(w, r)
			return
		}
		genericUnauthorized(w)
	})
}
func genericUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}
func writeQueryError(w http.ResponseWriter, err error) {
	if err == ErrInvalidQuery || err == ErrInvalidCursor || err == analytics.ErrInvalidQuery {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
