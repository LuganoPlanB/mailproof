package results

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// API is the internal driver adapter. It intentionally exposes projections,
// never raw artifacts, SMTP facts, capabilities, or report destinations.
type API struct {
	Repository Repository
	Token      []byte
}

func (a API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.health)
	mux.HandleFunc("GET /v1/results", a.results)
	mux.HandleFunc("GET /v1/results/", a.result)
	mux.HandleFunc("GET /v1/decisions", a.decisions)
	mux.HandleFunc("GET /v1/decisions/", a.decision)
	mux.HandleFunc("GET /v1/analytics/summary", a.summary)
	return securityHeaders(auth(a.Token, mux))
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
	if err == ErrInvalidQuery || err == ErrInvalidCursor {
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
