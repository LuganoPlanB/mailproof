package control

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// API is the internal-only driver adapter; it deliberately has no browser or session state.
type API struct {
	Service Service
	Token   []byte
}

func (a API) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		write(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	m.HandleFunc("GET /v1/control/policy", a.policy)
	m.HandleFunc("GET /v1/control/audit", a.audit)
	m.HandleFunc("POST /v1/control/previews", a.preview)
	m.HandleFunc("POST /v1/control/confirmations", a.confirm)
	return a.auth(m)
}
func (a API) auth(next http.Handler) http.Handler {
	digest := sha256.Sum256(a.Token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		raw := r.Header.Get("Authorization")
		if len(a.Token) < 32 || !strings.HasPrefix(raw, "Bearer ") {
			failure(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		x := sha256.Sum256([]byte(strings.TrimPrefix(raw, "Bearer ")))
		if hmac.Equal(digest[:], x[:]) {
			next.ServeHTTP(w, r)
			return
		}
		failure(w, http.StatusUnauthorized, "unauthorized")
	})
}
func decode(r *http.Request, v any) error {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return ErrInvalid
	}
	r.Body = http.MaxBytesReader(nil, r.Body, 64<<10)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return ErrInvalid
	}
	var extra any
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}
func (a API) preview(w http.ResponseWriter, r *http.Request) {
	var in struct {
		SessionID string  `json:"session_id"`
		Command   Command `json:"command"`
	}
	if e := decode(r, &in); e == nil {
		var p Preview
		p, e = a.Service.Preview(r.Context(), in.SessionID, in.Command)
		if e == nil {
			write(w, http.StatusOK, p)
			return
		}
		writeError(w, e)
		return
	} else {
		writeError(w, e)
	}
}
func (a API) confirm(w http.ResponseWriter, r *http.Request) {
	var x Confirmation
	if e := decode(r, &x); e == nil {
		var out Result
		out, e = a.Service.Confirm(r.Context(), x)
		if e == nil {
			write(w, http.StatusOK, out)
			return
		}
		writeError(w, e)
		return
	} else {
		writeError(w, e)
	}
}
func (a API) policy(w http.ResponseWriter, r *http.Request) {
	if !boundedQuery(r, "limit") {
		failure(w, http.StatusBadRequest, "invalid_filter")
		return
	}
	var v int64
	if e := a.Service.DB.QueryRowContext(r.Context(), "SELECT MAX(version) FROM policy_versions").Scan(&v); e != nil {
		failure(w, 500, "internal_error")
		return
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, _ = strconv.Atoi(raw)
	}
	// Disabled rules remain historical audit evidence, but never appear in the
	// effective policy returned to an operator or used by admission.
	rows, e := a.Service.DB.QueryContext(r.Context(), "SELECT rule_id,rule_type,subject,value,version,expires_at FROM policy_rules WHERE enabled=1 AND (expires_at IS NULL OR expires_at>?) ORDER BY rule_type,rule_id LIMIT ?", time.Now().UTC().Unix(), limit)
	if e != nil {
		failure(w, 500, "internal_error")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, typ, subject, value string
		var version int64
		var expiry any
		if e = rows.Scan(&id, &typ, &subject, &value, &version, &expiry); e != nil {
			failure(w, 500, "internal_error")
			return
		}
		item := map[string]any{"rule_id": id, "rule_type": typ, "subject": subject, "value": value, "version": version}
		if expiry != nil {
			item["expires_at"] = expiry
		}
		items = append(items, item)
	}
	if e = rows.Err(); e != nil {
		failure(w, 500, "internal_error")
		return
	}
	submitters, e := a.Service.DB.QueryContext(r.Context(), "SELECT submitter_id,status,policy_version,minute_limit,hour_limit,day_limit FROM submitters ORDER BY submitter_id LIMIT ?", limit)
	if e != nil {
		failure(w, 500, "internal_error")
		return
	}
	defer submitters.Close()
	quotaItems := []map[string]any{}
	for submitters.Next() {
		var id, status, version string
		var minute, hour, day int
		if e = submitters.Scan(&id, &status, &version, &minute, &hour, &day); e != nil {
			failure(w, 500, "internal_error")
			return
		}
		quotaItems = append(quotaItems, map[string]any{"submitter_id": id, "status": status, "policy_version": version, "minute_limit": minute, "hour_limit": hour, "day_limit": day})
	}
	if e = submitters.Err(); e != nil {
		failure(w, 500, "internal_error")
		return
	}
	bootstrap := map[string]any{}
	var digest string
	var importedAt int64
	if e = a.Service.DB.QueryRowContext(r.Context(), "SELECT source_digest,imported_at FROM policy_bootstrap WHERE singleton=1").Scan(&digest, &importedAt); e == nil {
		bootstrap["imported"] = true
		bootstrap["source_digest"] = digest
		bootstrap["imported_at"] = importedAt
	} else if !errors.Is(e, sql.ErrNoRows) {
		failure(w, 500, "internal_error")
		return
	}
	var observedAt, count int64
	var outcome string
	if e = a.Service.DB.QueryRowContext(r.Context(), "SELECT source_digest,source_count,outcome,observed_at FROM policy_bootstrap_observations ORDER BY observation_id DESC LIMIT 1").Scan(&digest, &count, &outcome, &observedAt); e == nil {
		bootstrap["observation"] = map[string]any{"source_digest": digest, "source_count": count, "outcome": outcome, "observed_at": observedAt}
	} else if !errors.Is(e, sql.ErrNoRows) {
		failure(w, 500, "internal_error")
		return
	}
	write(w, http.StatusOK, map[string]any{"schema_version": SchemaVersion, "policy_version": v, "items": items, "submitters": quotaItems, "bootstrap": bootstrap})
}
func (a API) audit(w http.ResponseWriter, r *http.Request) {
	if !boundedQuery(r, "limit") {
		failure(w, http.StatusBadRequest, "invalid_filter")
		return
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, _ = strconv.Atoi(raw)
	}
	rows, e := a.Service.DB.QueryContext(r.Context(), "SELECT command_id,actor,session_id,command_type,result_code,before_digest,after_digest,reason,created_at FROM audit_events ORDER BY audit_id DESC LIMIT ?", limit)
	if e != nil {
		failure(w, 500, "internal_error")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var cmd, actor, session, typ, result, before, after, reason string
		var at int64
		if rows.Scan(&cmd, &actor, &session, &typ, &result, &before, &after, &reason, &at) != nil {
			failure(w, 500, "internal_error")
			return
		}
		items = append(items, map[string]any{"command_id": cmd, "actor": actor, "session_id": session, "command_type": typ, "result_code": result, "before_digest": before, "after_digest": after, "reason": reason, "created_at": at})
	}
	write(w, http.StatusOK, map[string]any{"schema_version": SchemaVersion, "items": items})
}
func boundedQuery(r *http.Request, allowed string) bool {
	q := r.URL.Query()
	for k, v := range q {
		if k != allowed || len(v) != 1 {
			return false
		}
	}
	if raw := q.Get("limit"); raw != "" {
		n, e := strconv.Atoi(raw)
		return e == nil && n > 0 && n <= 100
	}
	return true
}
func writeError(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, ErrInvalid):
		failure(w, 400, "invalid_request")
	case errors.Is(e, ErrExpired):
		failure(w, 409, "preview_expired")
	case errors.Is(e, ErrConflict):
		failure(w, 409, "policy_version_conflict")
	case errors.Is(e, ErrReplay):
		failure(w, 409, "idempotency_replayed")
	case errors.Is(e, ErrUnsupported):
		failure(w, 400, "unsupported_command")
	default:
		failure(w, 500, "internal_error")
	}
}
func failure(w http.ResponseWriter, status int, code string) {
	write(w, status, map[string]string{"schema_version": "mailproof.error/v1", "code": code, "message": "request cannot be processed"})
}
func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
