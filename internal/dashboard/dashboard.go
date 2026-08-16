// Package dashboard serves the private, read-only operator interface.
package dashboard

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/luganoplanb/mailproof/internal/analytics"
	"github.com/luganoplanb/mailproof/internal/control"
)

//go:embed templates/*.html static/*
var assets embed.FS

// Handler returns a server-rendered dashboard. Dynamic values are always
// rendered through html/template; callers cannot supply templates or markup.
func Handler() http.Handler {
	return New(ResultsClient{})
}

type Config struct {
	PublicOrigin *url.URL
	SessionKey   []byte
	Control      ControlClient
}

// New composes the dashboard with its typed internal read client.
func New(client ResultsClient) http.Handler {
	return NewWithConfig(client, Config{})
}
func NewWithConfig(client ResultsClient, config Config) http.Handler {
	templates := template.Must(template.ParseFS(assets, "templates/*.html"))
	static, err := fs.Sub(assets, "static")
	if err != nil {
		panic(err)
	}
	mux := http.NewServeMux()
	capabilityShown := &sync.Map{}
	mux.Handle("GET /static/", http.StripPrefix("/static/", exactAssets(http.FileServerFS(static))))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	for _, route := range []string{"/", "/operations", "/campaigns", "/investigations"} {
		mux.HandleFunc("GET "+route, page(templates, client, route))
	}
	mux.HandleFunc("GET /campaigns/", page(templates, client, "/campaigns"))
	mux.HandleFunc("GET /investigations/", page(templates, client, "/investigations"))
	if config.Control.BaseURL != nil && len(config.Control.Token) >= 32 {
		mux.HandleFunc("GET /policy", managementPage(templates, config, false))
		mux.HandleFunc("GET /audit", managementPage(templates, config, true))
		mux.HandleFunc("GET /audit/", managementPage(templates, config, true))
		mux.HandleFunc("POST /policy/preview", managementPreview(templates, config))
		mux.HandleFunc("POST /policy/confirm", managementConfirm(templates, config, capabilityShown))
		mux.HandleFunc("POST /policy/ack", managementAcknowledge(capabilityShown))
	}
	return privateHeaders(boundary(config, mux))
}

func boundary(config Config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Forwarded") != "" || r.Header.Get("X-Forwarded-Host") != "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if config.PublicOrigin != nil && r.Host != config.PublicOrigin.Host {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if config.PublicOrigin != nil && len(config.SessionKey) >= 32 && r.URL.Path != "/healthz" {
			session, err := ensureSession(w, r, config)
			if err != nil {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), sessionIDContextKey{}, session))
		}
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		}
		if r.Method == http.MethodPost && (config.PublicOrigin == nil || r.Header.Get("Origin") != config.PublicOrigin.String() || (r.Header.Get("Sec-Fetch-Site") != "" && r.Header.Get("Sec-Fetch-Site") != "same-origin") || !validCSRF(r, config)) {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type sessionIDContextKey struct{}

func sessionID(r *http.Request) string {
	if id, ok := r.Context().Value(sessionIDContextKey{}).(string); ok {
		return id
	}
	c, e := r.Cookie("mailproof_session")
	if e != nil {
		return ""
	}
	return strings.Split(c.Value, ".")[0]
}

var randomReader io.Reader = rand.Reader

func csrf(s, method, path string, key []byte) (string, error) {
	nonce, err := randomID()
	if err != nil {
		return "", err
	}
	exp := time.Now().Add(5 * time.Minute).Unix()
	raw := fmt.Sprintf("%s|%s|%s|%d|%s", s, method, path, exp, nonce)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(raw))
	return base64.RawURLEncoding.EncodeToString([]byte(raw)) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}
func validCSRF(r *http.Request, c Config) bool {
	v := strings.Split(r.FormValue("csrf"), ".")
	if len(v) != 2 {
		return false
	}
	raw, e := base64.RawURLEncoding.DecodeString(v[0])
	if e != nil {
		return false
	}
	mac := hmac.New(sha256.New, c.SessionKey)
	_, _ = mac.Write(raw)
	sig, e := base64.RawURLEncoding.DecodeString(v[1])
	if e != nil || !hmac.Equal(sig, mac.Sum(nil)) {
		return false
	}
	p := strings.Split(string(raw), "|")
	if len(p) != 5 || p[0] != sessionID(r) || p[1] != r.Method || p[2] != r.URL.Path || p[4] == "" {
		return false
	}
	exp, e := strconv.ParseInt(p[3], 10, 64)
	return e == nil && time.Now().Unix() <= exp
}
func ensureSession(w http.ResponseWriter, r *http.Request, config Config) (string, error) {
	if cookie, err := r.Cookie("mailproof_session"); err == nil && validSession(cookie.Value, config.SessionKey) {
		return strings.Split(cookie.Value, ".")[0], nil
	}
	id := make([]byte, 32)
	if _, err := io.ReadFull(randomReader, id); err != nil {
		return "", err
	}
	expires := time.Now().Add(12 * time.Hour).Unix()
	body := base64.RawURLEncoding.EncodeToString(id) + "." + strconv.FormatInt(expires, 10)
	mac := hmac.New(sha256.New, config.SessionKey)
	_, _ = mac.Write([]byte(body))
	value := body + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	http.SetCookie(w, &http.Cookie{Name: "mailproof_session", Value: value, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: config.PublicOrigin.Scheme == "https", Expires: time.Unix(expires, 0)})
	return base64.RawURLEncoding.EncodeToString(id), nil
}
func validSession(value string, key []byte) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	expiry, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().After(time.Unix(expiry, 0)) {
		return false
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	actual, err := base64.RawURLEncoding.DecodeString(parts[2])
	return err == nil && hmac.Equal(actual, mac.Sum(nil))
}

func page(templates *template.Template, client ResultsClient, route string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := "page"
		if r.Header.Get("HX-Request") == "true" {
			name = "content"
		}
		w.Header().Set("Vary", "HX-Request")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		v := view{Route: route, Title: title(route)}
		if route == "/" || route == "/operations" {
			upstreamRoute := "/v1/dashboard/overview"
			if route == "/operations" {
				upstreamRoute = "/v1/dashboard/operations"
			}
			v.Snapshot, v.UpstreamError = client.Snapshot(r.Context(), upstreamRoute)
		}
		if err := templates.ExecuteTemplate(w, name, v); err != nil {
			panic(err)
		}
	}
}

type view struct {
	Route, Title  string
	Snapshot      analytics.Snapshot
	UpstreamError error
	Management    bool
	Policy        Policy
	Audit         Audit
	CSRF          string
	Preview       *control.Preview
	Command       *control.Command
	Message       string
	Capability    string
	AuditDetail   *AuditEvent
	AuditLink     string
	AckCSRF       string
	CommandID     string
}

func managementPage(t *template.Template, c Config, audit bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		csrfToken, err := csrf(sessionID(r), http.MethodPost, "/policy/preview", c.SessionKey)
		if err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		v := view{Management: true, Route: "/policy", Title: "Policy", CSRF: csrfToken}
		if audit {
			v.Route, v.Title = "/audit", "Audit"
			commandID := strings.TrimPrefix(path.Clean(r.URL.Path), "/audit/")
			if commandID != "" && commandID != "." && commandID != "audit" && !strings.Contains(commandID, "/") {
				var detail AuditEvent
				detail, v.UpstreamError = c.Control.AuditDetail(r.Context(), commandID)
				v.AuditDetail = &detail
				v.Title = "Audit event"
			} else {
				v.Audit, v.UpstreamError = c.Control.Audit(r.Context())
			}
		} else {
			v.Policy, v.UpstreamError = c.Control.Policy(r.Context())
		}
		render(t, w, r, v)
	}
}
func render(t *template.Template, w http.ResponseWriter, r *http.Request, v view) {
	name := "page"
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("Vary", "HX-Request")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<main id="content" tabindex="-1">`))
		if err := t.ExecuteTemplate(w, "content", v); err != nil {
			panic(err)
		}
		_, _ = w.Write([]byte(`</main>`))
		return
	}
	w.Header().Set("Vary", "HX-Request")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, name, v); err != nil {
		panic(err)
	}
}
func managementPreview(t *template.Template, c Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, e := managementCommand(r)
		if e != nil {
			render(t, w, r, view{Management: true, Route: "/policy", Title: "Policy", Message: "Check typed fields and reason."})
			return
		}
		expected, e := parseVersion(r.FormValue("expected_version"))
		if e != nil || len(strings.TrimSpace(r.FormValue("reason"))) < 8 || len(r.FormValue("reason")) > 512 {
			render(t, w, r, view{Management: true, Route: "/policy", Title: "Policy", Message: "Check typed fields and reason."})
			return
		}
		commandID, e := randomID()
		if e != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		idempotencyKey, e := randomID()
		if e != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		confirmCSRF, e := csrf(sessionID(r), http.MethodPost, "/policy/confirm", c.SessionKey)
		if e != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		cmd := control.Command{SchemaVersion: control.SchemaVersion, CommandID: commandID, CommandType: r.FormValue("command_type"), ExpectedVersion: expected, Reason: strings.TrimSpace(r.FormValue("reason")), IdempotencyKey: idempotencyKey, Command: raw}
		p, e := c.Control.Preview(r.Context(), sessionID(r), cmd)
		v := view{Management: true, Route: "/policy", Title: "Policy preview", Command: &cmd, CSRF: confirmCSRF, Message: "Preview unavailable"}
		if e == nil {
			v.Preview = &p
			v.Message = "Review the preview before confirmation."
		}
		render(t, w, r, v)
	}
}
func managementConfirm(t *template.Template, c Config, capabilityShown *sync.Map) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		expected, valid := parseVersion(r.FormValue("expected_version"))
		if valid != nil || !validConfirmationFields(r) {
			render(t, w, r, view{Management: true, Route: "/policy", Title: "Policy confirmation", Message: "Confirmation is invalid or expired."})
			return
		}
		ackCSRF, err := csrf(sessionID(r), http.MethodPost, "/policy/ack", c.SessionKey)
		if err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		x := control.Confirmation{SchemaVersion: control.SchemaVersion, CommandID: r.FormValue("command_id"), ExpectedVersion: expected, IdempotencyKey: r.FormValue("idempotency_key"), ConfirmationToken: r.FormValue("confirmation_token"), BeforeDigest: r.FormValue("before_digest"), AfterDigest: r.FormValue("after_digest"), Reason: strings.TrimSpace(r.FormValue("reason")), SessionID: sessionID(r)}
		out, e := c.Control.Confirm(r.Context(), x)
		msg := "Confirmation unavailable"
		if e == nil {
			msg = "Command applied. Review the immutable audit event."
		}
		capability := ""
		if r.FormValue("command_type") == "capability_rotate" && out.Capability != "" {
			if _, loaded := capabilityShown.LoadOrStore(sessionID(r)+"|"+out.CommandID, struct{}{}); !loaded {
				capability = out.Capability
			}
		}
		render(t, w, r, view{Management: true, Route: "/policy", Title: "Policy confirmation", Message: msg, Capability: capability, AuditLink: "/audit/" + out.CommandID, AckCSRF: ackCSRF, CommandID: out.CommandID})
	}
}
func managementAcknowledge(_ *sync.Map) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		commandID, err := required(r.FormValue("command_id"))
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		commandID = strings.TrimPrefix(commandID, "/audit/")
		http.Redirect(w, r, "/audit/"+commandID, http.StatusSeeOther)
	}
}
func randomID() (string, error) {
	b := make([]byte, 24)
	if _, err := io.ReadFull(randomReader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func parseVersion(v string) (int64, error) {
	if v == "" {
		return 0, fmt.Errorf("missing policy version")
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid policy version")
	}
	return n, nil
}
func required(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > 255 {
		return "", fmt.Errorf("required field missing")
	}
	return v, nil
}
func positive(v string) (int, error) {
	n, err := strconv.ParseInt(v, 10, 0)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("invalid positive number")
	}
	return int(n), nil
}
func validConfirmationFields(r *http.Request) bool {
	for _, name := range []string{"command_id", "idempotency_key", "confirmation_token", "before_digest", "after_digest"} {
		if _, err := required(r.FormValue(name)); err != nil {
			return false
		}
	}
	reason := strings.TrimSpace(r.FormValue("reason"))
	return len(reason) >= 8 && len(reason) <= 512
}
func managementCommand(r *http.Request) ([]byte, error) {
	typ := r.FormValue("command_type")
	x := map[string]any{}
	switch typ {
	case "quota_change":
		id, e := required(r.FormValue("submitter_id"))
		if e != nil {
			return nil, e
		}
		minute, e := positive(r.FormValue("minute_limit"))
		if e != nil {
			return nil, e
		}
		hour, e := positive(r.FormValue("hour_limit"))
		if e != nil {
			return nil, e
		}
		day, e := positive(r.FormValue("day_limit"))
		if e != nil {
			return nil, e
		}
		x["submitter_id"], x["minute_limit"], x["hour_limit"], x["day_limit"] = id, minute, hour, day
	case "submitter_suspend", "submitter_reactivate", "capability_rotate":
		id, e := required(r.FormValue("submitter_id"))
		if e != nil {
			return nil, e
		}
		x["submitter_id"] = id
	case "peer_block_put", "subject_allowlist_put", "outer_domain_block_put", "subject_domain_block_put":
		value, e := required(r.FormValue("value"))
		if e != nil {
			return nil, e
		}
		x["value"] = value
		if subject := strings.TrimSpace(r.FormValue("subject")); subject != "" {
			x["subject"] = subject
		}
		if e := r.FormValue("expiry"); e != "" {
			t, err := time.Parse(time.RFC3339, e)
			if err != nil || t.Location() != time.UTC {
				return nil, fmt.Errorf("invalid expiry")
			}
			x["expiry"] = t.Format(time.RFC3339)
		} else if typ != "subject_allowlist_put" {
			x["expiry"] = time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
		}
	default:
		return nil, fmt.Errorf("unsupported command")
	}
	return json.Marshal(x)
}

func title(route string) string {
	if route == "/" {
		return "Overview"
	}
	return strings.ToUpper(route[1:2]) + route[2:]
}

func exactAssets(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "htmx-2.0.10.min.js" && r.URL.Path != "dashboard.css" && r.URL.Path != "dashboard.js" {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func privateHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
