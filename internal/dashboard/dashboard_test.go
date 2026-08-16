package dashboard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("entropy unavailable") }

func TestPrivatePageHeadersAndEscaping(t *testing.T) {
	r := httptest.NewRequest("GET", "/campaigns", nil)
	w := httptest.NewRecorder()
	Handler().ServeHTTP(w, r)
	if got := w.Header().Get("Content-Security-Policy"); !strings.Contains(got, "default-src 'none'") {
		t.Fatalf("CSP = %q", got)
	}
	if strings.Contains(w.Body.String(), "<script>") {
		t.Fatal("inline script")
	}
	if !strings.Contains(w.Body.String(), "htmx-config") {
		t.Fatal("missing htmx config")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestManagementRejectsCrossOriginMutation(t *testing.T) {
	publicOrigin, _ := url.Parse("https://dashboard.example.test")
	controlURL, _ := url.Parse("https://control.example.test")
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := `{"schema_version":"mailproof.control/v1","policy_version":1,"submitters":[]}`
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	h := NewWithConfig(ResultsClient{}, Config{PublicOrigin: publicOrigin, SessionKey: []byte("01234567890123456789012345678901"), Control: ControlClient{BaseURL: controlURL, Token: []byte("01234567890123456789012345678901"), HTTP: client}})
	get := httptest.NewRequest(http.MethodGet, "https://dashboard.example.test/policy", nil)
	get.Host = publicOrigin.Host
	w := httptest.NewRecorder()
	h.ServeHTTP(w, get)
	cookie := w.Result().Cookies()[0]
	post := httptest.NewRequest(http.MethodPost, "https://dashboard.example.test/policy/preview", strings.NewReader("csrf=forged"))
	post.Host = publicOrigin.Host
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.Header.Set("Origin", "https://evil.example")
	post.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, post)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("cross-origin status = %d", w.Code)
	}
	for _, origin := range []string{"", "https://dashboard.example.test"} {
		post := httptest.NewRequest(http.MethodPost, "https://dashboard.example.test/policy/preview", strings.NewReader("csrf=forged"))
		post.Host = publicOrigin.Host
		post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		post.Header.Set("Origin", origin)
		if origin != "" {
			post.Header.Set("Sec-Fetch-Site", "same-site")
		}
		post.AddCookie(cookie)
		w = httptest.NewRecorder()
		h.ServeHTTP(w, post)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("origin %q status = %d", origin, w.Code)
		}
	}
}

func TestControlClientDecodesPolicyAndSelectedAuditEvent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer 01234567890123456789012345678901" {
			t.Fatal("missing control credential")
		}
		switch r.URL.Path {
		case "/v1/control/policy":
			_, _ = io.WriteString(w, `{"schema_version":"mailproof.control/v1","policy_version":2,"items":[{"rule_id":"rule-1","rule_type":"peer_block_put","subject":"","value":"192.0.2.0/24","version":2}],"submitters":[{"submitter_id":"s","status":"active","policy_version":"v2","minute_limit":1,"hour_limit":2,"day_limit":3}],"bootstrap":{"imported":true,"source_digest":"import-digest","imported_at":2,"observation":{"source_digest":"digest","source_count":1,"outcome":"managed_policy_exists","observed_at":1}}}`)
		case "/v1/control/audit":
			_, _ = io.WriteString(w, `{"schema_version":"mailproof.control/v1","items":[{"command_id":"other","actor":"unauthenticated-local","session_id":"opaque","command_type":"peer_block_put","result_code":"applied","before_digest":"before","after_digest":"after","reason":"other event","created_at":1},{"command_id":"selected","actor":"unauthenticated-local","session_id":"opaque","command_type":"quota_change","result_code":"applied","before_digest":"before-2","after_digest":"after-2","reason":"selected event","created_at":2}]}`)
		default:
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL)
	client := ControlClient{BaseURL: base, Token: []byte("01234567890123456789012345678901")}
	policy, err := client.Policy(context.Background())
	if err != nil || policy.Items[0].Value != "192.0.2.0/24" || !policy.Bootstrap.Imported || policy.Bootstrap.SourceDigest != "import-digest" || policy.Bootstrap.ImportedAt != 2 || policy.Bootstrap.Observation == nil || policy.Bootstrap.Observation.Outcome != "managed_policy_exists" {
		t.Fatalf("policy = %#v, %v", policy, err)
	}
	event, err := client.AuditDetail(context.Background(), "selected")
	if err != nil || event.Reason != "selected event" || event.CommandType != "quota_change" {
		t.Fatalf("audit detail = %#v, %v", event, err)
	}
}

func TestControlClientRejectsMalformedVersionedPolicy(t *testing.T) {
	for _, body := range []string{
		`{"schema_version":"mailproof.control/v1","policy_version":1,"items":[],"submitters":[],"unexpected":true}`,
		`{"schema_version":"mailproof.control/v1","policy_version":1,"items":[],"submitters":[]} {}`,
		`{"schema_version":"mailproof.control/v2","policy_version":1,"items":[],"submitters":[]}`,
		`{"schema_version":"mailproof.control/v1","policy_version":"1","items":[],"submitters":[]}`,
		`{"schema_version":"mailproof.control/v1","policy_version":1,"items":[],"submitters":[],"bootstrap":{"unexpected":true}}`,
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) }))
		base, err := url.Parse(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		_, err = (ControlClient{BaseURL: base, Token: []byte("01234567890123456789012345678901")}).Policy(context.Background())
		server.Close()
		if err == nil {
			t.Fatalf("Policy accepted %s", body)
		}
	}
}

func TestEntropyFailureFailsClosed(t *testing.T) {
	previous := randomReader
	randomReader = failingReader{}
	t.Cleanup(func() { randomReader = previous })
	if _, err := randomID(); err == nil {
		t.Fatal("randomID accepted unavailable entropy")
	}
	if _, err := csrf("session", http.MethodPost, "/policy/preview", []byte("01234567890123456789012345678901")); err == nil {
		t.Fatal("csrf accepted unavailable entropy")
	}
	origin, _ := url.Parse("https://dashboard.example.test")
	h := NewWithConfig(ResultsClient{}, Config{PublicOrigin: origin, SessionKey: []byte("01234567890123456789012345678901")})
	r := httptest.NewRequest(http.MethodGet, "https://dashboard.example.test/", nil)
	r.Host = origin.Host
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable || len(w.Result().Cookies()) != 0 {
		t.Fatalf("entropy failure response = %d, cookies = %#v", w.Code, w.Result().Cookies())
	}
}

func TestManagementCommandRejectsInvalidTypedFields(t *testing.T) {
	for _, raw := range []string{
		"command_type=quota_change&submitter_id=s&minute_limit=0&hour_limit=1&day_limit=1",
		"command_type=quota_change&submitter_id=s&minute_limit=999999999999999999999&hour_limit=1&day_limit=1",
		"command_type=peer_block_put&value=",
		"command_type=peer_block_put&value=192.0.2.0%2F24&expiry=not-a-time",
	} {
		r := httptest.NewRequest(http.MethodPost, "/policy/preview", strings.NewReader(raw))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if _, err := managementCommand(r); err == nil {
			t.Fatalf("managementCommand(%q) accepted invalid fields", raw)
		}
	}
	if got, err := parseVersion("0"); err != nil || got != 0 {
		t.Fatalf("parseVersion(0) = %d, %v", got, err)
	}
	for _, raw := range []string{"", "-1", "not-a-number"} {
		if _, err := parseVersion(raw); err == nil {
			t.Fatalf("parseVersion(%q) accepted invalid version", raw)
		}
	}
}

func TestResultsClientRequestsOnlyServerCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer 01234567890123456789012345678901" {
			t.Fatal("missing server credential")
		}
		if r.URL.Query().Get("from") == "" || r.URL.Query().Get("to") == "" {
			t.Fatal("missing bounded range")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"schema_version":1,"values":[],"generated_at":"2026-08-15T00:00:00Z","data_through":"2026-08-15T00:00:00Z","observed_at":"2026-08-15T00:00:00Z","partial":false,"stale":false}`))
	}))
	defer server.Close()
	base, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := ResultsClient{BaseURL: base, Token: []byte("01234567890123456789012345678901")}
	if _, err := client.Snapshot(context.Background(), "/v1/dashboard/overview"); err != nil {
		t.Fatal(err)
	}
}

func TestPrivateBoundaryRejectsHostAndSetsStrictCookie(t *testing.T) {
	origin, _ := url.Parse("https://dashboard.example.test")
	h := NewWithConfig(ResultsClient{}, Config{PublicOrigin: origin, SessionKey: []byte("01234567890123456789012345678901")})
	bad := httptest.NewRequest("GET", "http://evil.test/", nil)
	bad.Host = "evil.test"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, bad)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("host status = %d", w.Code)
	}
	req := httptest.NewRequest("GET", "https://dashboard.example.test/", nil)
	req.Host = "dashboard.example.test"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if cookies := w.Result().Cookies(); len(cookies) != 1 || !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("missing strict session cookie")
	}
}

func TestVendoredHTMXBytes(t *testing.T) {
	bytes, err := fs.ReadFile(assets, "static/htmx-2.0.10.min.js")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(bytes)
	if got := hex.EncodeToString(sum[:]); got != "71ea67185bfa8c98c39d31717c6fce5d852370fcdfd129db4543774d3145c0de" {
		t.Fatalf("HTMX SHA-256 = %s", got)
	}
}
