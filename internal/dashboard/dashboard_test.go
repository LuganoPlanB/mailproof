package dashboard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

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
