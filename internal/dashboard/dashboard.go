// Package dashboard serves the private, read-only operator interface.
package dashboard

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/luganoplanb/mailproof/internal/analytics"
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
	mux.Handle("GET /static/", http.StripPrefix("/static/", exactAssets(http.FileServerFS(static))))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	for _, route := range []string{"/", "/operations", "/campaigns", "/investigations"} {
		mux.HandleFunc("GET "+route, page(templates, client, route))
	}
	mux.HandleFunc("GET /campaigns/", page(templates, client, "/campaigns"))
	mux.HandleFunc("GET /investigations/", page(templates, client, "/investigations"))
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
			ensureSession(w, r, config)
		}
		next.ServeHTTP(w, r)
	})
}
func ensureSession(w http.ResponseWriter, r *http.Request, config Config) {
	if cookie, err := r.Cookie("mailproof_session"); err == nil && validSession(cookie.Value, config.SessionKey) {
		return
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return
	}
	expires := time.Now().Add(12 * time.Hour).Unix()
	body := base64.RawURLEncoding.EncodeToString(id) + "." + strconv.FormatInt(expires, 10)
	mac := hmac.New(sha256.New, config.SessionKey)
	_, _ = mac.Write([]byte(body))
	value := body + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	http.SetCookie(w, &http.Cookie{Name: "mailproof_session", Value: value, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: config.PublicOrigin.Scheme == "https", Expires: time.Unix(expires, 0)})
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
