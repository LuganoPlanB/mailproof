// Command fixture serves deterministic dashboard pages for browser tests.
package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"

	"github.com/luganoplanb/mailproof/internal/dashboard"
)

func main() {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer 01234567890123456789012345678901" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"schema_version": 1, "values": []map[string]any{{"key": "completed", "state": "known", "count": 12}}, "generated_at": "2026-08-15T00:00:00Z", "data_through": "2026-08-15T00:00:00Z", "observed_at": "2026-08-15T00:00:00Z", "partial": false, "stale": false})
	}))
	defer upstream.Close()
	base, _ := url.Parse(upstream.URL)
	listener, err := net.Listen("tcp", "127.0.0.1:3010")
	if err != nil {
		panic(err)
	}
	server := http.Server{Handler: dashboard.New(dashboard.ResultsClient{BaseURL: base, Token: []byte("01234567890123456789012345678901")})}
	go server.Serve(listener)
	select {}
}
