// Command fixture serves deterministic dashboard pages for browser tests.
package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"

	"github.com/luganoplanb/mailproof/internal/control"
	"github.com/luganoplanb/mailproof/internal/dashboard"
)

func main() {
	var rotations sync.Map
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer 01234567890123456789012345678901" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"schema_version": 1, "values": []map[string]any{{"key": "completed", "state": "known", "count": 12}}, "generated_at": "2026-08-15T00:00:00Z", "data_through": "2026-08-15T00:00:00Z", "observed_at": "2026-08-15T00:00:00Z", "partial": false, "stale": false})
	}))
	defer upstream.Close()
	base, _ := url.Parse(upstream.URL)
	controlUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer 01234567890123456789012345678901" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/v1/control/policy" {
			_ = json.NewEncoder(w).Encode(map[string]any{"schema_version": "mailproof.control/v1", "policy_version": 1, "submitters": []any{}})
			return
		}
		if r.URL.Path == "/v1/control/audit" {
			_ = json.NewEncoder(w).Encode(map[string]any{"schema_version": "mailproof.control/v1", "items": []any{map[string]any{"command_id": "fixture-command", "actor": "unauthenticated-local", "session_id": "opaque-session", "command_type": "peer_block_put", "result_code": "applied", "before_digest": "before", "after_digest": "after", "reason": "Temporary hostile peer block", "created_at": 1786968000}}})
			return
		}
		if r.URL.Path == "/v1/control/previews" {
			body, _ := io.ReadAll(r.Body)
			var request struct {
				Command control.Command `json:"command"`
			}
			_ = json.Unmarshal(body, &request)
			if r.Header.Get("X-Fixture-Conflict") != "" || strings.Contains(string(body), "fixture-conflict") {
				http.Error(w, "conflict", http.StatusConflict)
				return
			}
			token := "abcdefghijklmnopqrstuvwxyz012345"
			if request.Command.CommandType == "capability_rotate" && request.Command.CommandID != "" {
				token = "rotation-confirmation-token-123456"
				rotations.Store(request.Command.CommandID, request.Command.CommandType)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"schema_version": "mailproof.control/v1", "confirmation_token": token, "before_digest": "before", "after_digest": "after", "expires_at": "2026-08-17T12:00:00Z", "normalized_command": map[string]any{}, "dry_run": true, "current_version": 1, "next_version": 2})
			return
		}
		if r.URL.Path == "/v1/control/confirmations" {
			body, _ := io.ReadAll(r.Body)
			var confirmation control.Confirmation
			_ = json.Unmarshal(body, &confirmation)
			out := map[string]any{"schema_version": "mailproof.control/v1", "command_id": "fixture-command", "policy_version": 2, "result_code": "applied"}
			if typ, ok := rotations.Load(confirmation.CommandID); ok && typ == "capability_rotate" {
				out["capability"] = "verify+one-time-fixture-secret@example.test"
			}
			_ = json.NewEncoder(w).Encode(out)
			return
		}
		http.Error(w, "unsupported", http.StatusBadRequest)
	}))
	defer controlUpstream.Close()
	controlBase, _ := url.Parse(controlUpstream.URL)
	listener, err := net.Listen("tcp", "127.0.0.1:3010")
	if err != nil {
		panic(err)
	}
	origin, _ := url.Parse("http://127.0.0.1:3010")
	server := http.Server{Handler: dashboard.NewWithConfig(dashboard.ResultsClient{BaseURL: base, Token: []byte("01234567890123456789012345678901")}, dashboard.Config{PublicOrigin: origin, SessionKey: []byte("01234567890123456789012345678901"), Control: dashboard.ControlClient{BaseURL: controlBase, Token: []byte("01234567890123456789012345678901")}})}
	go server.Serve(listener)
	select {}
}
