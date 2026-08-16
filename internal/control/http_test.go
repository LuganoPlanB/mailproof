package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAPIHealthAndAuthentication(t *testing.T) {
	s, _ := service(t)
	a := API{Service: s, Token: []byte("01234567890123456789012345678901")}.Handler()
	for _, tc := range []struct {
		path, auth string
		want       int
	}{{"/healthz", "", 200}, {"/v1/control/policy", "", 401}, {"/v1/control/policy", "Bearer wrong", 401}, {"/v1/control/policy", "Bearer 01234567890123456789012345678901", 200}} {
		r := httptest.NewRequest(http.MethodGet, tc.path, nil)
		r.Header.Set("Authorization", tc.auth)
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("%s=%d", tc.path, w.Code)
		}
		if w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatal("CORS exposed")
		}
	}
}

func TestAPIPolicyReturnsBoundedEffectiveRules(t *testing.T) {
	s, db := service(t)
	now := time.Now().Unix()
	if _, err := db.Exec(`INSERT INTO policy_versions(version,created_at,command_id,digest) VALUES(1,?,'test-policy','digest');
INSERT INTO policy_rules(rule_id,version,rule_type,subject,value,enabled,expires_at,created_at) VALUES
('active',1,'outer_domain_block_put','','blocked.example',1,NULL,?),
('disabled',1,'outer_domain_block_put','','disabled.example',0,NULL,?),
('expired',1,'outer_domain_block_put','','expired.example',1,?,?);
INSERT INTO submitters(submitter_id,canonical_address,status,created_at,policy_version,minute_limit,hour_limit,day_limit) VALUES('s','operator@example.test','active',?,'v1',2,3,4);
INSERT INTO policy_bootstrap_observations(observed_at,source_digest,source_count,outcome) VALUES(?,'digest',1,'managed_policy_exists')`, now, now, now-1, now, now, now); err != nil {
		t.Fatal(err)
	}
	a := API{Service: s, Token: []byte("01234567890123456789012345678901")}.Handler()
	r := httptest.NewRequest(http.MethodGet, "/v1/control/policy?limit=1", nil)
	r.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("policy status = %d", w.Code)
	}
	var out struct {
		SchemaVersion string `json:"schema_version"`
		PolicyVersion int64  `json:"policy_version"`
		Items         []struct {
			RuleID string `json:"rule_id"`
			Value  string `json:"value"`
		} `json:"items"`
		Submitters []struct {
			ID     string `json:"submitter_id"`
			Status string `json:"status"`
			Minute int    `json:"minute_limit"`
		} `json:"submitters"`
		Bootstrap struct {
			Observation struct {
				Outcome string `json:"outcome"`
				Count   int    `json:"source_count"`
			} `json:"observation"`
		} `json:"bootstrap"`
	}
	if err := json.NewDecoder(w.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.SchemaVersion != SchemaVersion || out.PolicyVersion != 1 || len(out.Items) != 1 || out.Items[0].RuleID != "active" || out.Items[0].Value != "blocked.example" || len(out.Submitters) != 1 || out.Submitters[0].ID != "s" || out.Submitters[0].Status != "active" || out.Submitters[0].Minute != 2 || out.Bootstrap.Observation.Outcome != "managed_policy_exists" || out.Bootstrap.Observation.Count != 1 {
		t.Fatalf("effective policy = %#v", out)
	}
}
func TestAPIRejectsWrongContentAndTrailingJSON(t *testing.T) {
	s, _ := service(t)
	a := API{Service: s, Token: []byte("01234567890123456789012345678901")}.Handler()
	for _, body := range []string{"{}", `{} {}`} {
		r := httptest.NewRequest(http.MethodPost, "/v1/control/previews", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer 01234567890123456789012345678901")
		if body != "{}" {
			r.Header.Set("Content-Type", "application/json")
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatalf("%q=%d", body, w.Code)
		}
	}
	_ = context.Background()
}
