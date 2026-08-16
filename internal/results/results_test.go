package results

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luganoplanb/mailproof/internal/analytics"
	"github.com/luganoplanb/mailproof/internal/queue"
)

func testRepository(t *testing.T) Repository {
	t.Helper()
	db, err := queue.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return Repository{DB: db, CursorKey: []byte("01234567890123456789012345678901"), Now: func() time.Time { return time.Unix(2000, 0).UTC() }}
}

func TestResultsPaginationAndTamperResistance(t *testing.T) {
	r := testRepository(t)
	ctx := context.Background()
	at := time.Unix(1000, 0).UTC()
	if _, err := r.DB.Exec(`INSERT INTO deliveries(delivery_id,message_digest,source_key,collected_at) VALUES('d','digest','source',?)`, at.Unix()); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"r2", "r1"} {
		if _, err := r.DB.Exec(`INSERT INTO runs(run_id,delivery_id,state,created_at) VALUES(?,?,?,?)`, id, "d", "complete", at.Unix()); err != nil {
			t.Fatal(err)
		}
		if err := InsertRecord(ctx, r.DB, Record{RunID: id, DeliveryID: "d", OccurredAt: at, Verdict: "VERIFIED", PolicyVersion: "v1", SchemaVersion: "v1", AuthScope: "local_ingress", SelectedSubjectStatus: "selected", ManifestDigest: "digest", ManifestPath: "runs/manifest", SourceArtifactDigests: "source"}); err != nil {
			t.Fatal(err)
		}
	}
	p, err := r.Results(ctx, Filter{Limit: 1})
	if err != nil || len(p.Items) != 1 || p.NextCursor == "" {
		t.Fatalf("page=%+v err=%v", p, err)
	}
	p2, err := r.Results(ctx, Filter{Limit: 1, Cursor: p.NextCursor})
	if err != nil || len(p2.Items) != 1 || p2.Items[0].RunID == p.Items[0].RunID {
		t.Fatalf("page2=%+v err=%v", p2, err)
	}
	if _, err := r.Results(ctx, Filter{Cursor: p.NextCursor + "x"}); err != ErrInvalidCursor {
		t.Fatalf("err=%v", err)
	}
}

func TestAPIAuthenticationAndPrivacy(t *testing.T) {
	r := testRepository(t)
	token := []byte("abcdefghijklmnopqrstuvwxyz0123456789")
	h := API{Repository: r, Token: token}.Handler()
	request := httptest.NewRequest(http.MethodGet, "/v1/results", nil)
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", response.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "/v1/results?unknown=x", nil)
	request.Header.Set("Authorization", "Bearer "+string(token))
	response = httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", response.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "/healthz", nil)
	response = httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("health=%d headers=%v", response.Code, response.Header())
	}
}

func TestCampaignAPIRejectsUnknownQueryAndTamperedCursor(t *testing.T) {
	r := testRepository(t)
	token := []byte("abcdefghijklmnopqrstuvwxyz0123456789")
	h := API{Repository: r, Token: token}.Handler()
	for _, path := range []string{"/v1/campaigns?unknown=x", "/v1/campaigns?cursor=not-a-cursor"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set("Authorization", "Bearer "+string(token))
		response := httptest.NewRecorder()
		h.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: status=%d headers=%v", path, response.Code, response.Header())
		}
	}
}

func TestSummaryRequiresBoundedUTCWindow(t *testing.T) {
	r := testRepository(t)
	if _, err := r.Summary(context.Background(), time.Time{}, time.Now(), "hour"); err != ErrInvalidQuery {
		t.Fatalf("err=%v", err)
	}
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := r.Summary(context.Background(), from, from.Add(2*time.Hour), "hour"); err != nil {
		t.Fatal(err)
	}
}

func TestInsertRecordEnqueuesOnlyReviewedCampaignCandidates(t *testing.T) {
	tests := []struct {
		name, verdict, category string
		want                    int
	}{
		{"phishing", "FAILED", "phishing", 1},
		{"impersonation", "FAILED", "impersonation", 1},
		{"malicious link", "FAILED", "malicious-link", 1},
		{"malicious attachment", "FAILED", "malicious-attachment", 1},
		{"failed unreviewed category", "FAILED", "suspicious", 0},
		{"non-failed reviewed category", "VERIFIED", "phishing", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repository := testRepository(t)
			if _, err := repository.DB.Exec(`INSERT INTO deliveries(delivery_id,message_digest,source_key,collected_at) VALUES('delivery','digest','source',1); INSERT INTO runs(run_id,delivery_id,state,created_at) VALUES('run','delivery','complete',1)`); err != nil {
				t.Fatal(err)
			}
			record := Record{RunID: "run", DeliveryID: "delivery", OccurredAt: time.Unix(1, 0).UTC(), Verdict: tt.verdict, PolicyVersion: "v1", SchemaVersion: "mailproof.result/v1", AuthScope: "local_ingress", SelectedSubjectStatus: "selected", CategorySummary: tt.category, ManifestDigest: "manifest", ManifestPath: "runs/run/report/manifest.json", SourceArtifactDigests: "source"}
			if err := InsertRecord(context.Background(), repository.DB, record); err != nil {
				t.Fatal(err)
			}
			var count int
			if err := repository.DB.QueryRow(`SELECT COUNT(*) FROM intel_projection_outbox`).Scan(&count); err != nil || count != tt.want {
				t.Fatalf("outbox count = %d, %v, want %d", count, err, tt.want)
			}
		})
	}
}

func TestResultAPIMapsStorageToReducedContract(t *testing.T) {
	repository := testRepository(t)
	if _, err := repository.DB.Exec(`INSERT INTO deliveries(delivery_id,message_digest,source_key,collected_at) VALUES('delivery','digest','source',1); INSERT INTO runs(run_id,delivery_id,state,created_at) VALUES('run','delivery','complete',1)`); err != nil {
		t.Fatal(err)
	}
	record := Record{RunID: "run", DeliveryID: "delivery", SubmitterID: "submitter", OccurredAt: time.Unix(1, 0).UTC(), Verdict: "INDETERMINATE", PolicyVersion: "v1", SchemaVersion: "internal-storage-version", AuthScope: "secret-scope", SelectedSubjectStatus: "selected", RiskSummary: "internal-risk", CategorySummary: "internal-category", ManifestDigest: "abcd", ManifestPath: "runs/run/report/manifest.json", SourceArtifactDigests: "source-digests"}
	if err := InsertRecord(context.Background(), repository.DB, record); err != nil {
		t.Fatal(err)
	}
	token := []byte("abcdefghijklmnopqrstuvwxyz0123456789")
	handler := API{Repository: repository, Token: token}.Handler()
	for _, path := range []string{"/v1/results", "/v1/results/run"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set("Authorization", "Bearer "+string(token))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		body := response.Body.String()
		if response.Code != http.StatusOK || !strings.Contains(body, `"schema_version":"mailproof.result/v1"`) || !strings.Contains(body, `"run_id":"run"`) || !strings.Contains(body, `"artifact":{"status":"signed","id":"sha256:abcd"}`) {
			t.Fatalf("%s: status=%d body=%s", path, response.Code, body)
		}
		for _, forbidden := range []string{"ManifestPath", "manifest_path", "secret-scope", "internal-risk", "internal-category", "source-digests"} {
			if strings.Contains(body, forbidden) {
				t.Fatalf("%s exposed %q in %s", path, forbidden, body)
			}
		}
	}
}

func TestWindowsAreHalfOpen(t *testing.T) {
	repository := testRepository(t)
	ctx := context.Background()
	from := time.Unix(100, 0).UTC()
	to := time.Unix(200, 0).UTC()
	for _, item := range []struct {
		run, delivery string
		at            time.Time
	}{{"run-from", "delivery-from", from}, {"run-to", "delivery-to", to}} {
		if _, err := repository.DB.Exec(`INSERT INTO deliveries(delivery_id,message_digest,source_key,collected_at) VALUES(?,?,?,?)`, item.delivery, "digest-"+item.run, "source-"+item.run, item.at.Unix()); err != nil {
			t.Fatal(err)
		}
		if _, err := repository.DB.Exec(`INSERT INTO runs(run_id,delivery_id,state,created_at) VALUES(?,?,?,?)`, item.run, item.delivery, "complete", item.at.Unix()); err != nil {
			t.Fatal(err)
		}
		if err := InsertRecord(ctx, repository.DB, Record{RunID: item.run, DeliveryID: item.delivery, OccurredAt: item.at, Verdict: "VERIFIED", PolicyVersion: "v1", SchemaVersion: "mailproof.result/v1", AuthScope: "local_ingress", SelectedSubjectStatus: "selected", ManifestDigest: "manifest", ManifestPath: "runs/" + item.run + "/report/manifest.json", SourceArtifactDigests: "source"}); err != nil {
			t.Fatal(err)
		}
		decisionID := "decision-" + item.run
		if _, err := repository.DB.Exec(`INSERT INTO submission_decisions(decision_id,envelope_sender,recipient,peer_ip,helo,spf_outcome,stage,reason_code,policy_version,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, decisionID, "sender@example.test", "verify@example.test", "192.0.2.1", "mx.example.test", "pass", "admission", "admitted", "v1", item.at.Unix()); err != nil {
			t.Fatal(err)
		}
		if err := InsertDecision(ctx, repository.DB, Decision{ID: decisionID, OccurredAt: item.at, Outcome: "admitted", Stage: "admission", ReasonCode: "admitted", PolicyVersion: "v1", CanonicalJSON: json.RawMessage(`{"decision":"safe"}`), CanonicalDigest: "digest", NotarizationStatus: "queued"}); err != nil {
			t.Fatal(err)
		}
	}
	resultsPage, err := repository.Results(ctx, Filter{From: from, To: to})
	if err != nil || len(resultsPage.Items) != 1 || resultsPage.Items[0].RunID != "run-from" {
		t.Fatalf("results window = %+v, %v", resultsPage, err)
	}
	decisionsPage, err := repository.Decisions(ctx, Filter{From: from, To: to})
	if err != nil || len(decisionsPage.Items) != 1 || decisionsPage.Items[0].ID != "decision-run-from" {
		t.Fatalf("decisions window = %+v, %v", decisionsPage, err)
	}
	summary, err := repository.Summary(ctx, from, to, "hour")
	if err != nil || len(summary) != 2 {
		t.Fatalf("summary window = %+v, %v", summary, err)
	}
}

func TestDashboardRoutesAreAuthenticatedAndBounded(t *testing.T) {
	r := testRepository(t)
	token := []byte("abcdefghijklmnopqrstuvwxyz0123456789")
	h := API{Repository: r, Dashboard: analytics.Repository{DB: r.DB}, Token: token}.Handler()
	path := "/v1/dashboard/overview?from=2026-01-01T00:00:00Z&to=2026-01-01T01:00:00Z&interval=hour"
	request := httptest.NewRequest(http.MethodGet, path, nil)
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || response.Body.String() != "{\"error\":\"unauthorized\"}\n" {
		t.Fatalf("unauthenticated response: %d %q", response.Code, response.Body.String())
	}
	request = httptest.NewRequest(http.MethodGet, path+"&series=run_started&series=run_completed", nil)
	request.Header.Set("Authorization", "Bearer "+string(token))
	response = httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("multiplicity response: %d headers=%v", response.Code, response.Header())
	}
	request = httptest.NewRequest(http.MethodGet, path+"&dimension=not-a-dimension", nil)
	request.Header.Set("Authorization", "Bearer "+string(token))
	response = httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid dimension response: %d", response.Code)
	}
	request = httptest.NewRequest(http.MethodGet, strings.Replace(path, "overview", "series", 1)+"&series=run_started&dimension=stage", nil)
	request.Header.Set("Authorization", "Bearer "+string(token))
	response = httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("valid dimension response: %d", response.Code)
	}
	for _, endpoint := range []string{"overview", "funnel", "series", "operations"} {
		request = httptest.NewRequest(http.MethodGet, strings.Replace(path, "overview", endpoint, 1), nil)
		request.Header.Set("Authorization", "Bearer "+string(token))
		response = httptest.NewRecorder()
		h.ServeHTTP(response, request)
		if response.Code != http.StatusOK || response.Header().Get("X-Content-Type-Options") != "nosniff" || !strings.Contains(response.Body.String(), "\"schema_version\":1") || strings.Contains(response.Body.String(), "manifest_path") {
			t.Fatalf("%s response: %d headers=%v body=%s", endpoint, response.Code, response.Header(), response.Body.String())
		}
	}
}

func FuzzDashboardQueryStrings(f *testing.F) {
	f.Add("from=2026-01-01T00:00:00Z&to=2026-01-01T01:00:00Z&interval=hour")
	f.Add("series=run_started&series=run_completed")
	f.Fuzz(func(t *testing.T, raw string) {
		r := testRepository(t)
		token := []byte("abcdefghijklmnopqrstuvwxyz0123456789")
		h := API{Repository: r, Dashboard: analytics.Repository{DB: r.DB}, Token: token}.Handler()
		req := httptest.NewRequest(http.MethodGet, "/v1/dashboard/series", nil)
		req.URL.RawQuery = raw
		req.Header.Set("Authorization", "Bearer "+string(token))
		response := httptest.NewRecorder()
		h.ServeHTTP(response, req)
		if response.Code != http.StatusOK && response.Code != http.StatusBadRequest && response.Code != http.StatusInternalServerError {
			t.Fatalf("unexpected status %d", response.Code)
		}
	})
}
