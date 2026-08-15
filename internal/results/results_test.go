package results

import (
	"context"
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
