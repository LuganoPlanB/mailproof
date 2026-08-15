package results

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
