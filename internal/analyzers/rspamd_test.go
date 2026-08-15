package analyzers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luganoplanb/mailproof/internal/evidence"
)

var testTime = time.Date(2026, time.August, 15, 0, 0, 0, 0, time.UTC)

func validRspamd() []byte {
	return []byte(`{"action":"no action","score":0,"symbols":{"MAILPROOF_PROJECTION":{"options":["{\"schemaVersion\":1,\"id\":\"p1\"}"]},"MAILPROOF_PROJECTION_COMPLETE":{"options":["{\"schemaVersion\":1,\"complete\":true}"]},"UNRELATED":{"options":["x"]}}}`)
}

func request(scope evidence.AuthScope) RspamdRequest {
	r := RspamdRequest{Scope: scope, Message: []byte("From: a@example.test\r\n\r\nbody"), SubjectDigest: "subject", ConfigDigest: "config", AdapterVersion: "3.12"}
	if scope == evidence.LocalIngress {
		r.PeerIP, r.HELO, r.EnvelopeFrom = "192.0.2.1", "mx.example.test", "sender@example.test"
	}
	return r
}

func TestNormalizeRspamdRequiresOneCompleteMarker(t *testing.T) {
	for _, tt := range []struct {
		name string
		body string
		want bool
	}{
		{"valid", string(validRspamd()), false},
		{"missing", `{"symbols":{}}`, true},
		{"duplicate", `{"symbols":{"MAILPROOF_PROJECTION_COMPLETE":{"options":["{\"schemaVersion\":1,\"complete\":true}","{\"schemaVersion\":1,\"complete\":true}"]}}}`, true},
		{"malformed", `{"symbols":{"MAILPROOF_PROJECTION_COMPLETE":{"options":["bad"]}}}`, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NormalizeRspamd([]byte(tt.body), request(evidence.LocalIngress))
			if (err != nil) != tt.want {
				t.Fatalf("NormalizeRspamd() error = %v, want error %v", err, tt.want)
			}
		})
	}
}

func TestRspamdClientUsesOneRequestAndScopeMetadata(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if got := r.Header.Get("IP"); got != "192.0.2.1" {
			t.Fatalf("IP = %q", got)
		}
		if got := r.Header.Get("Helo"); got != "mx.example.test" {
			t.Fatalf("Helo = %q", got)
		}
		_, _ = w.Write(validRspamd())
	}))
	defer server.Close()
	got, err := (RspamdClient{Endpoint: server.URL, MaxBytes: 1 << 20}).Analyze(context.Background(), request(evidence.LocalIngress))
	if err != nil || calls != 1 || len(got.Projections) != 1 {
		t.Fatalf("Analyze() = %#v, %v; calls=%d", got, err, calls)
	}
}

func TestDetachedRspamdOmitsSMTPMetadataAndMarksReplayUntrusted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, header := range []string{"IP", "Helo", "From"} {
			if r.Header.Get(header) != "" {
				t.Fatalf("detached request contains %s", header)
			}
		}
		_, _ = w.Write(validRspamd())
	}))
	defer server.Close()
	got, err := (RspamdClient{Endpoint: server.URL, MaxBytes: 1 << 20}).Analyze(context.Background(), request(evidence.Detached))
	if err != nil || !got.SPFNotApplicable || !got.UntrustedReplayAR {
		t.Fatalf("Analyze() = %#v, %v", got, err)
	}
}

func TestRspamdCoverageDoesNotInferCleanWithoutCompletion(t *testing.T) {
	coverage := capabilityCoverage(map[string]rspamdSymbol{}, false)
	for _, capability := range coverage {
		if capability.Status == evidence.CleanConfirmed {
			t.Fatal("absent symbol became clean")
		}
	}
	body := strings.Replace(string(validRspamd()), "UNRELATED", "MAILPROOF_CLAM_FAIL", 1)
	got, err := NormalizeRspamd([]byte(body), request(evidence.LocalIngress))
	if err != nil {
		t.Fatal(err)
	}
	for _, capability := range got.Capabilities {
		if capability.Name == "clamav" && capability.Status != evidence.Failed {
			t.Fatalf("clamav status = %s", capability.Status)
		}
	}
}

func TestRspamdEvidenceRetainsRawProvenance(t *testing.T) {
	got, err := NormalizeRspamd(validRspamd(), request(evidence.LocalIngress))
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range got.Evidence(request(evidence.LocalIngress), "responses/rspamd.json", testTime) {
		if err := item.Validate(); err != nil {
			t.Fatal(err)
		}
		var value RspamdCapability
		if err := json.Unmarshal(item.Value, &value); err != nil || item.ResponseDigest == "" || item.RawResponsePath == "" {
			t.Fatalf("evidence = %#v, decode=%v", item, err)
		}
	}
}
