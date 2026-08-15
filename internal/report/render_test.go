package report

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/luganoplanb/mailproof/internal/evidence"
)

func TestRenderProducesEscapedNonActiveReports(t *testing.T) {
	out, err := Render(Input{RunID: "run", DeliveryID: "delivery", DeliveredOriginalDigest: "abc", AuthContextScope: evidence.Detached, Verdict: evidence.Verdict{Category: evidence.Suspicious, Support: []string{"<script>alert(1)</script>\u202eevil"}, Unavailable: []string{"dns"}}, MissingAnalyzers: []string{"av"}, Timeline: []TimelineEvent{{Kind: "visible author claim", Claim: "https://attacker.example"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"report.json", "report.txt", "report.html"} {
		if len(out[name]) == 0 {
			t.Fatalf("%s missing", name)
		}
	}
	if bytes.Contains(out["report.html"], []byte("<script>")) || bytes.Contains(out["report.html"], []byte("href=")) {
		t.Fatalf("active content leaked: %s", out["report.html"])
	}
	if !bytes.Contains(out["report.txt"], []byte("does not authenticate this detached subject")) {
		t.Fatal("detached limitation missing")
	}
}

func TestPublishRefusesReplacement(t *testing.T) {
	root := t.TempDir()
	in := Input{RunID: "run", DeliveryID: "delivery", DeliveredOriginalDigest: "abc", AuthContextScope: evidence.LocalIngress, Verdict: evidence.Verdict{Category: evidence.Indeterminate}}
	if _, err := Publish(root, in); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "runs", "run", "report", "report.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := Publish(root, in); err == nil {
		t.Fatal("replacement unexpectedly succeeded")
	}
}
