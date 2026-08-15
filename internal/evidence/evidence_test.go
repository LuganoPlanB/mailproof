package evidence

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEvidenceValidate(t *testing.T) {
	valid := Evidence{ID: "e1", Category: "malware", Adapter: "test", SubjectDigest: "abc", Status: CleanConfirmed, Authority: Authoritative, Value: json.RawMessage(`{"completed":true}`)}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	valid.Status = CapabilityStatus("pass")
	if err := valid.Validate(); err == nil {
		t.Fatal("Validate() accepted invalid status")
	}
}

func TestDecideCategories(t *testing.T) {
	tests := []struct {
		name           string
		evidence       []Evidence
		contradictions []Contradiction
		want           VerdictCategory
	}{
		{name: "malware wins", evidence: []Evidence{{ID: "m", Category: "malware", Status: Observed, Authority: Authoritative}}, want: KnownMalicious},
		{name: "authenticated suspicious", evidence: []Evidence{{ID: "a", Category: "authentication", Status: Observed, Authority: Strong}, {ID: "b", Category: "behavior", Status: Observed, Authority: Weak}}, want: AuthenticatedButSuspicious},
		{name: "verified only with complete coverage", evidence: []Evidence{{ID: "a", Category: "authentication", Status: Observed, Authority: Strong}}, want: Verified},
		{name: "ambiguity suspicious", contradictions: []Contradiction{{ID: "c", Material: true}}, want: Suspicious},
		{name: "missing coverage indeterminate", evidence: []Evidence{{ID: "a", Category: "authentication", Status: Unknown, Authority: Strong}}, want: Indeterminate},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Decide(LocalIngress, tt.evidence, tt.contradictions).Category; got != tt.want {
				t.Fatalf("Decide() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestCanonicalDecisionDeterministic(t *testing.T) {
	v := Verdict{Category: Suspicious, Support: []string{"b", "a"}, Rules: []string{"z", "a"}, Contradictions: []string{}, Unavailable: []string{}}
	first, digest, err := CanonicalDecision(v)
	if err != nil {
		t.Fatal(err)
	}
	second, secondDigest, err := CanonicalDecision(v)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) || digest != secondDigest {
		t.Fatal("canonical decision is not deterministic")
	}
}

func TestProjectAndSelectTopLevelMessage(t *testing.T) {
	mail := []byte("From: Alice <alice@example.test>\r\nReceived: local\r\nAuthentication-Results: example; dkim=pass\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\nwrapper\r\n--x\r\nContent-Type: message/rfc822\r\n\r\nFrom: subject@example.test\r\n\r\nchild\r\n--x--\r\n")
	p, err := Project(mail, Digest(mail))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Headers) != 4 || len(p.Received) != 1 || len(p.AuthenticationResults) != 1 {
		t.Fatalf("unexpected projection: %#v", p)
	}
	root := t.TempDir()
	s, err := SelectTopLevelRFC822(mail, Digest(mail), root)
	if err != nil {
		t.Fatal(err)
	}
	if s.Scope != Detached || s.SubjectDigest == "" {
		t.Fatalf("unexpected selection: %#v", s)
	}
	if _, err := os.Stat(filepath.Join(root, "messages", s.SubjectDigest+".eml")); err != nil {
		t.Fatal(err)
	}
}

func TestSelectMultipleAttachedMessages(t *testing.T) {
	mail := []byte("Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: message/rfc822\r\n\r\nFrom: a@example.test\r\n\r\na\r\n--x\r\nContent-Type: message/rfc822\r\n\r\nFrom: b@example.test\r\n\r\nb\r\n--x--\r\n")
	s, err := SelectTopLevelRFC822(mail, Digest(mail), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if s.SelectionError != "multiple_top_level_rfc822" || s.SubjectDigest != "" {
		t.Fatalf("unexpected selection: %#v", s)
	}
}

func TestSenderAmbiguitiesAndForwarding(t *testing.T) {
	p := Projection{Headers: []Header{{Name: "From", Raw: "a@example.test", Position: 0}, {Name: "From", Raw: "b@example.test\u202e", Position: 1}}}
	if got := SenderAmbiguities(p); len(got) != 2 {
		t.Fatalf("ambiguities = %#v", got)
	}
	provenance := ClassifyForwarding([]string{"from a", "from b"}, true, "arc-v1")
	if provenance.Mode != MFEFLike || !provenance.ARCTrusted {
		t.Fatalf("provenance = %#v", provenance)
	}
}

func TestPublishAnalysisRefusesOverwrite(t *testing.T) {
	root := t.TempDir()
	e := []Evidence{{ID: "e", Category: "test", Adapter: "test", SubjectDigest: "x", Status: Observed, Authority: Weak, ObservedAt: time.Unix(0, 0)}}
	v := Verdict{Category: Indeterminate, Support: []string{}, Contradictions: []string{}, Unavailable: []string{}, Rules: []string{}}
	if err := PublishAnalysis(root, "run", e, v); err != nil {
		t.Fatal(err)
	}
	if err := PublishAnalysis(root, "run", e, v); err == nil {
		t.Fatal("second publication succeeded")
	}
}

func TestRunRejectsUnapprovedExecutable(t *testing.T) {
	r := Run(context.Background(), map[string]struct{}{}, Command{Path: "/bin/echo", Timeout: time.Second, StdoutLimit: 32, StderrLimit: 32})
	if r.Status != Failed || r.Error == "" {
		t.Fatalf("unexpected result: %#v", r)
	}
}
