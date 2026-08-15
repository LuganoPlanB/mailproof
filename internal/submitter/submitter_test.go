package submitter

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/luganoplanb/mailproof/internal/queue"
)

type fakeClock struct{ now time.Time }

func (c fakeClock) Now() time.Time { return c.now }

type fakeMailer struct {
	body string
	err  error
}

func (m *fakeMailer) Send(_ context.Context, _ string, _ string, body string) error {
	m.body = body
	return m.err
}

func service(t *testing.T) (Service, *fakeMailer, *sql.DB) {
	t.Helper()
	db, err := queue.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	m := &fakeMailer{}
	return Service{DB: db, Mailer: m, CapabilityKey: []byte(strings.Repeat("k", 32)), CapabilityKeyID: "test", Domain: "mailproof.test", Clock: fakeClock{time.Unix(1000, 0)}}, m, db
}
func codeFrom(body string) string {
	const prefix = "Your Mailproof activation code is: "
	return strings.TrimSpace(strings.Split(strings.TrimPrefix(body, prefix), "\n")[0])
}

func TestCanonicalAddress(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		ok       bool
	}{{"Name <a@example.org>", "", false}, {"a@EXAMPLE.org", "a@example.org", true}, {"a@[127.0.0.1]", "", false}, {"a@example.org\nBcc:x", "", false}} {
		got, err := CanonicalAddress(tc.in)
		if (err == nil) != tc.ok || got != tc.want {
			t.Fatalf("CanonicalAddress(%q)=(%q,%v)", tc.in, got, err)
		}
	}
}
func TestChallengeActivationIsSingleUseAndRedacted(t *testing.T) {
	s, m, db := service(t)
	defer db.Close()
	ch, err := s.Challenge(context.Background(), "alice@EXAMPLE.org")
	if err != nil {
		t.Fatal(err)
	}
	if ch.Address != "alice@example.org" || strings.Contains(m.body, "verify+") {
		t.Fatalf("unexpected challenge %#v %q", ch, m.body)
	}
	code := codeFrom(m.body)
	a, err := s.Activate(context.Background(), "alice@example.org", code)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(a.SubmissionAddress, "verify+") {
		t.Fatal("missing activation address")
	}
	if _, err = s.Activate(context.Background(), "alice@example.org", code); err != ErrChallenge {
		t.Fatalf("replay=%v", err)
	}
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM submission_capabilities WHERE CAST(digest AS TEXT) LIKE ?", "%"+code+"%").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("plaintext capability/code leaked to database")
	}
}
func TestExpiredAndRotatedCapability(t *testing.T) {
	s, m, db := service(t)
	defer db.Close()
	_, err := s.Challenge(context.Background(), "alice@example.org")
	if err != nil {
		t.Fatal(err)
	}
	code := codeFrom(m.body)
	s.Clock = fakeClock{time.Unix(1000, 0).Add(challengeTTL + time.Second)}
	if _, err = s.Activate(context.Background(), "alice@example.org", code); err != ErrChallenge {
		t.Fatalf("expired=%v", err)
	}
	s.Clock = fakeClock{time.Unix(2000, 0)}
	_, err = s.Challenge(context.Background(), "alice@example.org")
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.Activate(context.Background(), "alice@example.org", codeFrom(m.body))
	if err != nil {
		t.Fatal(err)
	}
	newAddress, err := s.Rotate(context.Background(), a.Submitter.ID)
	if err != nil || newAddress == a.SubmissionAddress {
		t.Fatalf("rotate=%q,%v", newAddress, err)
	}
	var active int
	if err := db.QueryRow("SELECT COUNT(*) FROM submission_capabilities WHERE submitter_id=? AND revoked_at IS NULL", a.Submitter.ID).Scan(&active); err != nil || active != 1 {
		t.Fatalf("active=%d err=%v", active, err)
	}
}
