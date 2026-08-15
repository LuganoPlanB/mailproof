package admission

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/luganoplanb/mailproof/internal/queue"
)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

type passSPF struct{}

func (passSPF) Check(context.Context, string, string, net.IP) (string, error) { return "pass", nil }

func TestParseRequest(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		ok   bool
	}{
		{"valid IPv4", "request=smtpd_access_policy\nprotocol_state=RCPT\nclient_address=192.0.2.1\nsender=alice@example.test\nrecipient=verify+YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo@mailproof.test\n", true},
		{"valid IPv6", "request=smtpd_access_policy\nprotocol_state=RCPT\nclient_address=2001:db8::1\nsender=alice@example.test\nrecipient=x@example.test\n", true},
		{"duplicate attributes", "request=smtpd_access_policy\nprotocol_state=RCPT\nprotocol_state=RCPT\nclient_address=192.0.2.1\nsender=a@example.test\nrecipient=b@example.test\n", false},
		{"missing peer", "request=smtpd_access_policy\nprotocol_state=RCPT\nsender=a@example.test\nrecipient=b@example.test\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseRequest([]byte(tt.raw))
			if (err == nil) != tt.ok {
				t.Fatalf("ParseRequest() error = %v, want success=%v", err, tt.ok)
			}
		})
	}
}

func TestSelectedSubjectAllowed(t *testing.T) {
	tests := []struct {
		name, from string
		allowlist  []string
		wantDomain string
		want       bool
	}{
		{"empty allowlist", "alice@bücher.example", nil, "xn--bcher-kva.example", true},
		{"exact", "alice@trusted.example", []string{"trusted.example"}, "trusted.example", true},
		{"wildcard child", "alice@news.trusted.example", []string{"*.trusted.example"}, "news.trusted.example", true},
		{"wildcard excludes apex", "alice@trusted.example", []string{"*.trusted.example"}, "trusted.example", false},
		{"suffix attack", "alice@eviltrusted.example", []string{"*.trusted.example"}, "eviltrusted.example", false},
		{"malformed", "Alice <alice@trusted.example>", nil, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domain, got := SelectedSubjectAllowed(tt.from, tt.allowlist)
			if got != tt.want || domain != tt.wantDomain {
				t.Fatalf("SelectedSubjectAllowed() = (%q, %v), want (%q, %v)", domain, got, tt.wantDomain, tt.want)
			}
		})
	}
}

func TestSelectedSubjectFrom(t *testing.T) {
	tests := []struct {
		name, message, want string
		valid               bool
	}{
		{"one mailbox", "From: Alice <alice@trusted.example>\r\n\r\nbody", "alice@trusted.example", true},
		{"missing", "Subject: no sender\r\n\r\nbody", "", false},
		{"multiple fields", "From: a@example.test\r\nFrom: b@example.test\r\n\r\nbody", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SelectedSubjectFrom([]byte(tt.message))
			if (err == nil) != tt.valid || got != tt.want {
				t.Fatalf("SelectedSubjectFrom() = (%q, %v)", got, err)
			}
		})
	}
}

func TestAdmitPersistsAndEnforcesMinuteQuota(t *testing.T) {
	ctx := context.Background()
	db, err := queue.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	key := []byte("01234567890123456789012345678901")
	capability := base64.RawURLEncoding.EncodeToString([]byte("abcdefghijklmnopqrstuvwxyz012345"))
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(capability))
	digest := h.Sum(nil)
	now := time.Unix(1_700_000_000, 0).UTC()
	if _, err := db.ExecContext(ctx, `INSERT INTO submitters(submitter_id,canonical_address,status,created_at,policy_version,minute_limit,hour_limit,day_limit) VALUES('s','alice@example.test','active',?,'v1',1,2,3)`, now.Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO submission_capabilities(capability_id,submitter_id,digest,key_id,activated_at) VALUES('c','s',?,'v1',?)`, digest, now.Unix()); err != nil {
		t.Fatal(err)
	}
	svc := Service{DB: db, CapabilityKey: key, StampKey: key, Domain: "mailproof.test", Resolver: passSPF{}, Clock: fixedClock{now}}
	r := Request{RequestType: "smtpd_access_policy", ProtocolState: "RCPT", ClientAddress: "192.0.2.1", Helo: "mx.example.test", Sender: "alice@example.test", Recipient: "verify+" + capability + "@mailproof.test"}
	if d, err := svc.Admit(ctx, r); err != nil || d.Stage != "admission" || d.Stamp == "" {
		t.Fatalf("first Admit() = (%+v, %v)", d, err)
	}
	if _, err := svc.Admit(ctx, r); !errors.Is(err, ErrDenied) {
		t.Fatalf("second Admit() error = %v, want ErrDenied", err)
	}
	var admitted, denied int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM admission_events").Scan(&admitted); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM submission_decisions WHERE reason_code='quota_exceeded'").Scan(&denied); err != nil {
		t.Fatal(err)
	}
	if admitted != 1 || denied != 1 {
		t.Fatalf("events=%d quota decisions=%d", admitted, denied)
	}
}

func TestConsumeStampIsSingleUseAndQueueBound(t *testing.T) {
	ctx := context.Background()
	db, err := queue.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	key := []byte("01234567890123456789012345678901")
	capability := base64.RawURLEncoding.EncodeToString([]byte("abcdefghijklmnopqrstuvwxyz012345"))
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(capability))
	digest := h.Sum(nil)
	now := time.Unix(1_700_000_000, 0).UTC()
	if _, err := db.ExecContext(ctx, `INSERT INTO submitters(submitter_id,canonical_address,status,created_at,policy_version,minute_limit,hour_limit,day_limit) VALUES('s','alice@example.test','active',?,'v1',2,2,2)`, now.Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO submission_capabilities(capability_id,submitter_id,digest,key_id,activated_at) VALUES('c','s',?,'v1',?)`, digest, now.Unix()); err != nil {
		t.Fatal(err)
	}
	svc := Service{DB: db, CapabilityKey: key, StampKey: key, Domain: "mailproof.test", Resolver: passSPF{}, Clock: fixedClock{now}}
	r := Request{RequestType: "smtpd_access_policy", QueueID: "Q1", ProtocolState: "RCPT", ClientAddress: "192.0.2.1", Helo: "mx.example.test", Sender: "alice@example.test", Recipient: "verify+" + capability + "@mailproof.test"}
	d, err := svc.Admit(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ConsumeStamp(ctx, []string{"X-Mailproof-Admission: " + d.Stamp}, "Q1"); err != nil {
		t.Fatalf("ConsumeStamp() error = %v", err)
	}
	if _, err := svc.ConsumeStamp(ctx, []string{"X-Mailproof-Admission: " + d.Stamp}, "Q1"); !errors.Is(err, ErrStamp) {
		t.Fatalf("replay error = %v, want ErrStamp", err)
	}
}
