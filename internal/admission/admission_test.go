package admission

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luganoplanb/mailproof/internal/queue"
)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

type passSPF struct{}

func (passSPF) Check(context.Context, string, string, net.IP) (string, error) { return "pass", nil }

type countingSPF struct{ calls int }

func (r *countingSPF) Check(context.Context, string, string, net.IP) (string, error) {
	r.calls++
	return "pass", nil
}

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

func TestBootstrapImportIsIdempotent(t *testing.T) {
	db, _ := queue.Open(context.Background(), ":memory:")
	defer db.Close()
	p := filepath.Join(t.TempDir(), "allow")
	if os.WriteFile(p, []byte("trusted.example\n"), 0600) != nil {
		t.Fatal("write")
	}
	now := time.Now().UTC()
	if err := BootstrapImport(context.Background(), db, p, now); err != nil {
		t.Fatal(err)
	}
	if os.WriteFile(p, []byte("changed.example\n"), 0600) != nil {
		t.Fatal("write")
	}
	if err := BootstrapImport(context.Background(), db, p, now); err != nil {
		t.Fatal(err)
	}
	var value, digest string
	if err := db.QueryRow("SELECT value FROM policy_rules").Scan(&value); err != nil || value != "trusted.example" {
		t.Fatalf("bootstrap policy = %q, %v", value, err)
	}
	if err := db.QueryRow("SELECT source_digest FROM policy_bootstrap").Scan(&digest); err != nil || digest == "" {
		t.Fatalf("bootstrap marker = %q, %v", digest, err)
	}
	var version int
	if err := db.QueryRow("SELECT MAX(version) FROM policy_versions").Scan(&version); err != nil || version != 1 {
		t.Fatalf("bootstrap version = %d, %v", version, err)
	}
	var n int
	if db.QueryRow("SELECT COUNT(*) FROM policy_rules").Scan(&n) != nil || n != 1 {
		t.Fatal("not idempotent")
	}
}

func TestBootstrapImportRefusesWhenManagedPolicyAlreadyExists(t *testing.T) {
	db, err := queue.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec("INSERT INTO policy_versions(version,created_at,command_id,digest) VALUES(1,0,'operator-command','digest')"); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "allow")
	if err = os.WriteFile(p, []byte("trusted.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = BootstrapImport(context.Background(), db, p, time.Now().UTC()); err != nil {
		t.Fatalf("BootstrapImport() = %v", err)
	}
	var count int
	if err = db.QueryRow("SELECT source_count FROM policy_bootstrap_observations").Scan(&count); err != nil || count != 1 {
		t.Fatalf("bootstrap observation = %d, %v", count, err)
	}
}

func TestSnapshotStoreRetainsLastValid(t *testing.T) {
	db, _ := queue.Open(context.Background(), ":memory:")
	defer db.Close()
	s := SnapshotStore{DB: db}
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !s.Ready() {
		t.Fatal("not ready")
	}
	if _, err := db.Exec("INSERT INTO policy_versions(version,created_at,command_id,digest) VALUES(1,0,'invalid','x'); INSERT INTO policy_rules(rule_id,version,rule_type,subject,value,created_at) VALUES('invalid',1,'peer_block_put','','not-a-cidr',0)"); err != nil {
		t.Fatal(err)
	}
	if s.Refresh(context.Background()) == nil {
		t.Fatal("expected refresh failure")
	}
	if !s.Ready() {
		t.Fatal("lost last valid")
	}
}

func TestSnapshotStoreFailsInitialReadiness(t *testing.T) {
	s := SnapshotStore{}
	if err := s.Refresh(context.Background()); err == nil {
		t.Fatal("initial refresh succeeded without a database")
	}
	if s.Ready() {
		t.Fatal("store became ready without a valid snapshot")
	}
}

func TestAdmitDefersWithoutValidatedSnapshot(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	svc := Service{DB: &sql.DB{}, CapabilityKey: key, StampKey: key, Domain: "mailproof.test", Resolver: passSPF{}}
	_, err := svc.Admit(context.Background(), Request{RequestType: "smtpd_access_policy", ProtocolState: "RCPT", ClientAddress: "192.0.2.1", Sender: "a@example.test", Recipient: "verify+YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo@mailproof.test"})
	if !errors.Is(err, ErrDeferred) {
		t.Fatalf("Admit() = %v", err)
	}
}

func TestAdmitDefersWhenRejectionCannotBePersisted(t *testing.T) {
	db, err := queue.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	key := []byte("01234567890123456789012345678901")
	svc := Service{
		DB:            db,
		CapabilityKey: key,
		StampKey:      key,
		Domain:        "mailproof.test",
		Resolver:      passSPF{},
		Policy:        &PolicySnapshot{OuterDomains: map[string]PolicyRule{}},
	}
	request := Request{ClientAddress: "192.0.2.1", Sender: "invalid", Recipient: "verify@example.test"}
	decision, err := svc.Admit(context.Background(), request)
	if !errors.Is(err, ErrDeferred) {
		t.Fatalf("Admit() error = %v, want ErrDeferred", err)
	}
	if decision.ID != "" {
		t.Fatalf("Admit() decision = %+v, want no unpersisted decision", decision)
	}
}

func TestSnapshotStorePollConvergesToNewVersion(t *testing.T) {
	db, err := queue.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := SnapshotStore{DB: db, PollInterval: time.Millisecond}
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Poll(ctx)
	if _, err := db.Exec("INSERT INTO policy_versions(version,created_at,command_id,digest) VALUES(1,0,'new','x')"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for s.Snapshot().VersionID() != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if version := s.Snapshot().VersionID(); version != 1 {
		t.Fatalf("snapshot version=%d, want 1", version)
	}
}

func TestSnapshotRefreshPublishesSubmitterQuotaAndCapability(t *testing.T) {
	ctx := context.Background()
	db, err := queue.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`INSERT INTO submitters(submitter_id,canonical_address,status,created_at,policy_version,minute_limit,hour_limit,day_limit) VALUES('s','alice@example.test','active',0,'v1',2,3,4);
INSERT INTO submission_capabilities(capability_id,submitter_id,digest,key_id,activated_at) VALUES('c','s',x'0102','v1',0)`); err != nil {
		t.Fatal(err)
	}
	s := SnapshotStore{DB: db}
	if err = s.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	item, ok := s.Snapshot().Submitters["0102"]
	if !ok || item.Status != "active" || item.Minute != 2 || item.Hour != 3 || item.Day != 4 {
		t.Fatalf("submitter snapshot = %#v", item)
	}
	if _, err = db.Exec("UPDATE submitters SET minute_limit=9 WHERE submitter_id='s'"); err != nil {
		t.Fatal(err)
	}
	if err = s.Refresh(ctx); err != nil || s.Snapshot().Submitters["0102"].Minute != 9 {
		t.Fatalf("refreshed quota = %#v, %v", s.Snapshot().Submitters["0102"], err)
	}
}

func TestSnapshotExpiryDoesNotMatch(t *testing.T) {
	db, _ := queue.Open(context.Background(), ":memory:")
	defer db.Close()
	db.Exec("INSERT INTO policy_versions(version,created_at,command_id,digest) VALUES(1,0,'x','x')")
	db.Exec("INSERT INTO policy_rules(rule_id,version,rule_type,subject,value,enabled,expires_at,created_at) VALUES('r',1,'outer_domain_block_put','','blocked.example',1,1,0)")
	p, e := LoadPolicySnapshot(context.Background(), db, time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	if _, blocked := p.BlockedOuter("blocked.example", time.Now().UTC()); blocked {
		t.Fatal("expired rule matched")
	}
}

func TestSnapshotExpiryUsesRequestClock(t *testing.T) {
	expires := time.Unix(100, 0).UTC()
	p := &PolicySnapshot{OuterDomains: map[string]PolicyRule{"blocked.example": {ID: "outer", ExpiresAt: expires}}}
	if _, blocked := p.BlockedOuter("blocked.example", expires.Add(-time.Second)); !blocked {
		t.Fatal("rule did not apply before injected clock expiry")
	}
	if _, blocked := p.BlockedOuter("blocked.example", expires); blocked {
		t.Fatal("rule applied at injected clock expiry")
	}
}

func TestSnapshotPublishesVersion(t *testing.T) {
	p := &PolicySnapshot{Version: 9, OuterDomains: map[string]PolicyRule{}}
	if p.VersionID() != 9 {
		t.Fatal("version provenance lost")
	}
}

func TestOuterSnapshotDenyPrecedesResolver(t *testing.T) {
	ctx := context.Background()
	db, err := queue.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	key := []byte("01234567890123456789012345678901")
	resolver := &countingSPF{}
	now := time.Unix(1_700_000_000, 0).UTC()
	svc := Service{DB: db, CapabilityKey: key, StampKey: key, Domain: "mailproof.test", Resolver: resolver, Clock: fixedClock{now}, Policy: &PolicySnapshot{Version: 7, OuterDomains: map[string]PolicyRule{"blocked.example": {ID: "outer-rule"}}}}
	r := Request{RequestType: "smtpd_access_policy", ProtocolState: "RCPT", ClientAddress: "192.0.2.1", Helo: "mx.example.test", Sender: "alice@blocked.example", Recipient: "verify+YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo@mailproof.test"}
	d, err := svc.Admit(ctx, r)
	if !errors.Is(err, ErrDenied) || d.Reason != "outer_domain_blocked" || d.PolicyVersion != "v7" || d.PolicyRuleID != "outer-rule" {
		t.Fatalf("Admit() = (%+v, %v)", d, err)
	}
	if resolver.calls != 0 {
		t.Fatalf("resolver calls=%d, want 0", resolver.calls)
	}
	var version string
	if err := db.QueryRowContext(ctx, "SELECT policy_version FROM decision_records WHERE decision_id=?", d.ID).Scan(&version); err != nil || version != "v7" {
		t.Fatalf("decision provenance = %q, %v", version, err)
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

func TestPreflightBlockPrecedesAllowlist(t *testing.T) {
	p := &PolicySnapshot{Version: 7, SubjectDomains: map[string]PolicyRule{"trusted.example": {ID: "subject-rule"}}}
	_, ok, v := PreflightAllowed(p, "a@trusted.example", []string{"trusted.example"})
	if ok || v != 7 {
		t.Fatalf("block precedence: %v %d", ok, v)
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
	policy, err := LoadPolicySnapshot(ctx, db, now)
	if err != nil {
		t.Fatal(err)
	}
	svc := Service{DB: db, CapabilityKey: key, StampKey: key, Domain: "mailproof.test", Resolver: passSPF{}, Clock: fixedClock{now}, Policy: policy}
	r := Request{RequestType: "smtpd_access_policy", ProtocolState: "RCPT", ClientAddress: "192.0.2.1", Helo: "mx.example.test", Sender: "alice@example.test", Recipient: "verify+" + capability + "@mailproof.test"}
	if d, err := svc.Admit(ctx, r); err != nil || d.Stage != "admission" || d.Stamp == "" || d.PolicyVersion != "v0" {
		t.Fatalf("first Admit() = (%+v, %v)", d, err)
	}
	if _, err := db.Exec("INSERT INTO policy_versions(version,created_at,command_id,digest) VALUES(1,0,'unrelated','x')"); err != nil {
		t.Fatal(err)
	}
	if d, err := svc.Admit(ctx, r); !errors.Is(err, ErrDenied) || d.PolicyVersion != "v0" {
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
	policy, err := LoadPolicySnapshot(ctx, db, now)
	if err != nil {
		t.Fatal(err)
	}
	svc := Service{DB: db, CapabilityKey: key, StampKey: key, Domain: "mailproof.test", Resolver: passSPF{}, Clock: fixedClock{now}, Policy: policy}
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
