package control

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/luganoplanb/mailproof/internal/queue"
)

type clock struct{ t time.Time }

func (c clock) Now() time.Time { return c.t }

func service(t *testing.T) (Service, *sql.DB) {
	t.Helper()
	db, err := queue.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return Service{DB: db, ConfirmationKey: []byte("01234567890123456789012345678901"), Clock: clock{time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC)}}, db
}

func TestPreviewIsNoopThenConfirmationIsSingleUse(t *testing.T) {
	s, db := service(t)
	c := Command{SchemaVersion: SchemaVersion, CommandID: "1234567890abcdef", CommandType: "subject_allowlist_put", ExpectedVersion: 0, Reason: "needed for verified partner", IdempotencyKey: "1234567890abcdef", Command: []byte(`{"value":"example.org"}`)}
	p, err := s.Preview(context.Background(), "1234567890abcdef", c)
	if err != nil || !p.DryRun {
		t.Fatalf("preview = %#v, %v", p, err)
	}
	if len(p.BeforeDigest) != 64 || len(p.AfterDigest) != 64 || p.BeforeDigest == p.AfterDigest {
		t.Fatalf("effective policy evidence = %#v", p)
	}
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM policy_rules").Scan(&n); err != nil || n != 0 {
		t.Fatalf("preview mutated rules: %d, %v", n, err)
	}
	x := Confirmation{SchemaVersion: SchemaVersion, CommandID: c.CommandID, ExpectedVersion: 0, IdempotencyKey: c.IdempotencyKey, ConfirmationToken: p.ConfirmationToken, BeforeDigest: p.BeforeDigest, AfterDigest: p.AfterDigest, Reason: c.Reason, SessionID: "1234567890abcdef"}
	if _, err = s.Confirm(context.Background(), x); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Confirm(context.Background(), x); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay = %v", err)
	}
}

func TestPreviewRejectsCrossSessionAndExpiry(t *testing.T) {
	s, _ := service(t)
	c := Command{SchemaVersion: SchemaVersion, CommandID: "1234567890abcdef", CommandType: "quota_change", ExpectedVersion: 0, Reason: "raise temporary rate capacity", IdempotencyKey: "1234567890abcdef", Command: []byte(`{"submitter_id":"s","minute_limit":1,"hour_limit":2,"day_limit":3}`)}
	p, err := s.Preview(context.Background(), "1234567890abcdef", c)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Confirm(context.Background(), Confirmation{SchemaVersion: SchemaVersion, CommandID: c.CommandID, ExpectedVersion: 0, IdempotencyKey: c.IdempotencyKey, ConfirmationToken: p.ConfirmationToken, BeforeDigest: p.BeforeDigest, AfterDigest: p.AfterDigest, Reason: c.Reason, SessionID: "fedcba0987654321"})
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("cross session = %v", err)
	}
}

func TestConfirmationTokenIsStoredOnlyAsDigest(t *testing.T) {
	s, db := service(t)
	c := Command{SchemaVersion: SchemaVersion, CommandID: "1234567890abcdef", CommandType: "quota_change", ExpectedVersion: 0, Reason: "raise temporary rate capacity", IdempotencyKey: "1234567890abcdef", Command: []byte(`{"submitter_id":"s","minute_limit":1,"hour_limit":2,"day_limit":3}`)}
	p, err := s.Preview(context.Background(), "1234567890abcdef", c)
	if err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err := db.QueryRow("SELECT token_digest FROM confirmation_tokens").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if string(raw) == p.ConfirmationToken {
		t.Fatal("plaintext confirmation token persisted")
	}
}

func TestPreviewRejectsStaleVersionAndExpiry(t *testing.T) {
	s, db := service(t)
	c := Command{SchemaVersion: SchemaVersion, CommandID: "1234567890abcdef", CommandType: "quota_change", ExpectedVersion: 1, Reason: "raise temporary rate capacity", IdempotencyKey: "1234567890abcdef", Command: []byte(`{"submitter_id":"s","minute_limit":1,"hour_limit":2,"day_limit":3}`)}
	if _, err := s.Preview(context.Background(), "1234567890abcdef", c); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale = %v", err)
	}
	c.ExpectedVersion = 0
	p, err := s.Preview(context.Background(), "1234567890abcdef", c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE confirmation_tokens SET expires_at=0"); err != nil {
		t.Fatal(err)
	}
	_, err = s.Confirm(context.Background(), Confirmation{SchemaVersion: SchemaVersion, CommandID: c.CommandID, ExpectedVersion: 0, IdempotencyKey: c.IdempotencyKey, ConfirmationToken: p.ConfirmationToken, BeforeDigest: p.BeforeDigest, AfterDigest: p.AfterDigest, Reason: c.Reason, SessionID: "1234567890abcdef"})
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("expired = %v", err)
	}
}

func TestConfirmBindsPreviewIdentityAndAuditMetadata(t *testing.T) {
	s, db := service(t)
	c := Command{SchemaVersion: SchemaVersion, CommandID: "1234567890abcdef", CommandType: "subject_allowlist_put", ExpectedVersion: 0, Reason: "needed for verified partner", IdempotencyKey: "abcdefghijklmnop", Command: []byte(`{"value":"example.org"}`)}
	p, err := s.Preview(context.Background(), "1234567890abcdef", c)
	if err != nil {
		t.Fatal(err)
	}
	x := Confirmation{SchemaVersion: SchemaVersion, CommandID: c.CommandID, ExpectedVersion: 0, IdempotencyKey: c.IdempotencyKey, ConfirmationToken: p.ConfirmationToken, BeforeDigest: p.BeforeDigest, AfterDigest: p.AfterDigest, Reason: c.Reason, SessionID: "1234567890abcdef"}
	for _, substitute := range []func(*Confirmation){
		func(x *Confirmation) { x.Reason = "substituted reason" },
		func(x *Confirmation) { x.CommandID = "fedcba0987654321" },
		func(x *Confirmation) { x.IdempotencyKey = "ponmlkjihgfedcba" },
		func(x *Confirmation) { x.BeforeDigest = "substituted-before" },
	} {
		candidate := x
		substitute(&candidate)
		if _, err := s.Confirm(context.Background(), candidate); !errors.Is(err, ErrExpired) {
			t.Fatalf("substituted confirmation = %v", err)
		}
	}
	if _, err := s.Confirm(context.Background(), x); err != nil {
		t.Fatal(err)
	}
	var commandID, before, after, reason string
	if err := db.QueryRow("SELECT command_id,before_digest,after_digest,reason FROM audit_events").Scan(&commandID, &before, &after, &reason); err != nil {
		t.Fatal(err)
	}
	if commandID != c.CommandID || before != p.BeforeDigest || after != p.AfterDigest || reason != c.Reason {
		t.Fatalf("untrusted audit provenance: %q %q %q %q", commandID, before, after, reason)
	}
}

func TestCanonicalRequiresApplicableOperation(t *testing.T) {
	for _, tc := range []struct {
		name, typ, body string
	}{
		{"quota limits", "quota_change", `{"submitter_id":"s"}`},
		{"suspend identity", "submitter_suspend", `{}`},
		{"reactivate identity", "submitter_reactivate", `{}`},
		{"capability identity", "capability_rotate", `{}`},
		{"disabled rule identity", "peer_block_put", `{"enabled":false}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := canonical(Command{SchemaVersion: SchemaVersion, CommandID: "1234567890abcdef", CommandType: tc.typ, ExpectedVersion: 0, Reason: "a sufficiently detailed reason", IdempotencyKey: "1234567890abcdef", Command: []byte(tc.body)})
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("canonical error = %v", err)
			}
		})
	}
}

func TestCanonicalAcceptsBarePeerIP(t *testing.T) {
	_, err := canonical(Command{SchemaVersion: SchemaVersion, CommandID: "1234567890abcdef", CommandType: "peer_block_put", ExpectedVersion: 0, Reason: "block abusive local peer", IdempotencyKey: "1234567890abcdef", Command: []byte(`{"value":"192.0.2.7"}`)})
	if err != nil {
		t.Fatalf("bare IP command = %v", err)
	}
}

func TestCapabilityRotationChangesEffectivePolicyDigest(t *testing.T) {
	s, db := service(t)
	s.CapabilityKey = []byte("abcdefghijklmnopqrstuvwxyz012345")
	s.CapabilityDomain = "mailproof.test"
	if _, err := db.Exec(`INSERT INTO submitters(submitter_id,canonical_address,status,created_at,policy_version,minute_limit,hour_limit,day_limit) VALUES('s','operator@example.test','active',0,'v0',1,1,1);
INSERT INTO submission_capabilities(capability_id,submitter_id,digest,key_id,activated_at) VALUES('old','s',x'0102','v0',0)`); err != nil {
		t.Fatal(err)
	}
	c := Command{SchemaVersion: SchemaVersion, CommandID: "1234567890abcdef", CommandType: "capability_rotate", ExpectedVersion: 0, Reason: "replace operator capability", IdempotencyKey: "abcdefghijklmnop", Command: []byte(`{"submitter_id":"s"}`)}
	p, err := s.Preview(context.Background(), "1234567890abcdef", c)
	if err != nil {
		t.Fatal(err)
	}
	if p.BeforeDigest == p.AfterDigest {
		t.Fatal("capability rotation did not change effective policy digest")
	}
	x := Confirmation{SchemaVersion: SchemaVersion, CommandID: c.CommandID, ExpectedVersion: 0, IdempotencyKey: c.IdempotencyKey, ConfirmationToken: p.ConfirmationToken, BeforeDigest: p.BeforeDigest, AfterDigest: p.AfterDigest, Reason: c.Reason, SessionID: "1234567890abcdef"}
	if _, err = s.Confirm(context.Background(), x); err != nil {
		t.Fatal(err)
	}
}

func TestApplySuspendAndReactivateRequireExistingTransition(t *testing.T) {
	s, db := service(t)
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = apply(context.Background(), tx, "submitter_suspend", []byte(`{"submitter_id":"missing"}`), 1, s.now()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("suspend missing = %v", err)
	}
	_ = tx.Rollback()
}

func FuzzCanonicalCommand(f *testing.F) {
	f.Add("quota_change", `{"submitter_id":"s"}`)
	f.Add("unknown", `{}`)
	f.Fuzz(func(t *testing.T, typ, body string) {
		_, _ = canonical(Command{SchemaVersion: SchemaVersion, CommandID: "1234567890abcdef", CommandType: typ, ExpectedVersion: 0, Reason: "a sufficiently detailed reason", IdempotencyKey: "1234567890abcdef", Command: []byte(body)})
	})
}
