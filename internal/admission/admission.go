package admission

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/luganoplanb/mailproof/internal/submitter"
)

const (
	maxCapability = 128
	maxAttribute  = 1024
	stampTTL      = 10 * time.Minute
)

var (
	ErrMalformed = errors.New("malformed policy request")
	ErrDenied    = errors.New("submission denied")
	ErrDeferred  = errors.New("submission temporarily unavailable")
)

// SPFResolver is intentionally narrow: the policy process can only evaluate the
// envelope identity supplied by Postfix, never a message-provided domain.
type SPFResolver interface {
	Check(context.Context, string, string, net.IP) (string, error)
}
type Clock interface{ Now() time.Time }
type realClock struct{}

func (realClock) Now() time.Time { return time.Now().UTC() }

type Request struct{ RequestType, Instance, QueueID, ProtocolState, ClientAddress, Helo, Sender, Recipient string }
type Decision struct {
	ID, SubmitterID, Envelope, Recipient, SPF, Reason, Stage, PolicyVersion, Stamp string
	ExpiresAt                                                                      time.Time
}
type Service struct {
	DB                      *sql.DB
	CapabilityKey, StampKey []byte
	Domain                  string
	Resolver                SPFResolver
	Clock                   Clock
}

func (s Service) now() time.Time {
	if s.Clock != nil {
		return s.Clock.Now().UTC()
	}
	return realClock{}.Now()
}

// ParseRequest accepts Postfix's key=value protocol only. Duplicate keys,
// continuations, and oversized fields are rejected before any database or DNS work.
func ParseRequest(raw []byte) (Request, error) {
	if len(raw) == 0 || len(raw) > 16<<10 {
		return Request{}, ErrMalformed
	}
	var r Request
	seen := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" || len(value) > maxAttribute || seen[key] {
			return Request{}, ErrMalformed
		}
		seen[key] = true
		switch key {
		case "request":
			r.RequestType = value
		case "instance":
			r.Instance = value
		case "queue_id":
			r.QueueID = value
		case "protocol_state":
			r.ProtocolState = value
		case "client_address":
			r.ClientAddress = value
		case "helo_name":
			r.Helo = value
		case "sender":
			r.Sender = value
		case "recipient":
			r.Recipient = value
		}
	}
	if r.RequestType != "smtpd_access_policy" || r.ProtocolState == "" || r.Sender == "" || r.Recipient == "" || net.ParseIP(r.ClientAddress) == nil {
		return Request{}, ErrMalformed
	}
	return r, nil
}

func (s Service) Admit(ctx context.Context, r Request) (Decision, error) {
	if len(s.CapabilityKey) < 32 || len(s.StampKey) < 32 || s.DB == nil || s.Resolver == nil {
		return Decision{}, ErrDeferred
	}
	envelope, err := submitter.CanonicalAddress(r.Sender)
	if err != nil {
		return s.reject(ctx, r, "identity", "invalid_sender", ""), ErrDenied
	}
	cap, err := capability(r.Recipient, s.Domain)
	if err != nil {
		return s.reject(ctx, r, "identity", "invalid_capability", ""), ErrDenied
	}
	digest := keyed(s.CapabilityKey, cap)
	var submitterID, expected, policy string
	var minute, hour, day int
	err = s.DB.QueryRowContext(ctx, `SELECT s.submitter_id,s.canonical_address,s.policy_version,s.minute_limit,s.hour_limit,s.day_limit FROM submitters s JOIN submission_capabilities c ON c.submitter_id=s.submitter_id WHERE c.digest=? AND c.revoked_at IS NULL AND s.status='active'`, digest).Scan(&submitterID, &expected, &policy, &minute, &hour, &day)
	if errors.Is(err, sql.ErrNoRows) {
		return s.reject(ctx, r, "identity", "unknown_capability", ""), ErrDenied
	}
	if err != nil {
		return Decision{}, ErrDeferred
	}
	if envelope != expected {
		return s.reject(ctx, r, "identity", "envelope_mismatch", submitterID), ErrDenied
	}
	spf, err := s.Resolver.Check(ctx, envelope, r.Helo, net.ParseIP(r.ClientAddress))
	if err != nil {
		return Decision{}, ErrDeferred
	}
	if spf != "pass" {
		return s.reject(ctx, r, "spf", "spf_"+spf, submitterID), ErrDenied
	}
	if minute < 1 || hour < 1 || day < 1 {
		return s.reject(ctx, r, "quota", "invalid_limit", submitterID), ErrDenied
	}
	return s.admit(ctx, r, submitterID, envelope, policy, digest, minute, hour, day)
}

func capability(recipient, domain string) (string, error) {
	if len(recipient) > maxAttribute || strings.Count(recipient, "@") != 1 {
		return "", ErrMalformed
	}
	local, host, _ := strings.Cut(recipient, "@")
	if !strings.EqualFold(host, domain) || !strings.HasPrefix(local, "verify+") {
		return "", ErrMalformed
	}
	cap := strings.TrimPrefix(local, "verify+")
	if len(cap) < 32 || len(cap) > maxCapability {
		return "", ErrMalformed
	}
	decoded, err := base64.RawURLEncoding.DecodeString(cap)
	if err != nil || len(decoded) < 24 {
		return "", ErrMalformed
	}
	return cap, nil
}
func keyed(key []byte, value string) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(value))
	return h.Sum(nil)
}
func decisionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s Service) admit(ctx context.Context, r Request, submitterID, envelope, policy string, digest []byte, minute, hour, day int) (Decision, error) {
	now := s.now()
	id, err := decisionID()
	if err != nil {
		return Decision{}, ErrDeferred
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Decision{}, ErrDeferred
	}
	defer tx.Rollback()
	for _, limit := range []struct{ seconds, n int64 }{{60, int64(minute)}, {3600, int64(hour)}, {86400, int64(day)}} {
		var n int64
		if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM admission_events WHERE submitter_id=? AND admitted_at>?", submitterID, now.Add(-time.Duration(limit.seconds)*time.Second).Unix()).Scan(&n); err != nil {
			return Decision{}, ErrDeferred
		}
		if n >= limit.n {
			d := Decision{ID: id, SubmitterID: submitterID, Envelope: envelope, Recipient: r.Recipient, SPF: "pass", Stage: "quota", Reason: "quota_exceeded", PolicyVersion: policy}
			if err = s.store(ctx, tx, d, r, digest, now); err != nil {
				return Decision{}, ErrDeferred
			}
			if err = tx.Commit(); err != nil {
				return Decision{}, ErrDeferred
			}
			return d, ErrDenied
		}
	}
	d := Decision{ID: id, SubmitterID: submitterID, Envelope: envelope, Recipient: r.Recipient, SPF: "pass", Stage: "admission", Reason: "admitted", PolicyVersion: policy, ExpiresAt: now.Add(stampTTL)}
	d.Stamp = s.stamp(d, r)
	if err = s.store(ctx, tx, d, r, digest, now); err != nil {
		return Decision{}, ErrDeferred
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO admission_events(decision_id,submitter_id,admitted_at) VALUES(?,?,?)", id, submitterID, now.Unix()); err != nil {
		return Decision{}, ErrDeferred
	}
	if err = tx.Commit(); err != nil {
		return Decision{}, ErrDeferred
	}
	return d, nil
}
func (s Service) reject(ctx context.Context, r Request, stage, reason, submitterID string) Decision {
	id, err := decisionID()
	if err != nil {
		return Decision{Stage: stage, Reason: reason}
	}
	d := Decision{ID: id, SubmitterID: submitterID, Envelope: r.Sender, Recipient: r.Recipient, Stage: stage, Reason: reason, PolicyVersion: "v1"}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err == nil {
		_ = s.store(ctx, tx, d, r, nil, s.now())
		_ = tx.Commit()
	}
	return d
}
func (s Service) store(ctx context.Context, tx *sql.Tx, d Decision, r Request, digest []byte, now time.Time) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO submission_decisions(decision_id,submitter_id,capability_digest,envelope_sender,recipient,peer_ip,helo,spf_outcome,stage,reason_code,policy_version,queue_id,stamp_mac,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, d.ID, nilOr(d.SubmitterID), digest, d.Envelope, d.Recipient, r.ClientAddress, r.Helo, d.SPF, d.Stage, d.Reason, d.PolicyVersion, r.QueueID, keyed(s.StampKey, d.Stamp), nullUnix(d.ExpiresAt), now.Unix())
	return err
}
func nilOr(v string) any {
	if v == "" {
		return nil
	}
	return v
}
func nullUnix(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.Unix()
}
func (s Service) stamp(d Decision, r Request) string {
	payload := strings.Join([]string{"v1", d.ID, d.SubmitterID, d.Envelope, d.Recipient, r.ClientAddress, r.Helo, d.SPF, d.PolicyVersion, fmt.Sprint(d.ExpiresAt.Unix())}, "|")
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString(keyed(s.StampKey, payload))
}
