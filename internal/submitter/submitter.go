// Package submitter owns mailbox-proven submitter enrollment.
package submitter

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

const challengeTTL = 15 * time.Minute

var (
	ErrInvalidAddress = errors.New("invalid submitter address")
	ErrChallenge      = errors.New("challenge invalid or expired")
	ErrActiveAddress  = errors.New("submitter address is already active")
)

type Clock interface{ Now() time.Time }
type realClock struct{}

func (realClock) Now() time.Time { return time.Now().UTC() }

// Mailer is the sole delivery dependency of enrollment.
type Mailer interface {
	Send(context.Context, string, string, string) error
}

type Submitter struct {
	ID, Address, Status, PolicyVersion string
	CreatedAt                          time.Time
	VerifiedAt, RevokedAt              *time.Time
}
type Challenge struct {
	ID, SubmitterID, Address string
	ExpiresAt                time.Time
}
type Activation struct {
	Submitter         Submitter
	SubmissionAddress string
}

type Service struct {
	DB                      *sql.DB
	Mailer                  Mailer
	CapabilityKey           []byte
	CapabilityKeyID, Domain string
	Clock                   Clock
}

func CanonicalAddress(value string) (string, error) {
	if strings.IndexFunc(value, func(r rune) bool { return r <= 0x1f || r == 0x7f }) >= 0 {
		return "", ErrInvalidAddress
	}
	parsed, err := mail.ParseAddress(value)
	if err != nil || parsed.Address != value || strings.Count(value, "@") != 1 {
		return "", ErrInvalidAddress
	}
	parts := strings.Split(value, "@")
	if parts[0] == "" || parts[1] == "" || strings.HasPrefix(parts[1], "[") {
		return "", ErrInvalidAddress
	}
	domain, err := idna.Lookup.ToASCII(strings.ToLower(parts[1]))
	if err != nil {
		return "", ErrInvalidAddress
	}
	if domain == "" || strings.Contains(domain, "..") {
		return "", ErrInvalidAddress
	}
	return parts[0] + "@" + domain, nil
}

func (s Service) now() time.Time {
	if s.Clock != nil {
		return s.Clock.Now().UTC()
	}
	return realClock{}.Now()
}
func randomID(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}
func randomSecret(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func (s Service) digest(value string) ([]byte, error) {
	if len(s.CapabilityKey) < 32 {
		return nil, errors.New("capability HMAC key must be at least 32 bytes")
	}
	m := hmac.New(sha256.New, s.CapabilityKey)
	_, _ = m.Write([]byte(value))
	return m.Sum(nil), nil
}

func (s Service) Challenge(ctx context.Context, address string) (Challenge, error) {
	canonical, err := CanonicalAddress(address)
	if err != nil {
		return Challenge{}, err
	}
	if s.Mailer == nil {
		return Challenge{}, errors.New("challenge mailer is required")
	}
	now := s.now()
	id, err := randomID(16)
	if err != nil {
		return Challenge{}, err
	}
	code, err := randomSecret(24)
	if err != nil {
		return Challenge{}, err
	}
	digest, err := s.digest(code)
	if err != nil {
		return Challenge{}, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Challenge{}, fmt.Errorf("begin challenge: %w", err)
	}
	defer tx.Rollback()
	var active int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM submitters WHERE canonical_address=? AND status='active'", canonical).Scan(&active); err != nil {
		return Challenge{}, err
	}
	if active > 0 {
		return Challenge{}, ErrActiveAddress
	}
	submitterID, err := randomID(16)
	if err != nil {
		return Challenge{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO submitters(submitter_id,canonical_address,status,created_at,policy_version,minute_limit,hour_limit,day_limit) VALUES(?,?, 'pending',?,'v1',5,30,100)`, submitterID, canonical, now.Unix()); err != nil {
		// A pending identity can be challenged again; retain its audit history.
		if err = tx.QueryRowContext(ctx, "SELECT submitter_id FROM submitters WHERE canonical_address=? AND status='pending' ORDER BY created_at DESC LIMIT 1", canonical).Scan(&submitterID); err != nil {
			return Challenge{}, fmt.Errorf("create pending submitter: %w", err)
		}
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO submitter_challenges(challenge_id,submitter_id,code_digest,created_at,expires_at) VALUES(?,?,?,?,?)", id, submitterID, digest, now.Unix(), now.Add(challengeTTL).Unix()); err != nil {
		return Challenge{}, fmt.Errorf("store challenge: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return Challenge{}, fmt.Errorf("commit challenge: %w", err)
	}
	subject := "Mailproof submitter enrollment"
	body := fmt.Sprintf("Your Mailproof activation code is: %s\nIt expires in 15 minutes.\n", code)
	if err = s.Mailer.Send(ctx, canonical, subject, body); err != nil {
		return Challenge{}, fmt.Errorf("deliver challenge: %w", err)
	}
	return Challenge{ID: id, SubmitterID: submitterID, Address: canonical, ExpiresAt: now.Add(challengeTTL)}, nil
}

func (s Service) Activate(ctx context.Context, address, code string) (Activation, error) {
	canonical, err := CanonicalAddress(address)
	if err != nil {
		return Activation{}, err
	}
	digest, err := s.digest(code)
	if err != nil {
		return Activation{}, err
	}
	now := s.now()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Activation{}, err
	}
	defer tx.Rollback()
	var id, status, policy string
	var created int64
	err = tx.QueryRowContext(ctx, `SELECT s.submitter_id,s.status,s.policy_version,s.created_at FROM submitters s JOIN submitter_challenges c ON c.submitter_id=s.submitter_id WHERE s.canonical_address=? AND c.code_digest=? AND c.consumed_at IS NULL AND c.expires_at>=? ORDER BY c.created_at DESC LIMIT 1`, canonical, digest, now.Unix()).Scan(&id, &status, &policy, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return Activation{}, ErrChallenge
	}
	if err != nil {
		return Activation{}, err
	}
	if status == "active" {
		return Activation{}, ErrActiveAddress
	}
	capability, err := randomSecret(32)
	if err != nil {
		return Activation{}, err
	}
	capDigest, err := s.digest(capability)
	if err != nil {
		return Activation{}, err
	}
	capID, err := randomID(16)
	if err != nil {
		return Activation{}, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE submitter_challenges SET consumed_at=? WHERE submitter_id=? AND code_digest=? AND consumed_at IS NULL", now.Unix(), id, digest); err != nil {
		return Activation{}, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE submitters SET status='active',verified_at=? WHERE submitter_id=? AND status='pending'", now.Unix(), id); err != nil {
		return Activation{}, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO submission_capabilities(capability_id,submitter_id,digest,key_id,activated_at) VALUES(?,?,?,?,?)", capID, id, capDigest, s.CapabilityKeyID, now.Unix()); err != nil {
		return Activation{}, err
	}
	if err = tx.Commit(); err != nil {
		return Activation{}, err
	}
	verified := now
	return Activation{Submitter: Submitter{ID: id, Address: canonical, Status: "active", PolicyVersion: policy, CreatedAt: time.Unix(created, 0).UTC(), VerifiedAt: &verified}, SubmissionAddress: "verify+" + capability + "@" + s.Domain}, nil
}

func (s Service) List(ctx context.Context) ([]Submitter, error) {
	rows, err := s.DB.QueryContext(ctx, "SELECT submitter_id,canonical_address,status,created_at,verified_at,revoked_at,policy_version FROM submitters ORDER BY created_at")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Submitter
	for rows.Next() {
		var x Submitter
		var c int64
		var vn, rn sql.NullInt64
		if err := rows.Scan(&x.ID, &x.Address, &x.Status, &c, &vn, &rn, &x.PolicyVersion); err != nil {
			return nil, err
		}
		x.CreatedAt = time.Unix(c, 0).UTC()
		if vn.Valid {
			z := time.Unix(vn.Int64, 0).UTC()
			x.VerifiedAt = &z
		}
		if rn.Valid {
			z := time.Unix(rn.Int64, 0).UTC()
			x.RevokedAt = &z
		}
		out = append(out, x)
	}
	return out, rows.Err()
}
func (s Service) Revoke(ctx context.Context, id string) error {
	r, err := s.DB.ExecContext(ctx, "UPDATE submitters SET status='revoked',revoked_at=? WHERE submitter_id=? AND status='active'", s.now().Unix(), id)
	if err != nil {
		return err
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return errors.New("active submitter not found")
	}
	return nil
}
func (s Service) Rotate(ctx context.Context, id string) (string, error) {
	now := s.now()
	cap, err := randomSecret(32)
	if err != nil {
		return "", err
	}
	d, err := s.digest(cap)
	if err != nil {
		return "", err
	}
	cid, err := randomID(16)
	if err != nil {
		return "", err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	r, err := tx.ExecContext(ctx, "UPDATE submission_capabilities SET revoked_at=? WHERE submitter_id=? AND revoked_at IS NULL", now.Unix(), id)
	if err != nil {
		return "", err
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return "", errors.New("active capability not found")
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO submission_capabilities(capability_id,submitter_id,digest,key_id,activated_at) VALUES(?,?,?,?,?)", cid, id, d, s.CapabilityKeyID, now.Unix()); err != nil {
		return "", err
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	return "verify+" + cap + "@" + s.Domain, nil
}
