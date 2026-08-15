package admission

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"net/mail"
	"strconv"
	"strings"
	"time"

	"github.com/luganoplanb/mailproof/internal/submitter"
)

var ErrStamp = errors.New("invalid admission stamp")
var ErrSubjectFrom = errors.New("invalid selected-subject From")

// ConsumeStamp accepts exactly one Postfix-added stamp. Callers must pass only
// the bounded header prefix obtained from the sealed original; arbitrary
// message headers are never a source of ingress authentication.
func (s Service) ConsumeStamp(ctx context.Context, headers []string, queueID string) (Decision, error) {
	var stamp string
	for _, header := range headers {
		name, value, ok := strings.Cut(header, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "X-Mailproof-Admission") {
			if stamp != "" || len(value) > 2048 {
				return Decision{}, ErrStamp
			}
			stamp = strings.TrimSpace(value)
		}
	}
	if stamp == "" {
		return Decision{}, ErrStamp
	}
	payload64, mac64, ok := strings.Cut(stamp, ".")
	if !ok || strings.Contains(mac64, ".") {
		return Decision{}, ErrStamp
	}
	payload, err := base64.RawURLEncoding.DecodeString(payload64)
	if err != nil || !hmac.Equal(keyed(s.StampKey, string(payload)), mustDecode(mac64)) {
		return Decision{}, ErrStamp
	}
	parts := strings.Split(string(payload), "|")
	if len(parts) != 10 || parts[0] != "v1" {
		return Decision{}, ErrStamp
	}
	expires, err := strconv.ParseInt(parts[9], 10, 64)
	if err != nil || expires < s.now().Unix() {
		return Decision{}, ErrStamp
	}
	var decision Decision
	var expiry int64
	err = s.DB.QueryRowContext(ctx, `UPDATE submission_decisions SET consumed_at=? WHERE decision_id=? AND consumed_at IS NULL AND expires_at>=? AND queue_id=? RETURNING decision_id,submitter_id,envelope_sender,recipient,spf_outcome,stage,reason_code,policy_version,expires_at`, s.now().Unix(), parts[1], s.now().Unix(), queueID).Scan(&decision.ID, &decision.SubmitterID, &decision.Envelope, &decision.Recipient, &decision.SPF, &decision.Stage, &decision.Reason, &decision.PolicyVersion, &expiry)
	if err != nil {
		return Decision{}, ErrStamp
	}
	decision.ExpiresAt = time.Unix(expiry, 0).UTC()
	if decision.ID != parts[1] || decision.SubmitterID != parts[2] || decision.Envelope != parts[3] || decision.Recipient != parts[4] || decision.SPF != parts[7] || decision.PolicyVersion != parts[8] || decision.ExpiresAt.Unix() != expires {
		return Decision{}, ErrStamp
	}
	return decision, nil
}

func mustDecode(value string) []byte {
	b, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(b) != 32 {
		return nil
	}
	return b
}

// SelectedSubjectAllowed is the cheap post-seal preflight. An empty allowlist
// deliberately means syntax-only validation, not authentication.
func SelectedSubjectAllowed(from string, allowlist []string) (string, bool) {
	canonical, err := submitter.CanonicalAddress(from)
	if err != nil {
		return "", false
	}
	_, domain, _ := strings.Cut(canonical, "@")
	if len(allowlist) == 0 {
		return domain, true
	}
	for _, rule := range allowlist {
		rule = strings.ToLower(strings.TrimSpace(rule))
		if strings.HasPrefix(rule, "*.") {
			base := strings.TrimPrefix(rule, "*.")
			if strings.HasSuffix(domain, "."+base) && domain != base {
				return domain, true
			}
		} else if domain == rule {
			return domain, true
		}
	}
	return domain, false
}

// SelectedSubjectFrom extracts exactly one mailbox from a bounded selected
// subject. It deliberately does not consult wrapper headers.
func SelectedSubjectFrom(message []byte) (string, error) {
	if len(message) == 0 || len(message) > 64<<10 {
		return "", ErrSubjectFrom
	}
	m, err := mail.ReadMessage(bytes.NewReader(message))
	if err != nil {
		return "", ErrSubjectFrom
	}
	values := m.Header["From"]
	if len(values) != 1 {
		return "", ErrSubjectFrom
	}
	parsed, err := mail.ParseAddress(values[0])
	if err != nil {
		return "", ErrSubjectFrom
	}
	canonical, err := submitter.CanonicalAddress(parsed.Address)
	if err != nil {
		return "", ErrSubjectFrom
	}
	return canonical, nil
}
