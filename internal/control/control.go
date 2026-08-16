// Package control owns the internal, typed policy mutation use cases.
package control

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

const SchemaVersion = "mailproof.control/v1"
const confirmationTTL = 5 * time.Minute

var (
	ErrInvalid     = errors.New("invalid_request")
	ErrExpired     = errors.New("preview_expired")
	ErrConflict    = errors.New("policy_version_conflict")
	ErrReplay      = errors.New("idempotency_replayed")
	ErrUnsupported = errors.New("unsupported_command")
)

type Clock interface{ Now() time.Time }
type Service struct {
	DB                             *sql.DB
	ConfirmationKey, CapabilityKey []byte
	CapabilityDomain               string
	Clock                          Clock
}
type Command struct {
	SchemaVersion   string          `json:"schema_version"`
	CommandID       string          `json:"command_id"`
	CommandType     string          `json:"command_type"`
	ExpectedVersion int64           `json:"expected_policy_version"`
	Reason          string          `json:"reason"`
	IdempotencyKey  string          `json:"idempotency_key"`
	Command         json.RawMessage `json:"command"`
}
type Preview struct {
	SchemaVersion     string          `json:"schema_version"`
	ConfirmationToken string          `json:"confirmation_token"`
	BeforeDigest      string          `json:"before_digest"`
	AfterDigest       string          `json:"after_digest"`
	ExpiresAt         time.Time       `json:"expires_at"`
	Normalized        json.RawMessage `json:"normalized_command"`
	DryRun            bool            `json:"dry_run"`
	CurrentVersion    int64           `json:"current_version"`
	NextVersion       int64           `json:"next_version"`
}
type Confirmation struct {
	SchemaVersion     string `json:"schema_version"`
	CommandID         string `json:"command_id"`
	ExpectedVersion   int64  `json:"expected_policy_version"`
	IdempotencyKey    string `json:"idempotency_key"`
	ConfirmationToken string `json:"confirmation_token"`
	BeforeDigest      string `json:"before_digest"`
	AfterDigest       string `json:"after_digest"`
	Reason            string `json:"reason"`
	SessionID         string `json:"session_id"`
}
type Result struct {
	SchemaVersion string `json:"schema_version"`
	CommandID     string `json:"command_id"`
	PolicyVersion int64  `json:"policy_version"`
	ResultCode    string `json:"result_code"`
	Capability    string `json:"capability,omitempty"`
}
type policyQuery interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}
type effectiveRule struct {
	ID, Type, Subject, Value string
	ExpiresAt                *int64 `json:"expires_at,omitempty"`
}
type effectiveSubmitter struct {
	ID, Status        string
	Minute, Hour, Day int
}
type effectiveCapability struct{ SubmitterID, Digest string }
type effectivePolicy struct {
	Rules        []effectiveRule       `json:"rules"`
	Submitters   []effectiveSubmitter  `json:"submitters"`
	Capabilities []effectiveCapability `json:"capabilities"`
}

func (s Service) now() time.Time {
	if s.Clock != nil {
		return s.Clock.Now().UTC()
	}
	return time.Now().UTC()
}
func allowed(t string) bool {
	switch t {
	case "quota_change", "submitter_suspend", "submitter_reactivate", "capability_rotate", "subject_allowlist_put", "peer_block_put", "outer_domain_block_put", "subject_domain_block_put":
		return true
	}
	return false
}
func canonical(c Command) ([]byte, error) {
	if c.SchemaVersion != SchemaVersion || !allowed(c.CommandType) || len(c.CommandID) < 16 || len(c.CommandID) > 128 || len(c.IdempotencyKey) < 16 || len(c.IdempotencyKey) > 128 || len(strings.TrimSpace(c.Reason)) < 8 || len(c.Reason) > 512 || c.ExpectedVersion < 0 || len(c.Command) == 0 {
		return nil, ErrInvalid
	}
	var v any
	if err := json.Unmarshal(c.Command, &v); err != nil {
		return nil, ErrInvalid
	}
	if err := validateOperation(c.CommandType, c.Command); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Type    string `json:"command_type"`
		Command any    `json:"command"`
	}{c.CommandType, v})
}

// validateOperation rejects commands that are syntactically valid JSON but
// cannot be applied. A preview is therefore a commitment to one real operation.
func validateOperation(typ string, raw []byte) error {
	var v struct {
		SubmitterID string `json:"submitter_id"`
		RuleID      string `json:"rule_id"`
		Value       string `json:"value"`
		Expiry      string `json:"expiry"`
		Enabled     *bool  `json:"enabled"`
		MinuteLimit int    `json:"minute_limit"`
		HourLimit   int    `json:"hour_limit"`
		DayLimit    int    `json:"day_limit"`
	}
	if json.Unmarshal(raw, &v) != nil {
		return ErrInvalid
	}
	switch typ {
	case "quota_change":
		if v.SubmitterID == "" || v.MinuteLimit < 1 || v.HourLimit < 1 || v.DayLimit < 1 {
			return ErrInvalid
		}
	case "submitter_suspend", "submitter_reactivate", "capability_rotate":
		if v.SubmitterID == "" {
			return ErrInvalid
		}
	case "peer_block_put", "subject_allowlist_put", "outer_domain_block_put", "subject_domain_block_put":
		if v.Enabled != nil && !*v.Enabled {
			if v.RuleID == "" {
				return ErrInvalid
			}
			return nil
		}
		if v.Value == "" {
			return ErrInvalid
		}
		if typ == "peer_block_put" {
			if ip := net.ParseIP(v.Value); ip == nil {
				if _, _, err := net.ParseCIDR(v.Value); err != nil {
					return ErrInvalid
				}
			}
		} else if !validDomainRule(v.Value, typ == "subject_allowlist_put") {
			return ErrInvalid
		}
		if v.Expiry != "" {
			t, err := time.Parse(time.RFC3339, v.Expiry)
			if err != nil || t.Location() != time.UTC {
				return ErrInvalid
			}
		}
	default:
		return ErrUnsupported
	}
	return nil
}
func digest(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
func validDomainRule(v string, wildcard bool) bool {
	if wildcard && strings.HasPrefix(v, "*.") {
		v = strings.TrimPrefix(v, "*.")
	} else if strings.HasPrefix(v, "*.") {
		return false
	}
	return v != "" && !strings.ContainsAny(v, " /@") && strings.Contains(v, ".")
}
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func (s Service) mac(v string) []byte {
	h := hmac.New(sha256.New, s.ConfirmationKey)
	_, _ = h.Write([]byte(v))
	return h.Sum(nil)
}

func effectivePolicyState(ctx context.Context, q policyQuery, now time.Time) (effectivePolicy, error) {
	state := effectivePolicy{}
	rules, err := q.QueryContext(ctx, "SELECT rule_id,rule_type,subject,value,expires_at FROM policy_rules WHERE enabled=1 AND (expires_at IS NULL OR expires_at>?) ORDER BY rule_type,subject,value,rule_id", now.Unix())
	if err != nil {
		return state, err
	}
	defer rules.Close()
	for rules.Next() {
		var r effectiveRule
		var expiry sql.NullInt64
		if err = rules.Scan(&r.ID, &r.Type, &r.Subject, &r.Value, &expiry); err != nil {
			return state, err
		}
		if expiry.Valid {
			x := expiry.Int64
			r.ExpiresAt = &x
		}
		state.Rules = append(state.Rules, r)
	}
	if err = rules.Err(); err != nil {
		return state, err
	}
	submitters, err := q.QueryContext(ctx, "SELECT submitter_id,status,minute_limit,hour_limit,day_limit FROM submitters ORDER BY submitter_id")
	if err != nil {
		return state, err
	}
	defer submitters.Close()
	for submitters.Next() {
		var x effectiveSubmitter
		if err = submitters.Scan(&x.ID, &x.Status, &x.Minute, &x.Hour, &x.Day); err != nil {
			return state, err
		}
		state.Submitters = append(state.Submitters, x)
	}
	if err = submitters.Err(); err != nil {
		return state, err
	}
	caps, err := q.QueryContext(ctx, "SELECT submitter_id,lower(hex(digest)) FROM submission_capabilities WHERE revoked_at IS NULL ORDER BY submitter_id,digest")
	if err != nil {
		return state, err
	}
	defer caps.Close()
	for caps.Next() {
		var x effectiveCapability
		if err = caps.Scan(&x.SubmitterID, &x.Digest); err != nil {
			return state, err
		}
		state.Capabilities = append(state.Capabilities, x)
	}
	return state, caps.Err()
}

func projectedPolicyDigest(state effectivePolicy, typ string, raw []byte, now time.Time, capabilityDigest string) (string, error) {
	var wrapped struct {
		Command json.RawMessage `json:"command"`
	}
	if json.Unmarshal(raw, &wrapped) == nil && len(wrapped.Command) != 0 {
		raw = wrapped.Command
	}
	var v struct {
		SubmitterID string `json:"submitter_id"`
		RuleID      string `json:"rule_id"`
		Value       string `json:"value"`
		Subject     string `json:"subject"`
		Expiry      string `json:"expiry"`
		Enabled     *bool  `json:"enabled"`
		MinuteLimit int    `json:"minute_limit"`
		HourLimit   int    `json:"hour_limit"`
		DayLimit    int    `json:"day_limit"`
	}
	if json.Unmarshal(raw, &v) != nil {
		return "", ErrInvalid
	}
	switch typ {
	case "quota_change":
		for i := range state.Submitters {
			if state.Submitters[i].ID == v.SubmitterID {
				state.Submitters[i].Minute, state.Submitters[i].Hour, state.Submitters[i].Day = v.MinuteLimit, v.HourLimit, v.DayLimit
			}
		}
	case "submitter_suspend":
		for i := range state.Submitters {
			if state.Submitters[i].ID == v.SubmitterID {
				state.Submitters[i].Status = "revoked"
			}
		}
	case "submitter_reactivate":
		for i := range state.Submitters {
			if state.Submitters[i].ID == v.SubmitterID {
				state.Submitters[i].Status = "active"
			}
		}
	case "peer_block_put", "subject_allowlist_put", "outer_domain_block_put", "subject_domain_block_put":
		if v.Enabled != nil && !*v.Enabled {
			for i := range state.Rules {
				if state.Rules[i].ID == v.RuleID {
					state.Rules = append(state.Rules[:i], state.Rules[i+1:]...)
					break
				}
			}
		} else {
			r := effectiveRule{Type: typ, Subject: v.Subject, Value: v.Value}
			if v.Expiry != "" {
				t, e := time.Parse(time.RFC3339, v.Expiry)
				if e != nil {
					return "", ErrInvalid
				}
				x := t.Unix()
				r.ExpiresAt = &x
			}
			state.Rules = append(state.Rules, r)
		}
	case "capability_rotate":
		for i := range state.Capabilities {
			if state.Capabilities[i].SubmitterID == v.SubmitterID {
				state.Capabilities = append(state.Capabilities[:i], state.Capabilities[i+1:]...)
				break
			}
		}
		if capabilityDigest == "" {
			return "", ErrInvalid
		}
		state.Capabilities = append(state.Capabilities, effectiveCapability{SubmitterID: v.SubmitterID, Digest: capabilityDigest})
	}
	// Rule IDs are storage identities, not policy semantics; omit them from evidence.
	for i := range state.Rules {
		state.Rules[i].ID = ""
	}
	sort.Slice(state.Rules, func(i, j int) bool {
		a, b := state.Rules[i], state.Rules[j]
		return a.Type+a.Subject+a.Value < b.Type+b.Subject+b.Value
	})
	sort.Slice(state.Submitters, func(i, j int) bool { return state.Submitters[i].ID < state.Submitters[j].ID })
	sort.Slice(state.Capabilities, func(i, j int) bool {
		return state.Capabilities[i].SubmitterID+state.Capabilities[i].Digest < state.Capabilities[j].SubmitterID+state.Capabilities[j].Digest
	})
	b, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	return digest(b), nil
}

func rotatedCapability(key []byte, confirmationToken string) string {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte("control-rotate:" + confirmationToken))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
func digestCapability(key []byte, capability string) string {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(capability))
	return hex.EncodeToString(h.Sum(nil))
}

// Preview validates a command and writes only its single-use confirmation record.
func (s Service) Preview(ctx context.Context, session string, c Command) (Preview, error) {
	if s.DB == nil || len(s.ConfirmationKey) < 32 || len(session) < 16 {
		return Preview{}, ErrInvalid
	}
	b, err := canonical(c)
	if err != nil {
		return Preview{}, err
	}
	now := s.now()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Preview{}, err
	}
	defer tx.Rollback()
	var version int64
	if err = tx.QueryRowContext(ctx, "SELECT MAX(version) FROM policy_versions").Scan(&version); err != nil {
		return Preview{}, err
	}
	if version != c.ExpectedVersion {
		return Preview{}, ErrConflict
	}
	state, err := effectivePolicyState(ctx, tx, now)
	if err != nil {
		return Preview{}, err
	}
	raw, err := randomToken()
	if err != nil {
		return Preview{}, err
	}
	before, err := projectedPolicyDigest(state, "", []byte(`{}`), now, "")
	if err != nil {
		return Preview{}, err
	}
	capabilityDigest := ""
	if c.CommandType == "capability_rotate" {
		capabilityDigest = digestCapability(s.CapabilityKey, rotatedCapability(s.CapabilityKey, raw))
	}
	after, err := projectedPolicyDigest(state, c.CommandType, c.Command, now, capabilityDigest)
	if err != nil {
		return Preview{}, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO confirmation_tokens(token_digest,command_digest,session_id,expected_version,expires_at,command_json,command_type,command_id,idempotency_key,reason,before_digest) VALUES(?,?,?,?,?,?,?,?,?,?,?)", s.mac(raw), after, session, version, now.Add(confirmationTTL).Unix(), b, c.CommandType, c.CommandID, c.IdempotencyKey, c.Reason, before); err != nil {
		return Preview{}, err
	}
	if err = tx.Commit(); err != nil {
		return Preview{}, err
	}
	return Preview{SchemaVersion: SchemaVersion, ConfirmationToken: raw, BeforeDigest: before, AfterDigest: after, ExpiresAt: now.Add(confirmationTTL), Normalized: b, DryRun: true, CurrentVersion: version, NextVersion: version + 1}, nil
}

// Confirm atomically consumes a preview and appends command/audit facts.
func (s Service) Confirm(ctx context.Context, x Confirmation) (Result, error) {
	if s.DB == nil || len(s.ConfirmationKey) < 32 || x.SchemaVersion != SchemaVersion || len(x.SessionID) < 16 || len(x.ConfirmationToken) < 32 || len(strings.TrimSpace(x.Reason)) < 8 {
		return Result{}, ErrInvalid
	}
	now := s.now()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Result{}, err
	}
	defer tx.Rollback()
	var commandDigest, session, commandType, commandID, idempotencyKey, reason, beforeDigest string
	var commandJSON []byte
	var version, expiry int64
	var consumed sql.NullInt64
	err = tx.QueryRowContext(ctx, "SELECT command_digest,session_id,expected_version,expires_at,consumed_at,command_json,command_type,command_id,idempotency_key,reason,before_digest FROM confirmation_tokens WHERE token_digest=?", s.mac(x.ConfirmationToken)).Scan(&commandDigest, &session, &version, &expiry, &consumed, &commandJSON, &commandType, &commandID, &idempotencyKey, &reason, &beforeDigest)
	if errors.Is(err, sql.ErrNoRows) || now.Unix() > expiry {
		return Result{}, ErrExpired
	}
	if err != nil {
		return Result{}, err
	}
	if consumed.Valid {
		return Result{}, ErrReplay
	}
	if session != x.SessionID || version != x.ExpectedVersion || commandDigest != x.AfterDigest || commandID != x.CommandID || idempotencyKey != x.IdempotencyKey || reason != x.Reason || beforeDigest != x.BeforeDigest {
		return Result{}, ErrExpired
	}
	var current int64
	if err = tx.QueryRowContext(ctx, "SELECT MAX(version) FROM policy_versions").Scan(&current); err != nil {
		return Result{}, err
	}
	if current != version {
		return Result{}, ErrConflict
	}
	var duplicate int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM control_commands WHERE idempotency_key=?", idempotencyKey).Scan(&duplicate); err != nil {
		return Result{}, err
	}
	if duplicate != 0 {
		return Result{}, ErrReplay
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO policy_versions(version,created_at,command_id,digest) VALUES(?,?,?,?)", current+1, now.Unix(), commandID, commandDigest); err != nil {
		return Result{}, err
	}
	capability := ""
	if commandType == "capability_rotate" {
		capability, err = rotate(ctx, tx, commandJSON, s.CapabilityKey, s.CapabilityDomain, now, rotatedCapability(s.CapabilityKey, x.ConfirmationToken))
		if err != nil {
			return Result{}, err
		}
	} else if err = apply(ctx, tx, commandType, commandJSON, current+1, now); err != nil {
		return Result{}, err
	}
	actualState, err := effectivePolicyState(ctx, tx, now)
	if err != nil {
		return Result{}, err
	}
	actualAfter, err := projectedPolicyDigest(actualState, "", []byte(`{}`), now, "")
	if err != nil {
		return Result{}, err
	}
	if actualAfter != commandDigest {
		return Result{}, ErrConflict
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO control_commands(command_id,idempotency_key,command_type,command_digest,expected_version,result_version,result_code,created_at) VALUES(?,?,?,?,?,?,?,?)", commandID, idempotencyKey, commandType, commandDigest, current, current+1, "applied", now.Unix()); err != nil {
		return Result{}, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE confirmation_tokens SET consumed_at=? WHERE token_digest=? AND consumed_at IS NULL", now.Unix(), s.mac(x.ConfirmationToken)); err != nil {
		return Result{}, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO audit_events(command_id,actor,session_id,command_type,result_code,before_digest,after_digest,reason,created_at) VALUES(?,?,?,?,?,?,?,?,?)", commandID, "unauthenticated-local", session, commandType, "applied", beforeDigest, commandDigest, reason, now.Unix()); err != nil {
		return Result{}, err
	}
	if err = tx.Commit(); err != nil {
		return Result{}, err
	}
	return Result{SchemaVersion: SchemaVersion, CommandID: commandID, PolicyVersion: current + 1, ResultCode: "applied", Capability: capability}, nil
}

func rotate(ctx context.Context, tx *sql.Tx, raw, key []byte, domain string, now time.Time, secret string) (string, error) {
	if len(key) < 32 || domain == "" {
		return "", ErrInvalid
	}
	var wrap struct {
		Command json.RawMessage `json:"command"`
	}
	if json.Unmarshal(raw, &wrap) == nil && len(wrap.Command) > 0 {
		raw = wrap.Command
	}
	var x struct {
		SubmitterID string `json:"submitter_id"`
	}
	if json.Unmarshal(raw, &x) != nil || x.SubmitterID == "" {
		return "", ErrInvalid
	}
	if secret == "" {
		return "", ErrInvalid
	}
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(secret))
	d := h.Sum(nil)
	id, e := randomToken()
	if e != nil {
		return "", e
	}
	r, e := tx.ExecContext(ctx, "UPDATE submission_capabilities SET revoked_at=? WHERE submitter_id=? AND revoked_at IS NULL", now.Unix(), x.SubmitterID)
	if e != nil {
		return "", e
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return "", ErrInvalid
	}
	_, e = tx.ExecContext(ctx, "INSERT INTO submission_capabilities(capability_id,submitter_id,digest,key_id,activated_at) VALUES(?,?,?,?,?)", id, x.SubmitterID, d, "control", now.Unix())
	if e != nil {
		return "", e
	}
	return "verify+" + secret + "@" + domain, nil
}

func apply(ctx context.Context, tx *sql.Tx, typ string, raw []byte, version int64, now time.Time) error {
	var wrapped struct {
		Command json.RawMessage `json:"command"`
	}
	if json.Unmarshal(raw, &wrapped) == nil && len(wrapped.Command) != 0 {
		raw = wrapped.Command
	}
	var v struct {
		SubmitterID string `json:"submitter_id"`
		RuleID      string `json:"rule_id"`
		Value       string `json:"value"`
		Subject     string `json:"subject"`
		Expiry      string `json:"expiry"`
		Enabled     *bool  `json:"enabled"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return ErrInvalid
	}
	switch typ {
	case "quota_change":
		var q struct {
			SubmitterID       string `json:"submitter_id"`
			Minute, Hour, Day int    `json:"-"`
			MinuteLimit       int    `json:"minute_limit"`
			HourLimit         int    `json:"hour_limit"`
			DayLimit          int    `json:"day_limit"`
		}
		if json.Unmarshal(raw, &q) != nil || q.SubmitterID == "" || q.MinuteLimit < 1 || q.HourLimit < 1 || q.DayLimit < 1 {
			return ErrInvalid
		}
		r, e := tx.ExecContext(ctx, "UPDATE submitters SET minute_limit=?,hour_limit=?,day_limit=?,policy_version=? WHERE submitter_id=?", q.MinuteLimit, q.HourLimit, q.DayLimit, fmt.Sprintf("v%d", version), q.SubmitterID)
		if e != nil {
			return e
		}
		n, _ := r.RowsAffected()
		if n != 1 {
			return ErrInvalid
		}
	case "submitter_suspend":
		r, e := tx.ExecContext(ctx, "UPDATE submitters SET status='revoked',revoked_at=? WHERE submitter_id=? AND status='active'", now.Unix(), v.SubmitterID)
		if e != nil {
			return e
		}
		n, _ := r.RowsAffected()
		if n != 1 {
			return ErrInvalid
		}
		return nil
	case "submitter_reactivate":
		r, e := tx.ExecContext(ctx, "UPDATE submitters SET status='active',revoked_at=NULL WHERE submitter_id=? AND status='revoked'", v.SubmitterID)
		if e != nil {
			return e
		}
		n, _ := r.RowsAffected()
		if n != 1 {
			return ErrInvalid
		}
		return nil
	case "subject_allowlist_put", "peer_block_put", "outer_domain_block_put", "subject_domain_block_put":
		if v.Enabled != nil && !*v.Enabled {
			if v.RuleID == "" {
				return ErrInvalid
			}
			r, e := tx.ExecContext(ctx, "UPDATE policy_rules SET enabled=0,version=? WHERE rule_id=? AND rule_type=? AND enabled=1", version, v.RuleID, typ)
			if e != nil {
				return e
			}
			n, _ := r.RowsAffected()
			if n != 1 {
				return ErrInvalid
			}
			return nil
		}
		if v.Value == "" {
			return ErrInvalid
		}
		exp := any(nil)
		if v.Expiry != "" {
			t, e := time.Parse(time.RFC3339, v.Expiry)
			if e != nil || !t.After(now) {
				return ErrInvalid
			}
			exp = t.Unix()
		}
		_, e := tx.ExecContext(ctx, "INSERT INTO policy_rules(rule_id,version,rule_type,subject,value,expires_at,created_at) VALUES(lower(hex(randomblob(16))),?,?,?,?,?,?)", version, typ, v.Subject, v.Value, exp, now.Unix())
		return e
	case "capability_rotate":
		return ErrUnsupported
	default:
		return ErrUnsupported
	}
	return nil
}
