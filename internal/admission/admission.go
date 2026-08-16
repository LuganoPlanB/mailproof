package admission

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
	"log"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/luganoplanb/mailproof/internal/analytics"

	"github.com/luganoplanb/mailproof/internal/submitter"
)

const (
	maxCapability = 128
	maxAttribute  = 1024
	stampTTL      = 10 * time.Minute
)

var (
	ErrMalformed = errors.New("malformed policy request")
	// ErrBootstrapPolicyExists prevents a legacy file from silently being ignored
	// after an operator has already established managed policy.
	ErrBootstrapPolicyExists = errors.New("managed policy exists; bootstrap import refused")
	ErrDenied                = errors.New("submission denied")
	ErrDeferred              = errors.New("submission temporarily unavailable")
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
	ID, SubmitterID, Envelope, Recipient, SPF, Reason, Stage, PolicyVersion, PolicyRuleID, Stamp string
	ExpiresAt                                                                                    time.Time
}
type Service struct {
	DB                      *sql.DB
	CapabilityKey, StampKey []byte
	Domain                  string
	Resolver                SPFResolver
	Clock                   Clock
	Policy                  *PolicySnapshot
	PolicyStore             *SnapshotStore
}
type PolicyRule struct {
	ID        string
	ExpiresAt time.Time
}

func (r PolicyRule) Active(now time.Time) bool {
	return r.ExpiresAt.IsZero() || r.ExpiresAt.After(now)
}

type PolicySnapshot struct {
	Version        int64
	PeerCIDRs      []CIDRRule
	OuterDomains   map[string]PolicyRule
	SubjectDomains map[string]PolicyRule
	SubjectAllow   []DomainRule
	Submitters     map[string]SubmitterPolicy
}
type SubmitterPolicy struct {
	ID, Address, Status, PolicyVersion string
	Minute, Hour, Day                  int
}
type CIDRRule struct {
	PolicyRule
	CIDR *net.IPNet
}
type DomainRule struct {
	PolicyRule
	Domain   string
	Wildcard bool
}
type SnapshotStore struct {
	DB           *sql.DB
	Now          func() time.Time
	PollInterval time.Duration
	value        atomic.Pointer[PolicySnapshot]
}

func (s *SnapshotStore) Refresh(ctx context.Context) error {
	if s.DB == nil {
		return errors.New("policy snapshot database is required")
	}
	now := time.Now().UTC()
	if s.Now != nil {
		now = s.Now().UTC()
	}
	p, e := LoadPolicySnapshot(ctx, s.DB, now)
	if e != nil {
		return e
	}
	s.value.Store(p)
	return nil
}
func (s *SnapshotStore) Snapshot() *PolicySnapshot { return s.value.Load() }
func (s *SnapshotStore) Current(ctx context.Context) (*PolicySnapshot, error) {
	if p := s.Snapshot(); p != nil {
		return p, nil
	}
	if err := s.Refresh(ctx); err != nil {
		return nil, err
	}
	return s.Snapshot(), nil
}
func (s *SnapshotStore) Poll(ctx context.Context) {
	interval := s.PollInterval
	if interval == 0 {
		interval = 5 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = s.Refresh(ctx)
		}
	}
}
func (s *SnapshotStore) Ready() bool { return s.Snapshot() != nil }

func (p *PolicySnapshot) VersionID() int64 {
	if p == nil {
		return 0
	}
	return p.Version
}

func LoadPolicySnapshot(ctx context.Context, db *sql.DB, now time.Time) (*PolicySnapshot, error) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var v int64
	if err := tx.QueryRowContext(ctx, "SELECT MAX(version) FROM policy_versions").Scan(&v); err != nil {
		return nil, err
	}
	p := &PolicySnapshot{Version: v, OuterDomains: map[string]PolicyRule{}, SubjectDomains: map[string]PolicyRule{}, SubjectAllow: []DomainRule{}, Submitters: map[string]SubmitterPolicy{}}
	rows, err := tx.QueryContext(ctx, "SELECT rule_id,rule_type,value,expires_at FROM policy_rules WHERE enabled=1")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, typ, value string
		var expiry sql.NullInt64
		if err = rows.Scan(&id, &typ, &value, &expiry); err != nil {
			return nil, err
		}
		rule := PolicyRule{ID: id}
		if expiry.Valid {
			rule.ExpiresAt = time.Unix(expiry.Int64, 0).UTC()
		}
		switch typ {
		case "peer_block_put":
			var n *net.IPNet
			if ip := net.ParseIP(value); ip != nil {
				bits := 128
				if ip.To4() != nil {
					bits = 32
					ip = ip.To4()
				}
				n = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
			} else {
				_, n, err = net.ParseCIDR(value)
				if err != nil {
					return nil, err
				}
			}
			p.PeerCIDRs = append(p.PeerCIDRs, CIDRRule{PolicyRule: rule, CIDR: n})
		case "outer_domain_block_put":
			p.OuterDomains[strings.ToLower(value)] = rule
		case "subject_domain_block_put":
			p.SubjectDomains[strings.ToLower(value)] = rule
		case "subject_allowlist_put":
			p.SubjectAllow = append(p.SubjectAllow, DomainRule{PolicyRule: rule, Domain: strings.TrimPrefix(strings.ToLower(value), "*."), Wildcard: strings.HasPrefix(value, "*.")})
		}
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	caps, err := tx.QueryContext(ctx, `SELECT hex(c.digest),s.submitter_id,s.canonical_address,s.status,s.policy_version,s.minute_limit,s.hour_limit,s.day_limit FROM submission_capabilities c JOIN submitters s ON s.submitter_id=c.submitter_id WHERE c.revoked_at IS NULL`)
	if err != nil {
		return nil, err
	}
	defer caps.Close()
	for caps.Next() {
		var digest string
		var item SubmitterPolicy
		if err = caps.Scan(&digest, &item.ID, &item.Address, &item.Status, &item.PolicyVersion, &item.Minute, &item.Hour, &item.Day); err != nil {
			return nil, err
		}
		p.Submitters[strings.ToLower(digest)] = item
	}
	if err = caps.Err(); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return p, nil
}
func BootstrapImport(ctx context.Context, db *sql.DB, filePath string, now time.Time) error {
	raw, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var marker, versions int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM policy_bootstrap").Scan(&marker); err != nil {
		return err
	}
	if marker != 0 {
		return nil
	}
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM policy_versions WHERE version>0").Scan(&versions); err != nil {
		return err
	}
	if versions != 0 {
		sum := sha256.Sum256(raw)
		count := 0
		for _, line := range strings.Split(string(raw), "\n") {
			if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
				count++
			}
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO policy_bootstrap_observations(observed_at,source_digest,source_count,outcome) VALUES(?,?,?,?)", now.Unix(), hex.EncodeToString(sum[:]), count, "managed_policy_exists"); err != nil {
			return err
		}
		log.Printf("mailproof: legacy subject policy unchanged because managed policy exists (entries=%d source_digest=%s)", count, hex.EncodeToString(sum[:]))
		return tx.Commit()
	}
	sum := sha256.Sum256(raw)
	sourceDigest := hex.EncodeToString(sum[:])
	if _, err = tx.ExecContext(ctx, "INSERT INTO policy_versions(version,created_at,command_id,digest) VALUES(1,?,?,?)", now.Unix(), "bootstrap-import", sourceDigest); err != nil {
		return err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, ok := SelectedSubjectAllowed("a@"+strings.TrimPrefix(line, "*."), []string{line}); !ok {
			return ErrMalformed
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO policy_rules(rule_id,version,rule_type,subject,value,created_at) VALUES(lower(hex(randomblob(16))),1,'subject_allowlist_put','',?,?)", line, now.Unix()); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO policy_bootstrap(singleton,imported_at,source_digest) VALUES(1,?,?)", now.Unix(), sourceDigest)
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (p *PolicySnapshot) BlockedSubject(domain string, now time.Time) (PolicyRule, bool) {
	if p == nil {
		return PolicyRule{}, false
	}
	rule, ok := p.SubjectDomains[strings.ToLower(domain)]
	return rule, ok && rule.Active(now)
}
func (p *PolicySnapshot) SubjectAllowed(from string, allowlist []string, now time.Time) (string, bool, string) {
	domain, ok := SelectedSubjectAllowed(from, allowlist)
	if !ok {
		return domain, false, ""
	}
	if rule, blocked := p.BlockedSubject(domain, now); blocked {
		return domain, false, rule.ID
	}
	if p == nil || len(p.SubjectAllow) == 0 {
		return domain, true, ""
	}
	for _, rule := range p.SubjectAllow {
		if !rule.Active(now) {
			continue
		}
		if (!rule.Wildcard && domain == rule.Domain) || (rule.Wildcard && domain != rule.Domain && strings.HasSuffix(domain, "."+rule.Domain)) {
			return domain, true, rule.ID
		}
	}
	return domain, false, ""
}

type PreflightDecision struct {
	Domain, RuleID string
	Allowed        bool
	PolicyVersion  int64
}

func Preflight(snapshot *PolicySnapshot, from string, allowlist []string, now time.Time) PreflightDecision {
	if snapshot == nil {
		domain, ok := SelectedSubjectAllowed(from, allowlist)
		return PreflightDecision{Domain: domain, Allowed: ok}
	}
	domain, ok, ruleID := snapshot.SubjectAllowed(from, allowlist, now)
	return PreflightDecision{Domain: domain, Allowed: ok, RuleID: ruleID, PolicyVersion: snapshot.Version}
}
func PreflightAllowed(snapshot *PolicySnapshot, from string, allowlist []string) (string, bool, int64) {
	d := Preflight(snapshot, from, allowlist, time.Now().UTC())
	return d.Domain, d.Allowed, d.PolicyVersion
}
func (p *PolicySnapshot) BlockedPeer(raw string, now time.Time) (PolicyRule, bool) {
	if p == nil {
		return PolicyRule{}, false
	}
	ip := net.ParseIP(raw)
	for _, rule := range p.PeerCIDRs {
		if rule.Active(now) && rule.CIDR.Contains(ip) {
			return rule.PolicyRule, true
		}
	}
	return PolicyRule{}, false
}
func (p *PolicySnapshot) BlockedOuter(domain string, now time.Time) (PolicyRule, bool) {
	if p == nil {
		return PolicyRule{}, false
	}
	rule, ok := p.OuterDomains[strings.ToLower(domain)]
	return rule, ok && rule.Active(now)
}

func (s Service) snapshot() *PolicySnapshot {
	if s.PolicyStore != nil {
		return s.PolicyStore.Snapshot()
	}
	return s.Policy
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
	snapshot := s.snapshot()
	if snapshot == nil {
		return Decision{}, ErrDeferred
	}
	if rule, blocked := snapshot.BlockedPeer(r.ClientAddress, s.now()); blocked {
		return s.reject(ctx, r, "policy", "peer_blocked", "", snapshot.Version, rule.ID), ErrDenied
	}
	envelope, err := submitter.CanonicalAddress(r.Sender)
	if err != nil {
		return s.reject(ctx, r, "identity", "invalid_sender", "", 0, ""), ErrDenied
	}
	if rule, blocked := snapshot.BlockedOuter(strings.Split(envelope, "@")[1], s.now()); blocked {
		return s.reject(ctx, r, "policy", "outer_domain_blocked", "", snapshot.Version, rule.ID), ErrDenied
	}
	cap, err := capability(r.Recipient, s.Domain)
	if err != nil {
		return s.reject(ctx, r, "identity", "invalid_capability", "", 0, ""), ErrDenied
	}
	digest := keyed(s.CapabilityKey, cap)
	item, ok := snapshot.Submitters[hex.EncodeToString(digest)]
	if !ok || item.Status != "active" {
		return s.reject(ctx, r, "identity", "unknown_capability", "", 0, ""), ErrDenied
	}
	if envelope != item.Address {
		return s.reject(ctx, r, "identity", "envelope_mismatch", item.ID, 0, ""), ErrDenied
	}
	spf, err := s.Resolver.Check(ctx, envelope, r.Helo, net.ParseIP(r.ClientAddress))
	if err != nil {
		return Decision{}, ErrDeferred
	}
	if spf != "pass" {
		return s.reject(ctx, r, "spf", "spf_"+spf, item.ID, 0, ""), ErrDenied
	}
	if item.Minute < 1 || item.Hour < 1 || item.Day < 1 {
		return s.reject(ctx, r, "quota", "invalid_limit", item.ID, 0, ""), ErrDenied
	}
	return s.admit(ctx, r, item.ID, envelope, fmt.Sprintf("v%d", snapshot.Version), digest, item.Minute, item.Hour, item.Day)
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
func (s Service) reject(ctx context.Context, r Request, stage, reason, submitterID string, policyVersion int64, ruleID string) Decision {
	id, err := decisionID()
	if err != nil {
		return Decision{Stage: stage, Reason: reason}
	}
	version := "v1"
	if policyVersion > 0 {
		version = fmt.Sprintf("v%d", policyVersion)
	}
	d := Decision{ID: id, SubmitterID: submitterID, Envelope: r.Sender, Recipient: r.Recipient, Stage: stage, Reason: reason, PolicyVersion: version, PolicyRuleID: ruleID}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err == nil {
		_ = s.store(ctx, tx, d, r, nil, s.now())
		_ = tx.Commit()
	}
	return d
}
func (s Service) store(ctx context.Context, tx *sql.Tx, d Decision, r Request, digest []byte, now time.Time) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO submission_decisions(decision_id,submitter_id,capability_digest,envelope_sender,recipient,peer_ip,helo,spf_outcome,stage,reason_code,policy_version,applied_rule_id,queue_id,stamp_mac,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, d.ID, nilOr(d.SubmitterID), digest, d.Envelope, d.Recipient, r.ClientAddress, r.Helo, d.SPF, d.Stage, d.Reason, d.PolicyVersion, d.PolicyRuleID, r.QueueID, keyed(s.StampKey, d.Stamp), nullUnix(d.ExpiresAt), now.Unix())
	if err != nil {
		return err
	}
	// Stable struct field order is the retained canonical decision representation;
	// it excludes capabilities, recipient addresses, peer IPs, and stamps.
	canonical, err := json.Marshal(struct {
		ID, Outcome, Stage, Reason, Policy, RuleID string
		OccurredAt                                 int64 `json:"occurred_at"`
	}{ID: d.ID, Outcome: decisionOutcome(d.Reason), Stage: d.Stage, Reason: d.Reason, Policy: d.PolicyVersion, RuleID: d.PolicyRuleID, OccurredAt: now.Unix()})
	if err != nil {
		return err
	}
	digestText := sha256.Sum256(canonical)
	status := "queued"
	if _, err = tx.ExecContext(ctx, `INSERT INTO decision_records(decision_id,submitter_id,occurred_at,outcome,stage,reason_code,policy_version,applied_rule_id,smtp_class,canonical_json,canonical_digest,notarization_status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(decision_id) DO NOTHING`, d.ID, nilOr(d.SubmitterID), now.Unix(), decisionOutcome(d.Reason), d.Stage, d.Reason, d.PolicyVersion, d.PolicyRuleID, smtpClass(d.Reason), canonical, hex.EncodeToString(digestText[:]), status); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO decision_signing_outbox(decision_id,state,created_at) VALUES(?,'pending',?) ON CONFLICT(decision_id) DO NOTHING`, d.ID, now.Unix())
	if err != nil {
		return err
	}
	e, err := analytics.NewLifecycle("admission", "decision", d.ID, "admission_decision", decisionOutcome(d.Reason), now)
	if err != nil {
		return err
	}
	return analytics.InsertTx(ctx, tx, e)
}
func decisionOutcome(reason string) string {
	if reason == "admitted" {
		return "admitted"
	}
	return "rejected"
}
func smtpClass(reason string) int {
	if reason == "admitted" {
		return 250
	}
	return 550
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
