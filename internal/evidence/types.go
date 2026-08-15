// Package evidence contains the immutable, auditable vocabulary used by workers.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

type CapabilityStatus string

const (
	Observed       CapabilityStatus = "observed"
	CleanConfirmed CapabilityStatus = "clean_confirmed"
	NotApplicable  CapabilityStatus = "not_applicable"
	Unavailable    CapabilityStatus = "unavailable"
	Failed         CapabilityStatus = "failed"
	Skipped        CapabilityStatus = "skipped"
	Unknown        CapabilityStatus = "unknown"
)

type Authority string

const (
	Authoritative Authority = "authoritative"
	Strong        Authority = "strong"
	Supporting    Authority = "supporting"
	Weak          Authority = "weak"
)

type AuthScope string

const (
	LocalIngress AuthScope = "local_ingress"
	Detached     AuthScope = "detached"
)

type VerdictCategory string

const (
	Verified                   VerdictCategory = "VERIFIED"
	AuthenticatedButSuspicious VerdictCategory = "AUTHENTICATED_BUT_SUSPICIOUS"
	Suspicious                 VerdictCategory = "SUSPICIOUS"
	KnownMalicious             VerdictCategory = "KNOWN_MALICIOUS"
	Indeterminate              VerdictCategory = "INDETERMINATE"
)

type Evidence struct {
	ID              string           `json:"id"`
	Category        string           `json:"category"`
	Adapter         string           `json:"adapter"`
	AdapterVersion  string           `json:"adapter_version"`
	ConfigDigest    string           `json:"config_digest"`
	SubjectDigest   string           `json:"subject_digest"`
	InputDigest     string           `json:"input_digest"`
	ResponseDigest  string           `json:"response_digest"`
	ObservedAt      time.Time        `json:"observed_at"`
	Value           json.RawMessage  `json:"value"`
	RawResponsePath string           `json:"raw_response_path"`
	Status          CapabilityStatus `json:"status"`
	Limitations     []string         `json:"limitations"`
	Authority       Authority        `json:"authority"`
	Error           string           `json:"error,omitempty"`
}
type Contradiction struct {
	ID          string   `json:"id"`
	EvidenceIDs []string `json:"evidence_ids"`
	Reason      string   `json:"reason"`
	Material    bool     `json:"material"`
}
type Verdict struct {
	Category       VerdictCategory `json:"category"`
	Technical      string          `json:"technical"`
	Behavior       string          `json:"behavior"`
	Support        []string        `json:"support"`
	Contradictions []string        `json:"contradictions"`
	Unavailable    []string        `json:"unavailable"`
	Rules          []string        `json:"rules"`
}

func (e Evidence) Validate() error {
	if e.ID == "" || e.Category == "" || e.Adapter == "" || e.SubjectDigest == "" {
		return errors.New("evidence requires id, category, adapter, and subject digest")
	}
	if !validStatus(e.Status) || !validAuthority(e.Authority) {
		return errors.New("invalid evidence status or authority")
	}
	if e.Status == CleanConfirmed && len(e.Value) == 0 {
		return errors.New("clean confirmation requires execution proof")
	}
	if e.Error != "" && len(e.Error) > 1024 {
		return errors.New("evidence error exceeds bound")
	}
	return nil
}
func validStatus(s CapabilityStatus) bool {
	switch s {
	case Observed, CleanConfirmed, NotApplicable, Unavailable, Failed, Skipped, Unknown:
		return true
	}
	return false
}
func validAuthority(a Authority) bool {
	switch a {
	case Authoritative, Strong, Supporting, Weak:
		return true
	}
	return false
}
func CanonicalDecision(v Verdict) ([]byte, string, error) {
	sort.Strings(v.Support)
	sort.Strings(v.Contradictions)
	sort.Strings(v.Unavailable)
	sort.Strings(v.Rules)
	b, err := json.Marshal(v)
	if err != nil {
		return nil, "", fmt.Errorf("marshal verdict: %w", err)
	}
	h := sha256.Sum256(b)
	return b, hex.EncodeToString(h[:]), nil
}
