package report

import (
	"encoding/hex"
	"errors"
	"strings"
)

// CampaignEvidenceSchema is deliberately a small, signed published language.
// It contains no raw mail, URL, address, subject, filename, peer, key, or token.
const CampaignEvidenceSchema = "mailproof.campaign-evidence/v1"

// CampaignEvidence is the minimal privacy-reduced campaign input sealed in a
// signed report. It is intentionally not an analyzer response or mail view.
type CampaignEvidence struct {
	Schema               string                 `json:"schema"`
	NormalizationVersion string                 `json:"normalization_version"`
	PolicyVersion        string                 `json:"policy_version"`
	KeyID                string                 `json:"key_id,omitempty"`
	SourceArtifactDigest string                 `json:"source_artifact_digest"`
	Indicators           []CampaignIndicator    `json:"indicators"`
	Availability         []CampaignAvailability `json:"availability"`
	Truncation           []CampaignTruncation   `json:"truncation"`
}

// CampaignIndicator holds an already canonical safe value, never raw input.
type CampaignIndicator struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// CampaignAvailability explains why a typed value was unavailable or rejected.
type CampaignAvailability struct {
	Type   string `json:"type"`
	Reason string `json:"reason"`
}

// CampaignTruncation records deterministic dropped values which cannot group.
type CampaignTruncation struct {
	Type    string `json:"type"`
	Dropped int    `json:"dropped"`
}

// Validate fails closed for unknown values so a future schema cannot silently
// become campaign input before its privacy and grouping semantics are reviewed.
func (v CampaignEvidence) Validate() error {
	if v.Schema != CampaignEvidenceSchema || v.NormalizationVersion == "" || v.PolicyVersion == "" || !hexDigest(v.SourceArtifactDigest) {
		return errors.New("invalid campaign evidence envelope")
	}
	if len(v.Indicators) > 160 || len(v.Availability) > 16 || len(v.Truncation) > 16 {
		return errors.New("campaign evidence exceeds bounds")
	}
	allowed := map[string]bool{"risky_landing_domain": true, "redirect_domain": true, "selected_from_domain": true, "dkim_domain": true, "attachment_sha256": true, "attachment_mime": true, "filename_extension": true, "subject_fingerprint": true, "impersonated_organization": true, "network_asn": true, "reply_domain_mismatch": true}
	for _, i := range v.Indicators {
		if !allowed[i.Type] || !safeValue(i.Value) {
			return errors.New("invalid campaign indicator")
		}
		if i.Type == "subject_fingerprint" && (!hexDigest(i.Value) || v.KeyID == "") {
			return errors.New("invalid subject fingerprint")
		}
	}
	for _, a := range v.Availability {
		if !allowed[a.Type] || !safeToken(a.Reason) {
			return errors.New("invalid campaign availability")
		}
	}
	for _, t := range v.Truncation {
		if !allowed[t.Type] || t.Dropped < 0 {
			return errors.New("invalid campaign truncation")
		}
	}
	return nil
}
func hexDigest(v string) bool { _, err := hex.DecodeString(v); return len(v) == 64 && err == nil }
func safeValue(v string) bool {
	return len(v) > 0 && len(v) <= 255 && !strings.ContainsAny(v, "\x00\r\n\t ?@#") && !strings.Contains(v, "://")
}
func safeToken(v string) bool {
	return len(v) > 0 && len(v) <= 64 && !strings.ContainsAny(v, "\x00\r\n\t ")
}
