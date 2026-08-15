package evidence

import "strings"

type ForwardingMode string

const (
	ForwardingUnknown ForwardingMode = "unknown"
	PMFLike           ForwardingMode = "PMF-like"
	MFEFLike          ForwardingMode = "MFEF-like"
	REMLike           ForwardingMode = "REM-like"
	REMModifiedLike   ForwardingMode = "REM+MOD-like"
)

type Provenance struct {
	Mode        ForwardingMode `json:"mode"`
	Reasons     []string       `json:"reasons"`
	Received    []string       `json:"received"`
	ARCTrusted  bool           `json:"arc_trusted"`
	TrustRuleID string         `json:"trust_rule_id,omitempty"`
}

// ClassifyForwarding is descriptive evidence. It never changes authentication.
func ClassifyForwarding(received []string, arcValidated bool, trustRuleID string) Provenance {
	p := Provenance{Mode: ForwardingUnknown, Reasons: []string{}, Received: append([]string{}, received...), ARCTrusted: arcValidated && trustRuleID != "", TrustRuleID: trustRuleID}
	if len(received) == 0 {
		p.Reasons = append(p.Reasons, "no Received chain retained")
		return p
	}
	if len(received) == 1 {
		p.Mode = PMFLike
		p.Reasons = append(p.Reasons, "single observed delivery hop")
		return p
	}
	if arcValidated && trustRuleID != "" {
		p.Mode = MFEFLike
		p.Reasons = append(p.Reasons, "validated ARC with explicit trust rule")
		return p
	}
	for _, hop := range received {
		if strings.Contains(strings.ToLower(hop), "list-id") {
			p.Mode = REMModifiedLike
			p.Reasons = append(p.Reasons, "list rewrite marker observed")
			return p
		}
	}
	p.Mode = REMLike
	p.Reasons = append(p.Reasons, "multiple Received hops without trusted ARC")
	return p
}
