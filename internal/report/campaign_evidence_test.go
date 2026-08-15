package report

import "testing"

func TestCampaignEvidenceRejectsUnsafeValues(t *testing.T) {
	base := CampaignEvidence{Schema: CampaignEvidenceSchema, NormalizationVersion: "v1", PolicyVersion: "p1", KeyID: "kid", SourceArtifactDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Indicators: []CampaignIndicator{{Type: "subject_fingerprint", Value: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"alice@example.test", "https://bad.test/x", "subject text", "a?b"} {
		base.Indicators[0] = CampaignIndicator{Type: "risky_landing_domain", Value: value}
		if base.Validate() == nil {
			t.Fatalf("accepted %q", value)
		}
	}
}
