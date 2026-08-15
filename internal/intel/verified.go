package intel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/luganoplanb/mailproof/internal/report"
)

// ReadVerifiedCampaignEvidence accepts only a report.json whose digest and
// signature have already been checked against a configured public key.
func ReadVerifiedCampaignEvidence(bundle, expectedManifestDigest string, trusted []ed25519.PublicKey) (report.CampaignEvidence, error) {
	manifest, err := os.ReadFile(filepath.Join(bundle, "manifest.json"))
	if err != nil {
		return report.CampaignEvidence{}, errors.New("missing signed campaign evidence")
	}
	got := sha256.Sum256(manifest)
	if expectedManifestDigest == "" || !strings.EqualFold(expectedManifestDigest, hex.EncodeToString(got[:])) {
		return report.CampaignEvidence{}, errors.New("manifest digest mismatch")
	}
	if verification := report.VerifyBundle(bundle, trusted); !verification.Valid {
		return report.CampaignEvidence{}, errors.New("unverified report bundle")
	}
	raw, err := os.ReadFile(filepath.Join(bundle, "report.json"))
	if err != nil {
		return report.CampaignEvidence{}, err
	}
	var document report.Document
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil || document.Schema != report.Schema || document.CampaignEvidence == nil {
		return report.CampaignEvidence{}, errors.New("missing signed campaign evidence")
	}
	if err := document.CampaignEvidence.Validate(); err != nil {
		return report.CampaignEvidence{}, errors.New("invalid signed campaign evidence")
	}
	return *document.CampaignEvidence, nil
}

// IndicatorsFromVerifiedEnvelope rehydrates only its safe typed published values.
func IndicatorsFromVerifiedEnvelope(v report.CampaignEvidence) Result {
	r := Result{Truncated: map[string]int{}, Unavailable: map[string]string{}}
	if err := v.Validate(); err != nil {
		r.Unavailable["evidence"] = "invalid_signed_evidence"
		return r
	}
	for _, i := range v.Indicators {
		r.Indicators = append(r.Indicators, indicator(i.Type, i.Value, v.KeyID, v.SourceArtifactDigest))
	}
	for _, t := range v.Truncation {
		r.Truncated[t.Type] = t.Dropped
	}
	for _, a := range v.Availability {
		r.Unavailable[a.Type] = a.Reason
	}
	return r
}
