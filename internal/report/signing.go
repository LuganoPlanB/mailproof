package report

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const ManifestSchema = "mailproof.manifest/v1"

// Manifest deliberately contains no maps: encoding/json's struct ordering is
// the retained representation that is signed, not a home-grown canonicalizer.
type Manifest struct {
	Schema                string    `json:"schema"`
	DeliveryID            string    `json:"delivery_id"`
	SelectedSubjectDigest string    `json:"selected_subject_digest,omitempty"`
	DeliveredOriginal     string    `json:"delivered_original_digest"`
	Ingress               string    `json:"ingress_digest"`
	Subjects              string    `json:"subjects_digest"`
	Evidence              string    `json:"evidence_digest"`
	Verdict               string    `json:"verdict_digest"`
	ReportJSON            string    `json:"report_json_digest"`
	ReportText            string    `json:"report_text_digest"`
	ReportHTML            string    `json:"report_html_digest"`
	Policy                string    `json:"policy_digest"`
	Config                string    `json:"config_digest"`
	AdapterResponses      string    `json:"adapter_responses_digest"`
	IssuedAt              time.Time `json:"issued_at"`
	KeyID                 string    `json:"key_id"`
}

func (m Manifest) Bytes() ([]byte, error) {
	if m.Schema != ManifestSchema || m.DeliveryID == "" || m.KeyID == "" || m.IssuedAt.IsZero() {
		return nil, errors.New("manifest has missing or unsupported required fields")
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("encode manifest: %w", err)
	}
	return append(b, '\n'), nil
}

func ParsePrivateKey(pemBytes []byte) (ed25519.PrivateKey, string, error) {
	block, rest := pem.Decode(pemBytes)
	if block == nil || len(rest) != 0 || block.Type != "PRIVATE KEY" {
		return nil, "", errors.New("expected one PKCS#8 private key PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("parse PKCS#8 private key: %w", err)
	}
	private, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, "", errors.New("private key is not Ed25519")
	}
	return private, KeyID(private.Public().(ed25519.PublicKey)), nil
}

func ParsePublicKey(pemBytes []byte) (ed25519.PublicKey, string, error) {
	block, rest := pem.Decode(pemBytes)
	if block == nil || len(rest) != 0 || block.Type != "PUBLIC KEY" {
		return nil, "", errors.New("expected one public key PEM block")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("parse public key: %w", err)
	}
	public, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, "", errors.New("public key is not Ed25519")
	}
	return public, KeyID(public), nil
}

func KeyID(public ed25519.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256(der)
	return hex.EncodeToString(digest[:])
}

func Sign(m Manifest, private ed25519.PrivateKey) ([]byte, []byte, error) {
	if len(private) != ed25519.PrivateKeySize {
		return nil, nil, errors.New("invalid Ed25519 private key")
	}
	m.KeyID = KeyID(private.Public().(ed25519.PublicKey))
	bytes, err := m.Bytes()
	if err != nil {
		return nil, nil, err
	}
	return bytes, ed25519.Sign(private, bytes), nil
}

type Verification struct {
	Valid   bool   `json:"valid"`
	Trusted bool   `json:"trusted"`
	KeyID   string `json:"key_id"`
	Error   string `json:"error,omitempty"`
}

func Verify(manifest, signature []byte, trusted []ed25519.PublicKey) Verification {
	var m Manifest
	if err := json.Unmarshal(manifest, &m); err != nil {
		return Verification{Error: "invalid manifest JSON"}
	}
	if _, err := m.Bytes(); err != nil {
		return Verification{KeyID: m.KeyID, Error: err.Error()}
	}
	result := Verification{KeyID: m.KeyID}
	for _, key := range trusted {
		if KeyID(key) != m.KeyID {
			continue
		}
		result.Trusted = true
		result.Valid = ed25519.Verify(key, manifest, signature)
		if !result.Valid {
			result.Error = "invalid signature"
		}
		return result
	}
	result.Error = "untrusted signing key"
	return result
}

// VerifyBundle verifies both the retained signature and every report artifact
// that the manifest binds. It performs filesystem reads only; callers may use
// it safely on copied offline bundles.
func VerifyBundle(dir string, trusted []ed25519.PublicKey) Verification {
	manifestBytes, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return Verification{Error: "incomplete bundle"}
	}
	signature, err := os.ReadFile(filepath.Join(dir, "manifest.sig"))
	if err != nil {
		return Verification{Error: "incomplete bundle"}
	}
	result := Verify(manifestBytes, signature, trusted)
	if !result.Valid {
		return result
	}
	var manifest Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return Verification{KeyID: result.KeyID, Error: "invalid manifest JSON"}
	}
	for _, check := range []struct{ name, want string }{{"report.json", manifest.ReportJSON}, {"report.txt", manifest.ReportText}, {"report.html", manifest.ReportHTML}} {
		if check.want == "" {
			continue
		}
		contents, err := os.ReadFile(filepath.Join(dir, check.name))
		if err != nil || digest(contents) != check.want {
			return Verification{KeyID: result.KeyID, Trusted: result.Trusted, Error: "bound artifact is missing or altered"}
		}
	}
	return result
}

func digest(contents []byte) string {
	sum := sha256.Sum256(contents)
	return hex.EncodeToString(sum[:])
}

func SignAndPublish(root, runID string, manifest Manifest, private ed25519.PrivateKey) error {
	manifestBytes, signature, err := Sign(manifest, private)
	if err != nil {
		return err
	}
	dir := filepath.Join(root, "runs", runID, "report")
	if err := publish(dir, "manifest.json", manifestBytes); err != nil {
		return err
	}
	return publish(dir, "manifest.sig", signature)
}

func ReadTrustedPublicKeys(dir string) ([]ed25519.PublicKey, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read trusted key directory: %w", err)
	}
	keys := make([]ed25519.PublicKey, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".pem" {
			continue
		}
		contents, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read trusted key: %w", err)
		}
		key, _, err := ParsePublicKey(contents)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}
