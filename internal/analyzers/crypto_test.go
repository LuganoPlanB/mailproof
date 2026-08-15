package analyzers

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luganoplanb/mailproof/internal/evidence"
)

func cryptoConfig(t *testing.T) CryptoConfig {
	t.Helper()
	root := t.TempDir()
	trust := filepath.Join(root, "trust")
	if err := os.Mkdir(trust, 0o500); err != nil {
		t.Fatal(err)
	}
	return CryptoConfig{TrustRoot: trust, WorkRoot: root, Timeout: time.Second, OutputLimit: 1024}
}

func TestCryptoUnavailableWithoutTrustMaterial(t *testing.T) {
	config := CryptoConfig{WorkRoot: t.TempDir(), Timeout: time.Second, OutputLimit: 1024}
	result, err := VerifySMIME(context.Background(), config, []byte("message"))
	if err != nil || result.Status != evidence.Unavailable {
		t.Fatalf("VerifySMIME() = %#v, %v", result, err)
	}
}

func TestOpenPGPUsesOnlyConfiguredToolAndIsolatedFiles(t *testing.T) {
	config := cryptoConfig(t)
	config.GPGVPath = "/bin/false"
	result, err := VerifyOpenPGP(context.Background(), config, []byte("signed"), []byte("signature"))
	if err != nil || result.Status != evidence.Failed || result.CryptographicallyValid {
		t.Fatalf("VerifyOpenPGP() = %#v, %v", result, err)
	}
	entries, err := os.ReadDir(config.WorkRoot)
	if err != nil || len(entries) != 1 {
		t.Fatalf("isolated directory leaked: %#v, %v", entries, err)
	}
}

func TestCryptoEvidenceDistinguishesTrustAndValidity(t *testing.T) {
	result := CryptoResult{Format: "smime", Status: evidence.Failed, ConfiguredTrust: "not_verified", Revocation: RevocationIndeterminate, ToolVersion: "openssl", Limitations: []string{"signature invalid"}}
	item, err := result.Evidence("subject", "config", "responses/smime.json", testTime)
	if err != nil || item.Status != evidence.Failed || item.Authority != evidence.Strong {
		t.Fatalf("Evidence() = %#v, %v", item, err)
	}
}
