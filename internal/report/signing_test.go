package report

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSignAndVerifyDetectsMutation(t *testing.T) {
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest, signature, err := Sign(Manifest{Schema: ManifestSchema, DeliveryID: "delivery", DeliveredOriginal: "a", IssuedAt: time.Now()}, private)
	if err != nil {
		t.Fatal(err)
	}
	if got := Verify(manifest, signature, []ed25519.PublicKey{pub}); !got.Valid || !got.Trusted {
		t.Fatalf("unexpected verification: %+v", got)
	}
	manifest[0] ^= 1
	if got := Verify(manifest, signature, []ed25519.PublicKey{pub}); got.Valid {
		t.Fatalf("altered manifest verified: %+v", got)
	}
}

func TestVerifyBundleDetectsBoundReportMutation(t *testing.T) {
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "report.json"), []byte("json"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := Manifest{Schema: ManifestSchema, DeliveryID: "delivery", IssuedAt: time.Now(), ReportJSON: digest([]byte("json"))}
	bytes, sig, err := Sign(m, private)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), bytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.sig"), sig, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := VerifyBundle(dir, []ed25519.PublicKey{pub}); !got.Valid {
		t.Fatalf("valid bundle: %+v", got)
	}
	if err := os.WriteFile(filepath.Join(dir, "report.json"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := VerifyBundle(dir, []ed25519.PublicKey{pub}); got.Valid {
		t.Fatalf("altered bundle: %+v", got)
	}
}
