package intel

import (
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestRegistrableDomainRejectsUnsafeURLParts(t *testing.T) {
	for _, raw := range []string{"https://login.Example.CO.UK", "xn--bcher-kva.example"} {
		if _, err := RegistrableDomain(raw); err != nil {
			t.Fatalf("%q: %v", raw, err)
		}
	}
	for _, raw := range []string{"https://user@example.com", "https://example.com/a", "https://example.com?x=y", "https://127.0.0.1", "com", "https://example.com:443"} {
		if _, err := RegistrableDomain(raw); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
}

func TestRegistrableDomainPinnedPSLBoundaries(t *testing.T) {
	if PublicSuffixListModule != "golang.org/x/net@v0.56.0" || PublicSuffixListChecksum == "" || PublicSuffixListLicense == "" {
		t.Fatal("PSL provenance is not pinned")
	}
	for raw, want := range map[string]string{
		"login.example.co.uk":   "example.co.uk",
		"a.b.github.io":         "b.github.io",
		"xn--bcher-kva.example": "xn--bcher-kva.example",
	} {
		got, err := RegistrableDomain(raw)
		if err != nil || got != want {
			t.Fatalf("RegistrableDomain(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{"co.uk", "github.io", "[2001:db8::1]", "https://example.com/%E2%80%AE"} {
		if _, err := RegistrableDomain(raw); err == nil {
			t.Fatalf("accepted unsafe/public suffix %q", raw)
		}
	}
}

func TestNormalizeNeverPersistsSubjectOrFilename(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	r := Normalize(Input{SourceArtifactDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", RiskyURLs: []string{"https://a.example.test", "https://b.example.test"}, Subject: "Invoice 293 for alice@example.test https://bad.test/a", Filename: "private-payroll.xlsm", AttachmentSHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}, key)
	if len(r.Indicators) == 0 {
		t.Fatal("no indicators")
	}
	for _, v := range r.Indicators {
		if v.Value == "private-payroll.xlsm" || v.Value == "invoice 293 for alice@example.test https://bad.test/a" {
			t.Fatalf("unsafe value persisted: %#v", v)
		}
	}
	if r.Indicators[0].SourceArtifactDigest == "" {
		t.Fatal("missing provenance")
	}
}

func TestSubjectKeyRotationDoesNotCompare(t *testing.T) {
	in := Input{SourceArtifactDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Subject: "Payment 123"}
	a := Normalize(in, []byte("01234567890123456789012345678901"))
	b := Normalize(in, []byte("11234567890123456789012345678901"))
	var av, bv Indicator
	for _, v := range a.Indicators {
		if v.Type == "subject_fingerprint" {
			av = v
		}
	}
	for _, v := range b.Indicators {
		if v.Type == "subject_fingerprint" {
			bv = v
		}
	}
	if av.Value == bv.Value || av.KeyID == bv.KeyID {
		t.Fatal("rotation was not isolated")
	}
}

func TestNormalizeCapsAllValuesPerTypeAndRecordsUnsafeInput(t *testing.T) {
	urls := make([]string, 40)
	for i := range urls {
		urls[i] = fmt.Sprintf("https://host%d.example%d.test", i, i)
	}
	urls[0] = "https://user@example.com"
	r := Normalize(Input{
		SourceArtifactDigest: strings.Repeat("a", 64),
		RiskyURLs:            urls,
	}, []byte("01234567890123456789012345678901"))
	var domains int
	for _, indicator := range r.Indicators {
		if indicator.Type == "risky_landing_domain" {
			domains++
		}
	}
	if domains != 32 {
		t.Fatalf("risky domains = %d, want 32", domains)
	}
	if r.Truncated["risky_landing_domain"] != 7 {
		t.Fatalf("risky truncation = %d, want 7", r.Truncated["risky_landing_domain"])
	}
	if r.Unavailable["risky_landing_domain"] != "unsafe_value" {
		t.Fatalf("unsafe URL reason = %q", r.Unavailable["risky_landing_domain"])
	}
	if got := Normalize(Input{SourceArtifactDigest: strings.Repeat("z", 64)}, nil); got.Unavailable["evidence"] != "unverified_artifact" {
		t.Fatalf("invalid provenance accepted: %#v", got)
	}
}

func FuzzRegistrableDomainNeverLeaksUnsafeParts(f *testing.F) {
	for _, seed := range []string{"example.com", "https://example.com", "https://user@example.com", "https://example.com/a?b=c", "\u202eevil.example"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		got, err := RegistrableDomain(raw)
		if err != nil {
			return
		}
		if strings.ContainsAny(got, "/?@:#") || hasUnsafe(got) || net.ParseIP(got) != nil {
			t.Fatalf("unsafe registrable domain %q from %q", got, raw)
		}
	})
}
