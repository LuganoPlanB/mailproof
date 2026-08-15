package analyzers

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fixedResolver struct{ addresses []netip.Addr }

func (r fixedResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return r.addresses, nil
}

func TestCanonicalizeURL(t *testing.T) {
	got, err := CanonicalizeURL("https://www.b\u00fccher.example/path#fragment")
	if err != nil {
		t.Fatal(err)
	}
	if got.ALabel != "www.xn--bcher-kva.example" || got.URL != "https://www.xn--bcher-kva.example/path" {
		t.Fatalf("canonical URL = %#v", got)
	}
	for _, raw := range []string{"file:///tmp/a", "https://user@example.test", "https:///missing"} {
		if _, err := CanonicalizeURL(raw); err == nil {
			t.Fatalf("CanonicalizeURL(%q) succeeded", raw)
		}
	}
}

func TestDecodeURLObservationRequiresPartScopedProjection(t *testing.T) {
	valid := ProjectionRecord{Symbol: "MAILPROOF_URL_OBSERVATION", Value: []byte(`{"schemaVersion":1,"part_id":"p1","raw":"https://example.test","flags":[]}`)}
	if _, err := DecodeURLObservation(valid); err != nil {
		t.Fatal(err)
	}
	valid.Symbol = "OTHER"
	if _, err := DecodeURLObservation(valid); err == nil {
		t.Fatal("unexpected accepted projection")
	}
}

func TestSafeFetcherRejectsForbiddenResolvedAddress(t *testing.T) {
	client, err := (SafeFetcher{Resolver: fixedResolver{addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}}).ClientFor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	request, err := client.Get("http://example.test")
	if err == nil || request != nil {
		t.Fatalf("forbidden destination request = %v, %v", request, err)
	}
}

func TestPartBindingAndArchivePath(t *testing.T) {
	binding, err := BindPart("p1", "1.2", "application/pdf", "application/pdf", []byte("payload"))
	if err != nil || binding.Contradiction(binding.Digest) != nil {
		t.Fatalf("binding = %#v, %v", binding, err)
	}
	for _, name := range []string{"../escape", "/absolute", "safe/member.txt"} {
		err := SafeArchivePath(name)
		if (err != nil) != (name != "safe/member.txt") {
			t.Fatalf("SafeArchivePath(%q) = %v", name, err)
		}
	}
}

func TestSupplementaryToolDoesNotInvokePrimaryScanners(t *testing.T) {
	result := RunSupplementaryTool(context.Background(), map[string]struct{}{}, SupplementaryTool{Path: "/usr/bin/clamd", Timeout: time.Second})
	if result.Status != "skipped" {
		t.Fatalf("primary scanner result = %#v", result)
	}
	directory := t.TempDir()
	tool := filepath.Join(directory, "zbarimg")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\nprintf 'https://example.test\\n'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	values, result := DecodeQR(context.Background(), map[string]struct{}{tool: {}}, SupplementaryTool{Path: tool, Directory: directory, Timeout: time.Second, StdoutLimit: 1024, StderrLimit: 1024}, "parent", "part", 0, 0)
	if result.Status != "observed" || len(values) != 1 || values[0].URL == nil {
		t.Fatalf("QR result = %#v, values = %#v", result, values)
	}
}

func TestQRAndSemanticEvidence(t *testing.T) {
	qr, err := NewQRValue("parent", "part", "https://example.test", 1, 0)
	if err != nil || qr.URL == nil {
		t.Fatalf("QR value = %#v, %v", qr, err)
	}
	rules := []SemanticRule{{ID: "credential-request", Phrases: []string{"confirm your password"}, Strength: "weak"}}
	if matches := MatchSemanticRules("Please confirm your password", "1", rules); len(matches) != 1 {
		t.Fatalf("semantic matches = %#v", matches)
	}
	if matches := MatchSemanticRules("> confirm your password", "1", rules); len(matches) != 0 {
		t.Fatalf("quoted semantic matches = %#v", matches)
	}
}

func TestDefaultSemanticRulesAreWeakAndVersioned(t *testing.T) {
	rules := DefaultSemanticRules()
	if len(rules) != 5 {
		t.Fatalf("rule count = %d", len(rules))
	}
	for _, rule := range rules {
		if rule.Strength != "weak" || len(rule.Phrases) == 0 {
			t.Fatalf("unsafe semantic rule = %#v", rule)
		}
	}
}
