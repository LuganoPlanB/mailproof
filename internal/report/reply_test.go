package report

import (
	"bytes"
	"testing"
)

func TestReplyUsesOnlyAuthorizedRecipientAndSafeHeaders(t *testing.T) {
	r := Reply{EnvelopeFrom: "", Recipient: "operator@example.org", DeliveryID: "delivery", Manifest: []byte("manifest"), ReportText: []byte("text"), ReportHTML: []byte("html"), ReportJSON: []byte("json"), Signature: []byte("sig")}
	message, err := r.Message()
	if err != nil {
		t.Fatal(err)
	}
	for _, header := range []string{"Auto-Submitted: auto-replied", "X-Mailproof-Loop: v1", "X-Mailproof-Idempotency:"} {
		if !bytes.Contains(message, []byte(header)) {
			t.Fatalf("missing %s", header)
		}
	}
	r.Recipient = "operator@example.org\r\nBcc: attacker@example.org"
	if _, err := r.Message(); err == nil {
		t.Fatal("header injection accepted")
	}
}
