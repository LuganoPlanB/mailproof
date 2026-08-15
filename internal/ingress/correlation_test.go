package ingress

import "testing"

func TestCorrelateRejectsAmbiguousAndUnknown(t *testing.T) {
	message := "Received: from x by postfix.mailproof.test id=q1\n\nbody"
	if got := Correlate(message, []string{"queue_id=q1 token=bad"}, map[string]string{"good": "u"}); got.Status != "unknown_token" {
		t.Fatalf("%+v", got)
	}
	if got := Correlate(message, []string{"queue_id=q1 token=good", "queue_id=q1 token=good"}, map[string]string{"good": "u"}); got.Status != "lost_coverage" {
		t.Fatalf("%+v", got)
	}
}
