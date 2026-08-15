// Package ingress validates the only trusted SMTP correlation boundary.
package ingress

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Correlation is explicit: mail content never supplies authentication context.
type Correlation struct{ QueueID, Status, TokenHash string }

func Correlate(message string, logLines []string, tokens map[string]string) Correlation {
	s := bufio.NewScanner(strings.NewReader(message))
	queueID := ""
	for s.Scan() {
		line := s.Text()
		if line == "" {
			break
		}
		if strings.HasPrefix(line, "Received:") && strings.Contains(line, "postfix.mailproof.test") {
			for _, f := range strings.Fields(line) {
				if strings.HasPrefix(f, "id=") {
					queueID = strings.TrimPrefix(f, "id=")
					break
				}
			}
			break
		}
	}
	if queueID == "" {
		return Correlation{Status: "lost_coverage"}
	}
	matches := 0
	token := ""
	for _, line := range logLines {
		if strings.Contains(line, "queue_id="+queueID) {
			matches++
			for _, f := range strings.Fields(line) {
				if strings.HasPrefix(f, "token=") {
					token = strings.TrimPrefix(f, "token=")
				}
			}
		}
	}
	if matches != 1 {
		return Correlation{QueueID: queueID, Status: "lost_coverage"}
	}
	if _, ok := tokens[token]; !ok {
		return Correlation{QueueID: queueID, Status: "unknown_token"}
	}
	h := sha256.Sum256([]byte(token))
	return Correlation{QueueID: queueID, Status: "correlated", TokenHash: hex.EncodeToString(h[:])}
}
