// Package analyzers contains adapters for external, operator-configured tools.
package analyzers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/luganoplanb/mailproof/internal/evidence"
)

const (
	rspamdProjection       = "MAILPROOF_PROJECTION"
	rspamdProjectionMarker = "MAILPROOF_PROJECTION_COMPLETE"
	maxProjectionRecords   = 1_000
	maxProjectionBytes     = 4 << 10
)

// RspamdRequest is the trusted SMTP context sent to the sole Rspamd scan.  A
// detached subject deliberately contains none of the SMTP fields.
type RspamdRequest struct {
	Scope          evidence.AuthScope
	Message        []byte
	PeerIP         string
	HELO           string
	EnvelopeFrom   string
	SubjectDigest  string
	ConfigDigest   string
	AdapterVersion string
}

func (r RspamdRequest) Validate() error {
	if len(r.Message) == 0 || r.SubjectDigest == "" || r.ConfigDigest == "" {
		return errors.New("rspamd request requires message, subject digest, and config digest")
	}
	if r.Scope != evidence.LocalIngress && r.Scope != evidence.Detached {
		return errors.New("invalid authentication scope")
	}
	if r.Scope == evidence.Detached && (r.PeerIP != "" || r.HELO != "" || r.EnvelopeFrom != "") {
		return errors.New("detached subjects must not supply SMTP metadata")
	}
	return nil
}

// RspamdClient makes exactly one bounded request per Analyze call.
type RspamdClient struct {
	Endpoint string
	Client   *http.Client
	MaxBytes int64
}

func (c RspamdClient) Analyze(ctx context.Context, request RspamdRequest) (NormalizedRspamd, error) {
	if err := request.Validate(); err != nil {
		return NormalizedRspamd{}, err
	}
	if c.Endpoint == "" || c.MaxBytes <= 0 {
		return NormalizedRspamd{}, errors.New("rspamd endpoint and response bound are required")
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(request.Message))
	if err != nil {
		return NormalizedRspamd{}, fmt.Errorf("create Rspamd request: %w", err)
	}
	httpRequest.Header.Set("Content-Type", "message/rfc822")
	httpRequest.Header.Set("Queue-Id", request.SubjectDigest)
	if request.Scope == evidence.LocalIngress {
		httpRequest.Header.Set("IP", request.PeerIP)
		httpRequest.Header.Set("Helo", request.HELO)
		httpRequest.Header.Set("From", request.EnvelopeFrom)
	}
	response, err := client.Do(httpRequest)
	if err != nil {
		return NormalizedRspamd{}, fmt.Errorf("submit Rspamd scan: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return NormalizedRspamd{}, fmt.Errorf("Rspamd scan status %d", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, c.MaxBytes+1))
	if err != nil {
		return NormalizedRspamd{}, fmt.Errorf("read Rspamd response: %w", err)
	}
	if int64(len(raw)) > c.MaxBytes {
		return NormalizedRspamd{}, errors.New("Rspamd response exceeds bound")
	}
	return NormalizeRspamd(raw, request)
}

type rspamdResponse struct {
	Action  string                  `json:"action"`
	Score   float64                 `json:"score"`
	Symbols map[string]rspamdSymbol `json:"symbols"`
}
type rspamdSymbol struct {
	Score   float64  `json:"score"`
	Options []string `json:"options"`
}

type ProjectionRecord struct {
	Symbol string          `json:"symbol"`
	Value  json.RawMessage `json:"value"`
}

type RspamdCapability struct {
	Name   string                    `json:"name"`
	Status evidence.CapabilityStatus `json:"status"`
	Hits   []string                  `json:"hits"`
	Fails  []string                  `json:"fails"`
}

// NormalizedRspamd retains raw response bytes by digest for caller-owned
// immutable storage. Aggregate score/action remain metadata, never evidence.
type NormalizedRspamd struct {
	RawResponse       []byte             `json:"-"`
	ResponseDigest    string             `json:"response_digest"`
	Action            string             `json:"action"`
	Score             float64            `json:"score"`
	Symbols           []string           `json:"symbols"`
	Projections       []ProjectionRecord `json:"projections"`
	Capabilities      []RspamdCapability `json:"capabilities"`
	SPFNotApplicable  bool               `json:"spf_not_applicable"`
	UntrustedReplayAR bool               `json:"untrusted_replay_authentication_results"`
}

// NormalizeRspamd validates Mailproof's compact projection protocol without
// dropping unknown Rspamd symbols.  A clean outcome is only possible when the
// config contract and the final completion marker are both present.
func NormalizeRspamd(raw []byte, request RspamdRequest) (NormalizedRspamd, error) {
	var response rspamdResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		return NormalizedRspamd{}, fmt.Errorf("decode Rspamd response: %w", err)
	}
	if response.Symbols == nil {
		return NormalizedRspamd{}, errors.New("Rspamd response has no symbols")
	}
	digest := sha256.Sum256(raw)
	normalized := NormalizedRspamd{
		RawResponse:       append([]byte(nil), raw...),
		ResponseDigest:    hex.EncodeToString(digest[:]),
		Action:            response.Action,
		Score:             response.Score,
		Symbols:           make([]string, 0, len(response.Symbols)),
		Projections:       []ProjectionRecord{},
		Capabilities:      []RspamdCapability{},
		SPFNotApplicable:  request.Scope == evidence.Detached,
		UntrustedReplayAR: request.Scope == evidence.Detached,
	}
	for symbol := range response.Symbols {
		normalized.Symbols = append(normalized.Symbols, symbol)
	}
	sort.Strings(normalized.Symbols)
	markerCount := 0
	for _, symbol := range normalized.Symbols {
		if symbol != rspamdProjection && symbol != rspamdProjectionMarker {
			continue
		}
		for _, option := range response.Symbols[symbol].Options {
			if len(option) > maxProjectionBytes {
				return NormalizedRspamd{}, fmt.Errorf("%s option exceeds bound", symbol)
			}
			var value json.RawMessage
			if err := json.Unmarshal([]byte(option), &value); err != nil {
				return NormalizedRspamd{}, fmt.Errorf("decode %s option: %w", symbol, err)
			}
			if symbol == rspamdProjectionMarker {
				markerCount++
				var marker struct {
					SchemaVersion int  `json:"schemaVersion"`
					Complete      bool `json:"complete"`
				}
				if err := json.Unmarshal(value, &marker); err != nil || marker.SchemaVersion != 1 || !marker.Complete {
					return NormalizedRspamd{}, errors.New("invalid projection completion marker")
				}
				continue
			}
			normalized.Projections = append(normalized.Projections, ProjectionRecord{Symbol: symbol, Value: append(json.RawMessage(nil), value...)})
			if len(normalized.Projections) > maxProjectionRecords {
				return NormalizedRspamd{}, errors.New("too many projection records")
			}
		}
	}
	if markerCount != 1 {
		return NormalizedRspamd{}, fmt.Errorf("expected exactly one projection completion marker, got %d", markerCount)
	}
	normalized.Capabilities = capabilityCoverage(response.Symbols, true)
	return normalized, nil
}

func capabilityCoverage(symbols map[string]rspamdSymbol, complete bool) []RspamdCapability {
	contracts := []struct{ name, hit, fail string }{
		{"clamav", "MAILPROOF_CLAM_HIT", "MAILPROOF_CLAM_FAIL"},
		{"oletools", "MAILPROOF_OLETOOLS_HIT", "MAILPROOF_OLETOOLS_FAIL"},
	}
	capabilities := make([]RspamdCapability, 0, len(contracts))
	for _, contract := range contracts {
		capability := RspamdCapability{Name: contract.name, Status: evidence.Unknown, Hits: []string{}, Fails: []string{}}
		if _, hit := symbols[contract.hit]; hit {
			capability.Hits = append(capability.Hits, contract.hit)
			capability.Status = evidence.Observed
		}
		if _, failed := symbols[contract.fail]; failed {
			capability.Fails = append(capability.Fails, contract.fail)
			capability.Status = evidence.Failed
		}
		if complete && len(capability.Hits) == 0 && len(capability.Fails) == 0 {
			// Completion proves the pinned module was evaluated; absent symbols do
			// not prove a clean result without this condition.
			capability.Status = evidence.CleanConfirmed
		}
		capabilities = append(capabilities, capability)
	}
	return capabilities
}

// Evidence turns normalized response metadata into common evidence records.
// It intentionally does not give aggregate score/action any authority.
func (r NormalizedRspamd) Evidence(request RspamdRequest, rawPath string, observedAt time.Time) []evidence.Evidence {
	items := make([]evidence.Evidence, 0, len(r.Capabilities))
	for _, capability := range r.Capabilities {
		value, _ := json.Marshal(capability)
		items = append(items, evidence.Evidence{
			ID:              "rspamd-" + capability.Name,
			Category:        capability.Name,
			Adapter:         "rspamd",
			AdapterVersion:  request.AdapterVersion,
			ConfigDigest:    request.ConfigDigest,
			SubjectDigest:   request.SubjectDigest,
			InputDigest:     request.SubjectDigest,
			ResponseDigest:  r.ResponseDigest,
			ObservedAt:      observedAt.UTC(),
			Value:           value,
			RawResponsePath: rawPath,
			Status:          capability.Status,
			Authority:       evidence.Supporting,
			Limitations:     []string{},
		})
	}
	return items
}

func hasSymbol(symbols map[string]rspamdSymbol, name string) bool {
	_, ok := symbols[strings.ToUpper(name)]
	return ok
}
