package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/luganoplanb/mailproof/internal/analytics"
)

// ResultsClient is the typed, server-to-server read port. Its token is never
// accepted from, exposed to, or selected by a browser request.
type ResultsClient struct {
	BaseURL *url.URL
	Token   []byte
	HTTP    *http.Client
}

func (c ResultsClient) Snapshot(ctx context.Context, route string) (analytics.Snapshot, error) {
	if c.BaseURL == nil || len(c.Token) < 32 {
		return analytics.Snapshot{}, errors.New("dashboard results client is unavailable")
	}
	u := c.BaseURL.ResolveReference(&url.URL{Path: route})
	query := u.Query()
	now := time.Now().UTC().Truncate(time.Hour)
	query.Set("from", now.Add(-24*time.Hour).Format(time.RFC3339))
	query.Set("to", now.Format(time.RFC3339))
	query.Set("interval", "hour")
	u.RawQuery = query.Encode()
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return analytics.Snapshot{}, err
	}
	req.Header.Set("Authorization", "Bearer "+string(c.Token))
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return analytics.Snapshot{}, errors.New("dashboard upstream unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return analytics.Snapshot{}, errors.New("dashboard upstream unavailable")
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 2<<20))
	decoder.DisallowUnknownFields()
	var response struct {
		SchemaVersion int               `json:"schema_version"`
		Values        []analytics.Value `json:"values"`
		GeneratedAt   time.Time         `json:"generated_at"`
		DataThrough   time.Time         `json:"data_through"`
		ObservedAt    time.Time         `json:"observed_at"`
		Partial       bool              `json:"partial"`
		Stale         bool              `json:"stale"`
	}
	if err := decoder.Decode(&response); err != nil {
		return analytics.Snapshot{}, fmt.Errorf("decode dashboard projection: %w", err)
	}
	if decoder.More() || response.SchemaVersion != 1 {
		return analytics.Snapshot{}, errors.New("invalid dashboard projection")
	}
	return analytics.Snapshot{Values: response.Values, GeneratedAt: response.GeneratedAt, DataThrough: response.DataThrough, ObservedAt: response.ObservedAt, Partial: response.Partial, Stale: response.Stale}, nil
}
