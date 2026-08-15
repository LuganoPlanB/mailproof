// Package report renders bounded, non-active evidence reports.
package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"

	"github.com/luganoplanb/mailproof/internal/evidence"
)

const Schema = "mailproof.report/v1"

// Input is the stable report contract. Evidence IDs, rather than copied raw
// analyzer responses, let an auditor resolve every statement to retained data.
type Input struct {
	RunID                   string             `json:"run_id"`
	DeliveryID              string             `json:"delivery_id"`
	DeliveredOriginalDigest string             `json:"delivered_original_digest"`
	SelectedSubjectDigest   string             `json:"selected_subject_digest,omitempty"`
	AuthContextScope        evidence.AuthScope `json:"auth_context_scope"`
	Verdict                 evidence.Verdict   `json:"verdict"`
	PolicyVersion           string             `json:"policy_version"`
	ToolVersions            []string           `json:"tool_versions"`
	MissingAnalyzers        []string           `json:"missing_analyzers"`
	Timeline                []TimelineEvent    `json:"timeline"`
}

// Publish renders and atomically publishes the three immutable report files.
func Publish(root string, in Input) (map[string][]byte, error) {
	documents, err := Render(in)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(root, "runs", in.RunID, "report")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("create report directory: %w", err)
	}
	for _, name := range []string{"report.json", "report.txt", "report.html"} {
		if err := publish(dir, name, documents[name]); err != nil {
			return nil, err
		}
	}
	return documents, nil
}

func publish(dir, name string, contents []byte) error {
	target := filepath.Join(dir, name)
	if _, err := os.Stat(target); err == nil {
		return fmt.Errorf("refuse to overwrite %s", name)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect %s: %w", name, err)
	}
	temporary, err := os.CreateTemp(dir, "."+name+"-*")
	if err != nil {
		return fmt.Errorf("create temporary %s: %w", name, err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o440); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set report permissions: %w", err)
	}
	if _, err := temporary.Write(contents); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write report: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync report: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close report: %w", err)
	}
	if err := os.Link(temporaryName, target); err != nil {
		return fmt.Errorf("publish report: %w", err)
	}
	return nil
}

type TimelineEvent struct {
	Kind       string `json:"kind"`
	Claim      string `json:"claim"`
	EvidenceID string `json:"evidence_id,omitempty"`
}

type Document struct {
	Schema string `json:"schema"`
	Input
	SafeNextActions []string `json:"safe_next_actions"`
}

// Render returns the exact three report payloads required for a run.
func Render(in Input) (map[string][]byte, error) {
	if in.RunID == "" || in.DeliveryID == "" || in.DeliveredOriginalDigest == "" {
		return nil, fmt.Errorf("report requires run, delivery, and delivered-original identifiers")
	}
	if in.AuthContextScope != evidence.LocalIngress && in.AuthContextScope != evidence.Detached {
		return nil, fmt.Errorf("invalid authentication context scope %q", in.AuthContextScope)
	}
	doc := Document{Schema: Schema, Input: in, SafeNextActions: nextActions(in.Verdict.Category)}
	jsonBytes, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("encode report JSON: %w", err)
	}
	textBytes := []byte(renderText(doc))
	htmlBytes, err := renderHTML(doc)
	if err != nil {
		return nil, err
	}
	return map[string][]byte{"report.json": append(jsonBytes, '\n'), "report.txt": textBytes, "report.html": htmlBytes}, nil
}

func nextActions(category evidence.VerdictCategory) []string {
	actions := []string{"retain this report and its manifest", "verify through an independently obtained contact channel"}
	if category == evidence.KnownMalicious || category == evidence.Suspicious || category == evidence.AuthenticatedButSuspicious {
		actions = append(actions, "do not open links or attachments from the submitted message")
	}
	return actions
}

func renderText(doc Document) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Mailproof evidence report\nRun: %s\nDelivery: %s\nVerdict: %s\n", safe(doc.RunID), safe(doc.DeliveryID), doc.Verdict.Category)
	fmt.Fprintf(&b, "Delivered original digest: %s\nSelected subject digest: %s\nAuthentication context: %s\n", safe(doc.DeliveredOriginalDigest), safe(doc.SelectedSubjectDigest), doc.AuthContextScope)
	if doc.AuthContextScope == evidence.Detached {
		b.WriteString("Authentication for the outer submission does not authenticate this detached subject.\n")
	}
	writeList(&b, "Decisive support", doc.Verdict.Support)
	writeList(&b, "Contradictions", doc.Verdict.Contradictions)
	writeList(&b, "Missing or failed analyzers", append(append([]string{}, doc.MissingAnalyzers...), doc.Verdict.Unavailable...))
	b.WriteString("Custody timeline:\n")
	for _, event := range doc.Timeline {
		fmt.Fprintf(&b, "- %s: %s [%s]\n", safe(event.Kind), safe(event.Claim), safe(event.EvidenceID))
	}
	writeList(&b, "Safe next actions", doc.SafeNextActions)
	return b.String()
}

func writeList(b *strings.Builder, heading string, items []string) {
	fmt.Fprintf(b, "%s:\n", heading)
	if len(items) == 0 {
		b.WriteString("- none recorded\n")
		return
	}
	for _, item := range items {
		fmt.Fprintf(b, "- %s\n", safe(item))
	}
}

func renderHTML(doc Document) ([]byte, error) {
	const page = `<!doctype html><html><head><meta charset="utf-8"><title>Mailproof report</title></head><body><h1>Mailproof evidence report</h1><dl><dt>Run</dt><dd>{{.RunID}}</dd><dt>Delivery</dt><dd>{{.DeliveryID}}</dd><dt>Verdict</dt><dd>{{.Verdict.Category}}</dd><dt>Delivered original digest</dt><dd>{{.DeliveredOriginalDigest}}</dd><dt>Selected subject digest</dt><dd>{{.SelectedSubjectDigest}}</dd><dt>Authentication context</dt><dd>{{.AuthContextScope}}</dd></dl>{{if eq .AuthContextScope "detached"}}<p>Outer submission authentication does not authenticate this detached subject.</p>{{end}}<h2>Decisive support</h2><ul>{{range .Verdict.Support}}<li>{{.}}</li>{{end}}</ul><h2>Contradictions</h2><ul>{{range .Verdict.Contradictions}}<li>{{.}}</li>{{end}}</ul><h2>Missing or failed analyzers</h2><ul>{{range .MissingAnalyzers}}<li>{{.}}</li>{{end}}{{range .Verdict.Unavailable}}<li>{{.}}</li>{{end}}</ul><h2>Custody timeline</h2><ul>{{range .Timeline}}<li>{{.Kind}}: {{.Claim}} [{{.EvidenceID}}]</li>{{end}}</ul><h2>Safe next actions</h2><ul>{{range .SafeNextActions}}<li>{{.}}</li>{{end}}</ul></body></html>`
	t, err := template.New("report").Parse(page)
	if err != nil {
		return nil, fmt.Errorf("parse report template: %w", err)
	}
	var b bytes.Buffer
	if err := t.Execute(&b, doc); err != nil {
		return nil, fmt.Errorf("render report HTML: %w", err)
	}
	return b.Bytes(), nil
}

// safe makes control and bidirectional characters visible in every text report.
func safe(value string) string {
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			return '�'
		}
		return r
	}, value)
	if len(value) > 4096 {
		return value[:4096] + "…[truncated]"
	}
	return value
}
