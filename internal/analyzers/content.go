package analyzers

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/SCKelemen/unicode/v6/uts39"
	"github.com/luganoplanb/mailproof/internal/evidence"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// URLObservation is the only URL input accepted by Mailproof.  It is emitted
// by the Rspamd projection and deliberately retains Rspamd's forms verbatim.
type URLObservation struct {
	SchemaVersion int      `json:"schemaVersion"`
	PartID        string   `json:"part_id"`
	Raw           string   `json:"raw"`
	Display       string   `json:"display"`
	Target        string   `json:"target"`
	Flags         []string `json:"flags"`
}

type CanonicalURL struct {
	URL          string   `json:"url"`
	ALabel       string   `json:"a_label"`
	ULabel       string   `json:"u_label"`
	Organization string   `json:"organization_domain,omitempty"`
	Scripts      []string `json:"scripts"`
	Skeleton     string   `json:"skeleton"`
	IsIPLiteral  bool     `json:"is_ip_literal"`
}

// DecodeURLObservation rejects arbitrary projection records: URL enrichment
// can only begin with a bounded, part-scoped MAILPROOF_URL_OBSERVATION value.
func DecodeURLObservation(record ProjectionRecord) (URLObservation, error) {
	if record.Symbol != "MAILPROOF_URL_OBSERVATION" {
		return URLObservation{}, errors.New("unexpected URL projection symbol")
	}
	var observation URLObservation
	if err := json.Unmarshal(record.Value, &observation); err != nil {
		return URLObservation{}, fmt.Errorf("decode URL observation: %w", err)
	}
	if observation.SchemaVersion != 1 || observation.PartID == "" || observation.Raw == "" {
		return URLObservation{}, errors.New("invalid URL observation")
	}
	if observation.Flags == nil {
		observation.Flags = []string{}
	}
	return observation, nil
}

func CanonicalizeURL(raw string) (CanonicalURL, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return CanonicalURL{}, fmt.Errorf("parse URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return CanonicalURL{}, errors.New("URL scheme is not HTTP(S)")
	}
	if parsed.User != nil || parsed.Host == "" {
		return CanonicalURL{}, errors.New("URL has credentials or no host")
	}
	host := parsed.Hostname()
	if host == "" {
		return CanonicalURL{}, errors.New("URL has no hostname")
	}
	canonical := CanonicalURL{Scripts: []string{}}
	if address, err := netip.ParseAddr(host); err == nil {
		canonical.IsIPLiteral = true
		canonical.ALabel, canonical.ULabel = address.String(), address.String()
	} else {
		ascii, err := idna.Lookup.ToASCII(host)
		if err != nil {
			return CanonicalURL{}, fmt.Errorf("convert IDN to A-label: %w", err)
		}
		unicodeHost, err := idna.Lookup.ToUnicode(ascii)
		if err != nil {
			return CanonicalURL{}, fmt.Errorf("convert IDN to U-label: %w", err)
		}
		canonical.ALabel, canonical.ULabel = strings.ToLower(ascii), unicodeHost
		canonical.Scripts, canonical.Skeleton = unicodeSignals(unicodeHost)
		if domain, err := publicsuffix.EffectiveTLDPlusOne(canonical.ALabel); err == nil {
			canonical.Organization = domain
		}
	}
	parsed.Host = canonical.ALabel
	if port := parsed.Port(); port != "" {
		parsed.Host = net.JoinHostPort(canonical.ALabel, port)
	}
	parsed.Fragment = ""
	canonical.URL = parsed.String()
	return canonical, nil
}

func unicodeSignals(value string) ([]string, string) {
	scripts := map[string]struct{}{}
	for _, r := range strings.ToLower(value) {
		switch {
		case unicode.Is(unicode.Latin, r):
			scripts["Latin"] = struct{}{}
		case unicode.Is(unicode.Cyrillic, r):
			scripts["Cyrillic"] = struct{}{}
		case unicode.Is(unicode.Greek, r):
			scripts["Greek"] = struct{}{}
		case unicode.IsLetter(r):
			scripts["Other"] = struct{}{}
		}
	}
	values := make([]string, 0, len(scripts))
	for script := range scripts {
		values = append(values, script)
	}
	sort.Strings(values)
	// The UTS #39 skeleton is evidence only; original Rspamd and canonical
	// forms remain alongside it and are never silently replaced.
	return values, uts39.Skeleton(value)
}

// Resolver is injected so callers can use the internal Unbound service and
// tests can prove that forbidden destinations are never dialed.
type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type SafeFetcher struct {
	Resolver Resolver
	Client   *http.Client
}

func (f SafeFetcher) ClientFor(ctx context.Context) (*http.Client, error) {
	if f.Resolver == nil {
		return nil, errors.New("URL resolver is required")
	}
	base := f.Client
	if base == nil {
		base = &http.Client{}
	}
	copyClient := *base
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if configured, ok := base.Transport.(*http.Transport); ok && configured != nil {
		transport = configured.Clone()
	}
	transport.Proxy = nil
	transport.DialContext = func(dialCtx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("split destination: %w", err)
		}
		addresses, err := f.Resolver.LookupNetIP(dialCtx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("resolve destination: %w", err)
		}
		if len(addresses) != 1 {
			return nil, errors.New("destination must resolve to exactly one address")
		}
		if !publicAddress(addresses[0]) {
			return nil, errors.New("destination address is forbidden")
		}
		return (&net.Dialer{}).DialContext(dialCtx, network, net.JoinHostPort(addresses[0].String(), port))
	}
	copyClient.Transport = transport
	copyClient.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("redirect limit exceeded")
		}
		_, err := CanonicalizeURL(request.URL.String())
		return err
	}
	return &copyClient, nil
}

func publicAddress(address netip.Addr) bool {
	return address.IsValid() && !address.IsLoopback() && !address.IsPrivate() && !address.IsLinkLocalUnicast() && !address.IsLinkLocalMulticast() && !address.IsMulticast() && !address.IsUnspecified()
}

// PartBinding links safe Go-decoded bytes back to Rspamd's stable projection.
type PartBinding struct {
	PartID       string `json:"part_id"`
	PartPath     string `json:"part_path"`
	Digest       string `json:"digest"`
	DeclaredType string `json:"declared_type"`
	DetectedType string `json:"detected_type"`
}

func BindPart(partID, partPath, declaredType, detectedType string, decoded []byte) (PartBinding, error) {
	if partID == "" || partPath == "" || len(decoded) == 0 {
		return PartBinding{}, errors.New("part binding requires ID, path, and decoded bytes")
	}
	digest := sha256.Sum256(decoded)
	return PartBinding{PartID: partID, PartPath: partPath, Digest: hex.EncodeToString(digest[:]), DeclaredType: declaredType, DetectedType: detectedType}, nil
}

func (b PartBinding) Contradiction(expectedDigest string) *evidence.Contradiction {
	if expectedDigest == b.Digest && (b.DeclaredType == "" || b.DetectedType == "" || b.DeclaredType == b.DetectedType) {
		return nil
	}
	return &evidence.Contradiction{ID: "part-binding-" + b.PartID, EvidenceIDs: []string{}, Reason: "Rspamd part digest or type disagrees with Go binding", Material: true}
}

// SafeArchivePath accepts only ordinary relative paths.  Callers must still
// extract with a pinned tool in a fresh runner-owned directory.
func SafeArchivePath(name string) error {
	if name == "" || filepath.IsAbs(name) || strings.ContainsRune(name, '\x00') {
		return errors.New("archive member path is unsafe")
	}
	clean := filepath.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return errors.New("archive member traverses outside run directory")
	}
	return nil
}

// SupplementaryTool is a constrained invocation of a named gap analyzer.  It
// intentionally excludes primary MIME, anti-virus, and macro scanners, which
// are owned by Rspamd and are imported through its normalized coverage.
type SupplementaryTool struct {
	Path        string
	Args        []string
	Directory   string
	Timeout     time.Duration
	StdoutLimit int64
	StderrLimit int64
}

func RunSupplementaryTool(ctx context.Context, allowed map[string]struct{}, tool SupplementaryTool) evidence.CommandResult {
	name := strings.ToLower(filepath.Base(tool.Path))
	if name == "file" || strings.Contains(name, "clam") || strings.Contains(name, "olevba") {
		return evidence.CommandResult{Status: evidence.Skipped, Error: "tool is owned by Rspamd"}
	}
	return evidence.Run(ctx, allowed, evidence.Command{
		Path:        tool.Path,
		Args:        append([]string{}, tool.Args...),
		Directory:   tool.Directory,
		Timeout:     tool.Timeout,
		StdoutLimit: tool.StdoutLimit,
		StderrLimit: tool.StderrLimit,
	})
}

type QRValue struct {
	ParentDigest string        `json:"parent_digest"`
	PartDigest   string        `json:"part_digest"`
	Page         int           `json:"page,omitempty"`
	Frame        int           `json:"frame,omitempty"`
	ValueDigest  string        `json:"value_digest"`
	URL          *CanonicalURL `json:"url,omitempty"`
	Limitation   string        `json:"limitation,omitempty"`
}

func NewQRValue(parentDigest, partDigest, value string, page, frame int) (QRValue, error) {
	if parentDigest == "" || partDigest == "" || value == "" {
		return QRValue{}, errors.New("QR value requires parent, part, and value")
	}
	digest := sha256.Sum256([]byte(value))
	result := QRValue{ParentDigest: parentDigest, PartDigest: partDigest, Page: page, Frame: frame, ValueDigest: hex.EncodeToString(digest[:])}
	if canonical, err := CanonicalizeURL(value); err == nil {
		result.URL = &canonical
	}
	return result, nil
}

// DecodeQR invokes only zbarimg through the common bounded runner.  Output is
// line-oriented raw values; each value keeps its digest and is sent through the
// same URL canonicalization path rather than receiving its own fetch path.
func DecodeQR(ctx context.Context, allowed map[string]struct{}, tool SupplementaryTool, parentDigest, partDigest string, page, frame int) ([]QRValue, evidence.CommandResult) {
	if filepath.Base(tool.Path) != "zbarimg" {
		return []QRValue{}, evidence.CommandResult{Status: evidence.Skipped, Error: "QR decoder must be zbarimg"}
	}
	result := RunSupplementaryTool(ctx, allowed, tool)
	if result.Status != evidence.Observed {
		return []QRValue{}, result
	}
	values := []QRValue{}
	for _, line := range strings.Split(string(result.Stdout), "\n") {
		if value := strings.TrimSpace(line); value != "" {
			decoded, err := NewQRValue(parentDigest, partDigest, value, page, frame)
			if err == nil {
				values = append(values, decoded)
			}
		}
	}
	return values, result
}

type SemanticRule struct {
	ID       string             `json:"id"`
	Phrases  []string           `json:"phrases"`
	Strength evidence.Authority `json:"strength"`
}

//go:embed semantic_rules.yaml
var semanticRulesYAML string

// DefaultSemanticRules reads the small, committed rule vocabulary.  The file
// intentionally supports only its fixed auditable shape; accepting arbitrary
// YAML features would add an unnecessary hostile-input parser to this path.
func DefaultSemanticRules() []SemanticRule {
	rules := []SemanticRule{}
	var current *SemanticRule
	for _, line := range strings.Split(semanticRulesYAML, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "- id: "):
			rules = append(rules, SemanticRule{ID: strings.Trim(strings.TrimPrefix(trimmed, "- id: "), "\""), Phrases: []string{}, Strength: evidence.Weak})
			current = &rules[len(rules)-1]
		case current != nil && strings.HasPrefix(trimmed, "phrases: [") && strings.HasSuffix(trimmed, "]"):
			for _, phrase := range strings.Split(strings.TrimSuffix(strings.TrimPrefix(trimmed, "phrases: ["), "]"), ",") {
				if phrase = strings.Trim(strings.TrimSpace(phrase), "\""); phrase != "" {
					current.Phrases = append(current.Phrases, phrase)
				}
			}
		}
	}
	return rules
}

type SemanticMatch struct {
	RuleID   string             `json:"rule_id"`
	Excerpt  string             `json:"excerpt"`
	PartPath string             `json:"part_path"`
	Strength evidence.Authority `json:"strength"`
}

// MatchSemanticRules is intentionally deterministic and English-only.  It
// treats hostile instructions as message content and never emits authority
// above weak, so it cannot independently establish authenticity or malware.
func MatchSemanticRules(text, partPath string, rules []SemanticRule) []SemanticMatch {
	if len(text) > 1<<20 || partPath == "" {
		return []SemanticMatch{}
	}
	lower := strings.ToLower(stripQuotedAndSignature(text))
	matches := []SemanticMatch{}
	for _, rule := range rules {
		if rule.ID == "" || rule.Strength != evidence.Weak {
			continue
		}
		for _, phrase := range rule.Phrases {
			index := strings.Index(lower, strings.ToLower(phrase))
			if index < 0 {
				continue
			}
			end := index + len(phrase)
			matches = append(matches, SemanticMatch{RuleID: rule.ID, Excerpt: sanitizeExcerpt(text[index:end]), PartPath: partPath, Strength: evidence.Weak})
			break
		}
	}
	return matches
}

func stripQuotedAndSignature(value string) string {
	lines := strings.Split(value, "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "--" || strings.HasPrefix(trimmed, ">") || strings.HasPrefix(strings.ToLower(trimmed), "on ") && strings.Contains(strings.ToLower(trimmed), " wrote:") {
			break
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n")
}

func sanitizeExcerpt(value string) string {
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value)
	return strings.TrimSpace(value)
}
