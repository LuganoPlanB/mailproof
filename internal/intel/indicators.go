// Package intel derives privacy-reduced campaign indicators from already
// verified report evidence. It has no mail parser and never performs network I/O.
package intel

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// NormalizationVersion changes whenever canonicalization semantics change.
// A key/version change requires a parallel rebuild; fingerprints never compare
// across key IDs.
const NormalizationVersion = "campaign-indicators/v1"

var (
	ErrUnavailable = errors.New("indicator unavailable")
	emailToken     = regexp.MustCompile(`(?i)\b[^\s@]+@[^\s@]+\b`)
	urlToken       = regexp.MustCompile(`(?i)\b(?:https?://|www\.)\S+`)
	numberToken    = regexp.MustCompile(`\b(?:[0-9]{2,}|[0-9a-f]{8}-[0-9a-f-]{27,})\b`)
)

// Indicator is safe to persist and display. Source is an immutable verified
// artifact digest; Raw input deliberately never crosses this boundary.
// Indicator is a typed, safe-to-display value with immutable report provenance.
type Indicator struct {
	Type, Value, Digest, KeyID, Version, SourceArtifactDigest string
}

// Input is the narrow post-verification evidence contract. Callers must not
// pass mail bytes or HTTP request data to this package.
// Input is for an approved typed adapter, not raw mail or an HTTP handler.
type Input struct {
	SourceArtifactDigest                                                                                    string
	RiskyURLs, RedirectURLs                                                                                 []string
	SelectedFromDomain, DKIMDomain, Subject, AttachmentSHA256, MIMEType, Filename, ImpersonatedOrganization string
}

// Result contains accepted values plus reason-coded omissions and truncation.
type Result struct {
	Indicators  []Indicator
	Truncated   map[string]int
	Unavailable map[string]string
}

// RegistrableDomain uses the offline pinned Go PSL and IDNA only; it makes no
// DNS or HTTP request and rejects URL components that could carry secrets.
func RegistrableDomain(raw string) (string, error) {
	if len(raw) == 0 || len(raw) > 2048 || hasUnsafe(raw) {
		return "", ErrUnavailable
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Host == "" || u.Port() != "" || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" {
		return "", ErrUnavailable
	}
	host := strings.TrimSuffix(u.Hostname(), ".")
	if host == "" || net.ParseIP(host) != nil {
		return "", ErrUnavailable
	}
	host, err = idna.Lookup.ToASCII(host)
	if err != nil || len(host) > 253 {
		return "", ErrUnavailable
	}
	host = strings.ToLower(host)
	suffix, _ := publicsuffix.PublicSuffix(host)
	if suffix == host {
		return "", ErrUnavailable
	}
	domain, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return "", ErrUnavailable
	}
	return domain, nil
}

func subjectFingerprint(subject string, key []byte) (string, error) {
	if len(key) < 32 || len(subject) > 8192 || hasUnsafe(subject) || !utf8.ValidString(subject) {
		return "", ErrUnavailable
	}
	s := norm.NFKC.String(subject)
	s = cases.Fold().String(s)
	s = emailToken.ReplaceAllString(s, " <email> ")
	s = urlToken.ReplaceAllString(s, " <url> ")
	s = numberToken.ReplaceAllString(s, " <number> ")
	s = strings.Join(strings.FieldsFunc(s, unicode.IsSpace), " ")
	if s == "" {
		return "", ErrUnavailable
	}
	m := hmac.New(sha256.New, key)
	_, _ = m.Write([]byte(s))
	return hex.EncodeToString(m.Sum(nil)), nil
}

func keyID(key []byte) string { d := sha256.Sum256(key); return hex.EncodeToString(d[:8]) }

// Normalize canonicalizes a bounded typed adapter payload. HMAC fingerprints
// are stored instead of normalized subject text; sorted caps ensure dropped
// values never create campaign edges.
func Normalize(in Input, key []byte) Result {
	r := Result{Truncated: map[string]int{}, Unavailable: map[string]string{}}
	if _, err := validSHA(in.SourceArtifactDigest); err != nil {
		r.Unavailable["evidence"] = "unverified_artifact"
		return r
	}
	addDomains := func(kind string, raw []string, cap int) {
		values := make([]string, 0, len(raw))
		rejected := false
		for _, v := range raw {
			if d, err := RegistrableDomain(v); err == nil {
				values = append(values, d)
			} else if v != "" {
				rejected = true
			}
		}
		sort.Strings(values)
		values = dedupe(values)
		if len(values) > cap {
			r.Truncated[kind] += len(values) - cap
			values = values[:cap]
		}
		for _, v := range values {
			r.Indicators = append(r.Indicators, indicator(kind, v, "", in.SourceArtifactDigest))
		}
		if rejected {
			r.Unavailable[kind] = "unsafe_value"
		}
	}
	addDomains("risky_landing_domain", in.RiskyURLs, 32)
	addDomains("redirect_domain", in.RedirectURLs, 16)
	addDomains("selected_from_domain", []string{in.SelectedFromDomain}, 8)
	addDomains("dkim_domain", []string{in.DKIMDomain}, 8)
	if fp, err := subjectFingerprint(in.Subject, key); err == nil {
		r.Indicators = append(r.Indicators, indicator("subject_fingerprint", fp, keyID(key), in.SourceArtifactDigest))
	} else if in.Subject != "" {
		r.Unavailable["subject_fingerprint"] = "unsafe_subject"
	}
	if sha, err := validSHA(in.AttachmentSHA256); err == nil {
		r.Indicators = append(r.Indicators, indicator("attachment_sha256", sha, "", in.SourceArtifactDigest))
	}
	if ext := safeExtension(in.Filename); ext != "" {
		r.Indicators = append(r.Indicators, indicator("filename_extension", ext, "", in.SourceArtifactDigest))
	}
	if mime := coarseMIME(in.MIMEType); mime != "" {
		r.Indicators = append(r.Indicators, indicator("attachment_mime", mime, "", in.SourceArtifactDigest))
	}
	if org := safeOrganization(in.ImpersonatedOrganization); org != "" {
		r.Indicators = append(r.Indicators, indicator("impersonated_organization", org, "", in.SourceArtifactDigest))
	}
	sort.Slice(r.Indicators, func(i, j int) bool {
		if r.Indicators[i].Type == r.Indicators[j].Type {
			return r.Indicators[i].Value < r.Indicators[j].Value
		}
		return r.Indicators[i].Type < r.Indicators[j].Type
	})
	r.Indicators = dedupeIndicators(r.Indicators)
	return r
}

func indicator(kind, value, kid, source string) Indicator {
	d := sha256.Sum256([]byte(kind + "\x00" + value))
	return Indicator{Type: kind, Value: value, Digest: hex.EncodeToString(d[:]), KeyID: kid, Version: NormalizationVersion, SourceArtifactDigest: source}
}
func validSHA(v string) (string, error) {
	if len(v) != 64 {
		return "", ErrUnavailable
	}
	_, e := hex.DecodeString(v)
	return strings.ToLower(v), e
}
func safeExtension(v string) string {
	if len(v) > 255 || hasUnsafe(v) {
		return ""
	}
	e := strings.ToLower(strings.TrimPrefix(path.Ext(v), "."))
	if len(e) == 0 || len(e) > 16 {
		return ""
	}
	for _, r := range e {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
			return ""
		}
	}
	return e
}
func coarseMIME(v string) string {
	switch strings.ToLower(v) {
	case "application/pdf", "application/zip", "application/vnd.ms-excel", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "image/jpeg", "image/png":
		return strings.ToLower(v)
	}
	return ""
}
func safeOrganization(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if len(v) == 0 || len(v) > 64 || hasUnsafe(v) {
		return ""
	}
	for _, r := range v {
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == ' ' || r == '-' || r == '_') {
			return ""
		}
	}
	return v
}
func dedupe(v []string) []string { return slicesCompact(v, func(a, b string) bool { return a == b }) }
func slicesCompact[T any](v []T, eq func(T, T) bool) []T {
	if len(v) == 0 {
		return v
	}
	out := v[:1]
	for _, x := range v[1:] {
		if !eq(out[len(out)-1], x) {
			out = append(out, x)
		}
	}
	return out
}
func dedupeIndicators(v []Indicator) []Indicator {
	return slicesCompact(v, func(a, b Indicator) bool { return a.Type == b.Type && a.Value == b.Value && a.KeyID == b.KeyID })
}

func hasUnsafe(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			return true
		}
	}
	return false
}
