package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/emersion/go-message"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type SubjectSelection struct {
	DeliveredDigest string    `json:"delivered_digest"`
	SubjectDigest   string    `json:"subject_digest,omitempty"`
	PartPath        string    `json:"part_path,omitempty"`
	Scope           AuthScope `json:"auth_context_scope,omitempty"`
	SelectionError  string    `json:"selection_error,omitempty"`
	Warnings        []string  `json:"warnings"`
}
type Header struct {
	Name       string `json:"name"`
	Raw        string `json:"raw"`
	Normalized string `json:"normalized"`
	Position   int    `json:"position"`
}
type Projection struct {
	Headers               []Header         `json:"headers"`
	Received              []string         `json:"received"`
	AuthenticationResults []string         `json:"authentication_results"`
	MessageID             []string         `json:"message_id"`
	Warnings              []string         `json:"warnings"`
	Selection             SubjectSelection `json:"selection"`
}

// SenderAmbiguities records dangerous presentation differences without inventing
// another mailbox parser. It compares retained header occurrences only.
func SenderAmbiguities(p Projection) []Contradiction {
	from := []Header{}
	for _, h := range p.Headers {
		if strings.EqualFold(h.Name, "From") {
			from = append(from, h)
		}
	}
	issues := []Contradiction{}
	if len(from) > 1 {
		issues = append(issues, Contradiction{ID: "multiple-from", Reason: "multiple From header fields", Material: true})
	}
	for _, h := range from {
		if strings.ContainsAny(h.Raw, "\x00\u200b\u202e") {
			issues = append(issues, Contradiction{ID: fmt.Sprintf("unsafe-from-%d", h.Position), Reason: "control or bidi character in From", Material: true})
		}
	}
	return issues
}

// Project parses only a copy/read stream; it never serializes parsed mail back to artifacts.
func Project(delivered []byte, deliveredDigest string) (Projection, error) {
	p := Projection{Headers: []Header{}, Received: []string{}, AuthenticationResults: []string{}, MessageID: []string{}, Warnings: []string{}, Selection: SubjectSelection{DeliveredDigest: deliveredDigest, Scope: LocalIngress, Warnings: []string{}}}
	entity, err := message.Read(bytes.NewReader(delivered))
	if err != nil {
		return p, fmt.Errorf("parse rfc822: %w", err)
	}
	fields := entity.Header.Fields()
	for i := 0; fields.Next(); i++ {
		f := fields
		name := f.Key()
		raw := f.Value()
		h := Header{Name: name, Raw: raw, Normalized: strings.TrimSpace(strings.Join(strings.Fields(raw), " ")), Position: i}
		p.Headers = append(p.Headers, h)
		switch strings.ToLower(name) {
		case "received":
			p.Received = append(p.Received, raw)
		case "authentication-results":
			p.AuthenticationResults = append(p.AuthenticationResults, raw)
		case "message-id":
			p.MessageID = append(p.MessageID, raw)
		}
	}
	// go-message has parsed the envelope; retaining the sealed bytes, rather than reconstruction, is intentional.
	return p, nil
}
func SelectTopLevelRFC822(delivered []byte, deliveredDigest, artifactRoot string) (SubjectSelection, error) {
	s := SubjectSelection{DeliveredDigest: deliveredDigest, Scope: LocalIngress, Warnings: []string{}}
	e, err := message.Read(bytes.NewReader(delivered))
	if err != nil {
		return s, fmt.Errorf("parse message: %w", err)
	}
	ct, params, err := e.Header.ContentType()
	if err != nil || !strings.HasPrefix(strings.ToLower(ct), "multipart/") {
		return s, nil
	}
	mr := e.MultipartReader()
	if mr == nil {
		return s, nil
	}
	children := [][]byte{}
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return s, fmt.Errorf("read mime part: %w", err)
		}
		typ, _, _ := part.Header.ContentType()
		if strings.EqualFold(typ, "message/rfc822") {
			b, readErr := io.ReadAll(part.Body)
			if readErr != nil {
				return s, fmt.Errorf("read attached message: %w", readErr)
			}
			children = append(children, b)
		}
		_ = params
	}
	if len(children) > 1 {
		s.Scope = ""
		s.SelectionError = "multiple_top_level_rfc822"
		return s, nil
	}
	if len(children) == 0 {
		return s, nil
	}
	h := sha256.Sum256(children[0])
	s.SubjectDigest = hex.EncodeToString(h[:])
	s.PartPath = "1"
	s.Scope = Detached
	dir := filepath.Join(artifactRoot, "messages")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return s, fmt.Errorf("create messages: %w", err)
	}
	target := filepath.Join(dir, s.SubjectDigest+".eml")
	if _, err := os.Stat(target); err == nil {
		return s, nil
	}
	tmp, err := os.CreateTemp(dir, ".subject-*")
	if err != nil {
		return s, fmt.Errorf("create child temp: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err = tmp.Write(children[0]); err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return s, fmt.Errorf("write child: %w", err)
	}
	if err = os.Link(name, target); err != nil && !os.IsExist(err) {
		return s, fmt.Errorf("publish child: %w", err)
	}
	return s, nil
}
