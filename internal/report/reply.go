package report

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"strings"
	"time"

	smtp "github.com/emersion/go-smtp"
)

// Reply contains only trusted routing data. Header correlation is never routing.
type Reply struct {
	EnvelopeFrom string
	Recipient    string
	DeliveryID   string
	Manifest     []byte
	ReportText   []byte
	ReportHTML   []byte
	ReportJSON   []byte
	Signature    []byte
}

func (r Reply) IdempotencyKey() string {
	digest := sha256.Sum256(r.Manifest)
	return r.DeliveryID + ":" + hex.EncodeToString(digest[:])
}

func (r Reply) MessageID() string {
	digest := sha256.Sum256([]byte(r.IdempotencyKey()))
	return "<" + hex.EncodeToString(digest[:]) + "@mailproof.local>"
}

func (r Reply) Message() ([]byte, error) {
	if _, err := mail.ParseAddress(r.Recipient); err != nil || strings.ContainsAny(r.Recipient, "\r\n") {
		return nil, errors.New("invalid authorized recipient")
	}
	if strings.ContainsAny(r.EnvelopeFrom, "\r\n") {
		return nil, errors.New("invalid envelope sender")
	}
	digest := sha256.Sum256([]byte(r.IdempotencyKey()))
	boundary := "mailproof-" + hex.EncodeToString(digest[:])[:24]
	var b bytes.Buffer
	fmt.Fprintf(&b, "To: %s\r\nSubject: Mailproof verification report\r\nMessage-ID: %s\r\nAuto-Submitted: auto-replied\r\nX-Mailproof-Loop: v1\r\nX-Mailproof-Idempotency: %s\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=%q\r\n\r\n", r.Recipient, r.MessageID(), r.IdempotencyKey(), boundary)
	alternative := boundary + "-alt"
	fmt.Fprintf(&b, "--%s\r\nContent-Type: multipart/alternative; boundary=%q\r\n\r\n", boundary, alternative)
	writePart(&b, alternative, "text/plain; charset=utf-8", "", r.ReportText)
	writePart(&b, alternative, "text/html; charset=utf-8", "", r.ReportHTML)
	fmt.Fprintf(&b, "--%s--\r\n", alternative)
	writePart(&b, boundary, "application/json", "attachment; filename=report.json", r.ReportJSON)
	writePart(&b, boundary, "application/json", "attachment; filename=manifest.json", r.Manifest)
	writePart(&b, boundary, "application/octet-stream", "attachment; filename=manifest.sig", r.Signature)
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.Bytes(), nil
}

func writePart(b *bytes.Buffer, boundary, contentType, disposition string, content []byte) {
	fmt.Fprintf(b, "--%s\r\nContent-Type: %s\r\n", boundary, contentType)
	if disposition != "" {
		fmt.Fprintf(b, "Content-Disposition: %s\r\n", disposition)
	}
	b.WriteString("\r\n")
	b.Write(content)
	b.WriteString("\r\n")
}

// Submit reports an unknown post-DATA outcome distinctly: callers must not retry it.
func Submit(ctx context.Context, address string, reply Reply) (outcomeUnknown bool, err error) {
	message, err := reply.Message()
	if err != nil {
		return false, err
	}
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return false, fmt.Errorf("dial internal Postfix: %w", err)
	}
	defer connection.Close()
	client := smtp.NewClient(connection)
	client.CommandTimeout = 20 * time.Second
	client.SubmissionTimeout = 20 * time.Second
	if err := client.Hello("mailproof.local"); err != nil {
		return false, fmt.Errorf("SMTP hello: %w", err)
	}
	if err := client.Mail(reply.EnvelopeFrom, nil); err != nil {
		return false, fmt.Errorf("SMTP mail: %w", err)
	}
	if err := client.Rcpt(reply.Recipient, nil); err != nil {
		return false, fmt.Errorf("SMTP recipient: %w", err)
	}
	data, err := client.Data()
	if err != nil {
		return false, fmt.Errorf("SMTP data: %w", err)
	}
	if _, err := data.Write(message); err != nil {
		return false, fmt.Errorf("write SMTP body: %w", err)
	}
	if err := data.Close(); err != nil {
		return true, fmt.Errorf("SMTP outcome unknown after DATA terminator: %w", err)
	}
	if err := client.Quit(); err != nil {
		return false, fmt.Errorf("SMTP quit: %w", err)
	}
	return false, nil
}
