package analyzers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/luganoplanb/mailproof/internal/evidence"
	"github.com/miekg/dns"
)

type DNSSECState string

const (
	DNSSECSecure        DNSSECState = "secure"
	DNSSECInsecure      DNSSECState = "insecure"
	DNSSECBogus         DNSSECState = "bogus"
	DNSSECIndeterminate DNSSECState = "indeterminate"
)

// TrustedResolver is deliberately address-based: analyzers may only speak to
// the internal Unbound endpoint, never to mail-controlled nameservers.
type TrustedResolver struct {
	Address string
	Timeout time.Duration
}

type DNSObservation struct {
	Name          string      `json:"name"`
	Type          string      `json:"type"`
	RCode         int         `json:"rcode"`
	DNSSEC        DNSSECState `json:"dnssec"`
	ExtendedError []uint16    `json:"extended_dns_errors"`
	Answers       []string    `json:"answers"`
	TTL           uint32      `json:"ttl"`
	CNAME         []string    `json:"cname"`
	RawReply      []byte      `json:"-"`
	ReplyDigest   string      `json:"reply_digest"`
	Error         string      `json:"error,omitempty"`
}

func (r TrustedResolver) Lookup(ctx context.Context, name string, qtype uint16) (DNSObservation, error) {
	if r.Address == "" || r.Timeout <= 0 {
		return DNSObservation{}, errors.New("internal resolver address and timeout are required")
	}
	if err := ctx.Err(); err != nil {
		return DNSObservation{}, err
	}
	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(name), qtype)
	message.SetEdns0(1232, true)
	client := &dns.Client{Net: "udp", Timeout: r.Timeout}
	reply, _, err := client.ExchangeContext(ctx, message, r.Address)
	if err != nil {
		return DNSObservation{Name: dns.Fqdn(name), Type: dns.TypeToString[qtype], DNSSEC: DNSSECIndeterminate, Error: err.Error(), Answers: []string{}, CNAME: []string{}, ExtendedError: []uint16{}}, fmt.Errorf("query internal resolver: %w", err)
	}
	wire, err := reply.Pack()
	if err != nil {
		return DNSObservation{}, fmt.Errorf("pack resolver reply: %w", err)
	}
	result := DNSObservation{Name: dns.Fqdn(name), Type: dns.TypeToString[qtype], RCode: reply.Rcode, DNSSEC: classifyDNSSEC(reply), Answers: []string{}, CNAME: []string{}, ExtendedError: edeCodes(reply), RawReply: wire}
	h := sha256.Sum256(wire)
	result.ReplyDigest = hex.EncodeToString(h[:])
	for _, answer := range reply.Answer {
		result.Answers = append(result.Answers, answer.String())
		if result.TTL == 0 || answer.Header().Ttl < result.TTL {
			result.TTL = answer.Header().Ttl
		}
		if cname, ok := answer.(*dns.CNAME); ok {
			result.CNAME = append(result.CNAME, cname.Target)
		}
	}
	sort.Strings(result.Answers)
	sort.Strings(result.CNAME)
	return result, nil
}

func classifyDNSSEC(reply *dns.Msg) DNSSECState {
	if reply.AuthenticatedData {
		return DNSSECSecure
	}
	if reply.Rcode == dns.RcodeSuccess || reply.Rcode == dns.RcodeNameError {
		return DNSSECInsecure
	}
	if reply.Rcode == dns.RcodeServerFailure && len(edeCodes(reply)) > 0 {
		return DNSSECBogus
	}
	return DNSSECIndeterminate
}

func edeCodes(reply *dns.Msg) []uint16 {
	codes := []uint16{}
	for _, extra := range reply.Extra {
		opt, ok := extra.(*dns.OPT)
		if !ok {
			continue
		}
		for _, option := range opt.Option {
			if ede, ok := option.(*dns.EDNS0_EDE); ok {
				codes = append(codes, ede.InfoCode)
			}
		}
	}
	sort.Slice(codes, func(i, j int) bool { return codes[i] < codes[j] })
	return codes
}

// ObserveInfrastructure obtains only the record types independently useful to
// policy. Caller retains RawReply by digest before publishing evidence.
func ObserveInfrastructure(ctx context.Context, resolver TrustedResolver, domain, dkimSelector string) ([]DNSObservation, error) {
	queries := []struct {
		name   string
		typeID uint16
	}{
		{domain, dns.TypeA}, {domain, dns.TypeAAAA}, {domain, dns.TypeMX}, {domain, dns.TypeNS}, {domain, dns.TypeTXT},
		{"_dmarc." + domain, dns.TypeTXT}, {"_25._tcp." + domain, dns.TypeTLSA},
	}
	if dkimSelector != "" {
		queries = append(queries, struct {
			name   string
			typeID uint16
		}{dkimSelector + "._domainkey." + domain, dns.TypeTXT})
	}
	observations := make([]DNSObservation, 0, len(queries))
	for _, query := range queries {
		observation, err := resolver.Lookup(ctx, query.name, query.typeID)
		if err != nil {
			observations = append(observations, observation)
			continue
		}
		observations = append(observations, observation)
	}
	return observations, nil
}

// PTRNameForIP rejects non-address input rather than constructing a DNS name
// from user controlled text.
func PTRNameForIP(value string) (string, error) {
	ip := net.ParseIP(value)
	if ip == nil {
		return "", errors.New("invalid IP address")
	}
	return dns.ReverseAddr(ip.String())
}

// SPFIdentity is explicit about the identity that an SPF implementation must
// evaluate. Detached mail has no observed SMTP transaction and is inapplicable.
type SPFIdentity struct {
	Scope         evidence.AuthScope `json:"scope"`
	MailFrom      string             `json:"mail_from,omitempty"`
	HELO          string             `json:"helo,omitempty"`
	RemoteIP      string             `json:"remote_ip,omitempty"`
	NotApplicable bool               `json:"not_applicable"`
}

func NewSPFIdentity(scope evidence.AuthScope, mailFrom, helo, remoteIP string) (SPFIdentity, error) {
	if scope == evidence.Detached {
		if mailFrom != "" || helo != "" || remoteIP != "" {
			return SPFIdentity{}, errors.New("detached SPF cannot have SMTP inputs")
		}
		return SPFIdentity{Scope: scope, NotApplicable: true}, nil
	}
	if scope != evidence.LocalIngress || helo == "" || net.ParseIP(remoteIP) == nil {
		return SPFIdentity{}, errors.New("local ingress SPF requires HELO and remote IP")
	}
	return SPFIdentity{Scope: scope, MailFrom: mailFrom, HELO: helo, RemoteIP: remoteIP}, nil
}

// DMARCInputs prevents receiver-supplied Authentication-Results from being
// promoted: only independently observed SPF and Rspamd-verified DKIM fit here.
type DMARCInputs struct {
	FromDomain    string   `json:"from_domain"`
	SPFResult     string   `json:"spf_result"`
	DKIMDomains   []string `json:"rspamd_verified_dkim_domains"`
	PolicyRecords []string `json:"policy_records"`
}

func (d DMARCInputs) Validate() error {
	if d.FromDomain == "" {
		return errors.New("DMARC requires From domain")
	}
	if strings.ContainsAny(d.FromDomain, "\r\n") {
		return errors.New("invalid From domain")
	}
	return nil
}
