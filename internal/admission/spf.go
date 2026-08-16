package admission

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	spfcheck "github.com/migadu/spf"
)

const maxDNSCNAMEHops = 10

// DNSResolver is pinned at composition time to the trusted local Unbound
// service. Request data only supplies the already validated envelope domain.
type DNSResolver struct {
	Server  string
	Timeout time.Duration
}

func (r DNSResolver) Check(ctx context.Context, envelope, helo string, peer net.IP) (string, error) {
	if peer == nil {
		return "permerror", errors.New("invalid peer")
	}
	_, domain, ok := strings.Cut(envelope, "@")
	if !ok || domain == "" {
		return "permerror", errors.New("invalid envelope")
	}
	resolver := &spfResolver{server: r.Server, timeout: r.Timeout}
	result := spfcheck.CheckHostWithResolver(ctx, peer, domain, envelope, helo, resolver)
	outcome := strings.ToLower(result.String())
	if result == spfcheck.TempError {
		return outcome, errors.New("temporary SPF DNS failure")
	}
	return outcome, nil
}

// spfResolver adapts the pinned miekg/dns client to the complete, bounded SPF
// evaluator. CNAME traversal is bounded independently of the evaluator's RFC
// limits so malformed DNS cannot recurse indefinitely.
type spfResolver struct {
	server  string
	timeout time.Duration
}

func (r *spfResolver) exchange(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	timeout := r.timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	server := r.server
	if server == "" {
		server = "unbound:53"
	}
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(name), qtype)
	client := &dns.Client{Timeout: timeout}
	response, _, err := client.ExchangeContext(ctx, query, server)
	if err != nil {
		return nil, err
	}
	if response.Truncated {
		client.Net = "tcp"
		response, _, err = client.ExchangeContext(ctx, query, server)
		if err != nil {
			return nil, err
		}
	}
	switch response.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
		return response, nil
	case dns.RcodeServerFailure:
		return nil, errors.New("resolver failure")
	default:
		return nil, fmt.Errorf("resolver response: %s", dns.RcodeToString[response.Rcode])
	}
}

func (r *spfResolver) LookupTXT(ctx context.Context, domain string) ([]string, error) {
	return r.lookupTXT(ctx, domain, 0)
}

func (r *spfResolver) lookupTXT(ctx context.Context, domain string, depth int) ([]string, error) {
	if depth > maxDNSCNAMEHops {
		return nil, errors.New("SPF TXT CNAME limit exceeded")
	}
	response, err := r.exchange(ctx, domain, dns.TypeTXT)
	if err != nil {
		return nil, err
	}
	var values []string
	for _, answer := range response.Answer {
		switch record := answer.(type) {
		case *dns.TXT:
			values = append(values, strings.Join(record.Txt, ""))
		case *dns.CNAME:
			child, err := r.lookupTXT(ctx, record.Target, depth+1)
			if err != nil {
				return nil, err
			}
			values = append(values, child...)
		}
	}
	return values, nil
}

func (r *spfResolver) LookupMX(ctx context.Context, domain string) ([]string, error) {
	return r.lookupMX(ctx, domain, 0)
}

func (r *spfResolver) lookupMX(ctx context.Context, domain string, depth int) ([]string, error) {
	if depth > maxDNSCNAMEHops {
		return nil, errors.New("SPF MX CNAME limit exceeded")
	}
	response, err := r.exchange(ctx, domain, dns.TypeMX)
	if err != nil {
		return nil, err
	}
	var values []string
	for _, answer := range response.Answer {
		switch record := answer.(type) {
		case *dns.MX:
			values = append(values, record.Mx)
		case *dns.CNAME:
			child, err := r.lookupMX(ctx, record.Target, depth+1)
			if err != nil {
				return nil, err
			}
			values = append(values, child...)
		}
	}
	return values, nil
}

func (r *spfResolver) LookupA(ctx context.Context, domain string) ([]net.IP, error) {
	return r.lookupIP(ctx, domain, dns.TypeA, 0)
}

func (r *spfResolver) LookupAAAA(ctx context.Context, domain string) ([]net.IP, error) {
	return r.lookupIP(ctx, domain, dns.TypeAAAA, 0)
}

func (r *spfResolver) lookupIP(ctx context.Context, domain string, qtype uint16, depth int) ([]net.IP, error) {
	if depth > maxDNSCNAMEHops {
		return nil, errors.New("SPF address CNAME limit exceeded")
	}
	response, err := r.exchange(ctx, domain, qtype)
	if err != nil {
		return nil, err
	}
	var values []net.IP
	for _, answer := range response.Answer {
		switch record := answer.(type) {
		case *dns.A:
			if qtype == dns.TypeA {
				values = append(values, record.A)
			}
		case *dns.AAAA:
			if qtype == dns.TypeAAAA {
				values = append(values, record.AAAA)
			}
		case *dns.CNAME:
			child, err := r.lookupIP(ctx, record.Target, qtype, depth+1)
			if err != nil {
				return nil, err
			}
			values = append(values, child...)
		}
	}
	return values, nil
}

func (r *spfResolver) LookupPTR(ctx context.Context, ip net.IP) ([]string, error) {
	reverse, err := dns.ReverseAddr(ip.String())
	if err != nil {
		return nil, err
	}
	response, err := r.exchange(ctx, reverse, dns.TypePTR)
	if err != nil {
		return nil, err
	}
	var values []string
	for _, answer := range response.Answer {
		if record, ok := answer.(*dns.PTR); ok {
			values = append(values, record.Ptr)
		}
	}
	return values, nil
}
