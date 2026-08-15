package admission

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DNSResolver is pinned at composition time to the trusted local Unbound
// service. Request data only supplies the already validated envelope domain.
type DNSResolver struct {
	Server  string
	Timeout time.Duration
}

func (r DNSResolver) Check(ctx context.Context, envelope, _ string, peer net.IP) (string, error) {
	if peer == nil {
		return "permerror", errors.New("invalid peer")
	}
	_, domain, ok := strings.Cut(envelope, "@")
	if !ok || domain == "" {
		return "permerror", errors.New("invalid envelope")
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	server := r.Server
	if server == "" {
		server = "unbound:53"
	}
	client := &dns.Client{Timeout: timeout}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeTXT)
	resp, _, err := client.ExchangeContext(ctx, msg, server)
	if err != nil {
		return "temperror", err
	}
	if resp.Rcode == dns.RcodeServerFailure {
		return "temperror", errors.New("resolver failure")
	}
	if resp.Rcode != dns.RcodeSuccess {
		return "permerror", errors.New("resolver response")
	}
	for _, answer := range resp.Answer {
		txt, ok := answer.(*dns.TXT)
		if !ok {
			continue
		}
		record := strings.Join(txt.Txt, "")
		if !strings.HasPrefix(strings.ToLower(record), "v=spf1") {
			continue
		}
		for _, term := range strings.Fields(record)[1:] {
			switch term {
			case "+all", "all":
				return "pass", nil
			case "-all":
				return "fail", nil
			case "~all":
				return "softfail", nil
			case "?all":
				return "neutral", nil
			}
		}
		return "neutral", nil
	}
	return "none", nil
}
