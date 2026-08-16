package admission

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDNSResolverOutcomes(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	records := map[string]string{
		"pass.test.":          "v=spf1 +all",
		"fail.test.":          "v=spf1 -all",
		"softfail.test.":      "v=spf1 ~all",
		"neutral.test.":       "v=spf1 ?all",
		"ip4.test.":           "v=spf1 ip4:192.0.2.0/24 -all",
		"ip6.test.":           "v=spf1 ip6:2001:db8::/32 -all",
		"a.test.":             "v=spf1 a -all",
		"mx.test.":            "v=spf1 mx -all",
		"include.test.":       "v=spf1 include:_spf.include.test -all",
		"_spf.include.test.":  "v=spf1 ip4:192.0.2.1 -all",
		"redirect.test.":      "v=spf1 redirect=_spf.redirect.test",
		"_spf.redirect.test.": "v=spf1 ip4:192.0.2.1 -all",
		"exists.test.":        "v=spf1 exists:present.exists.test -all",
	}
	server := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		if q.Name == "none.test." {
			m.Rcode = dns.RcodeNameError
		} else if q.Qtype == dns.TypeTXT {
			text, ok := records[q.Name]
			if ok {
				m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 1}, Txt: []string{text}})
			}
		} else if q.Qtype == dns.TypeA && (q.Name == "a.test." || q.Name == "mail.mx.test." || q.Name == "present.exists.test.") {
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 1}, A: net.ParseIP("192.0.2.1").To4()})
		} else if q.Qtype == dns.TypeMX && q.Name == "mx.test." {
			m.Answer = append(m.Answer, &dns.MX{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 1}, Mx: "mail.mx.test."})
		}
		_ = w.WriteMsg(m)
	})}
	go server.ActivateAndServe()
	defer server.Shutdown()
	tests := []struct {
		name, domain, peer, want string
		wantErr                  bool
	}{
		{"pass", "pass.test", "192.0.2.1", "pass", false},
		{"fail", "fail.test", "192.0.2.1", "fail", false},
		{"softfail", "softfail.test", "192.0.2.1", "softfail", false},
		{"neutral", "neutral.test", "192.0.2.1", "neutral", false},
		{"none", "none.test", "192.0.2.1", "none", false},
		{"ip4", "ip4.test", "192.0.2.1", "pass", false},
		{"ip6", "ip6.test", "2001:db8::1", "pass", false},
		{"a", "a.test", "192.0.2.1", "pass", false},
		{"mx", "mx.test", "192.0.2.1", "pass", false},
		{"include", "include.test", "192.0.2.1", "pass", false},
		{"redirect", "redirect.test", "192.0.2.1", "pass", false},
		{"exists", "exists.test", "192.0.2.1", "pass", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := (DNSResolver{Server: pc.LocalAddr().String(), Timeout: time.Second}).Check(context.Background(), "a@"+tt.domain, "mx.sender.test", net.ParseIP(tt.peer))
			if got != tt.want || (err != nil) != tt.wantErr {
				t.Fatalf("Check() = (%q,%v), want (%q, err=%v)", got, err, tt.want, tt.wantErr)
			}
		})
	}
}

func TestDNSResolverTimeoutIsTemporary(t *testing.T) {
	got, err := (DNSResolver{Server: "127.0.0.1:1", Timeout: 10 * time.Millisecond}).Check(context.Background(), "a@example.test", "", net.ParseIP("192.0.2.1"))
	if got != "temperror" || err == nil {
		t.Fatalf("Check() = (%q,%v)", got, err)
	}
}
