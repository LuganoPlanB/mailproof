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
	records := map[string]string{"pass.test.": "v=spf1 +all", "fail.test.": "v=spf1 -all", "softfail.test.": "v=spf1 ~all", "neutral.test.": "v=spf1 ?all"}
	server := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		if q.Name == "perm.test." {
			m.Rcode = dns.RcodeNameError
		} else if text, ok := records[q.Name]; ok {
			m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 1}, Txt: []string{text}})
		}
		_ = w.WriteMsg(m)
	})}
	go server.ActivateAndServe()
	defer server.Shutdown()
	tests := []struct {
		name, domain, want string
		wantErr            bool
	}{{"pass", "pass.test", "pass", false}, {"fail", "fail.test", "fail", false}, {"softfail", "softfail.test", "softfail", false}, {"neutral", "neutral.test", "neutral", false}, {"none", "none.test", "none", false}, {"permanent dns", "perm.test", "permerror", true}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := (DNSResolver{Server: pc.LocalAddr().String(), Timeout: time.Second}).Check(context.Background(), "a@"+tt.domain, "", net.ParseIP("192.0.2.1"))
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
