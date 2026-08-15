package analyzers

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/luganoplanb/mailproof/internal/evidence"
	"github.com/miekg/dns"
)

func startDNSServer(t *testing.T, response func(*dns.Msg) *dns.Msg) string {
	t.Helper()
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{PacketConn: packet, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		_ = w.WriteMsg(response(request))
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	return packet.LocalAddr().String()
}

func TestTrustedResolverClassifiesDNSSEC(t *testing.T) {
	address := startDNSServer(t, func(request *dns.Msg) *dns.Msg {
		reply := new(dns.Msg)
		reply.SetReply(request)
		reply.AuthenticatedData = true
		reply.Answer = append(reply.Answer, &dns.A{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 42}, A: net.ParseIP("192.0.2.9")})
		return reply
	})
	got, err := (TrustedResolver{Address: address, Timeout: time.Second}).Lookup(context.Background(), "example.test", dns.TypeA)
	if err != nil || got.DNSSEC != DNSSECSecure || got.TTL != 42 || got.ReplyDigest == "" {
		t.Fatalf("Lookup() = %#v, %v", got, err)
	}
}

func TestDNSSECDoesNotCallEverySERVFAILBogus(t *testing.T) {
	address := startDNSServer(t, func(request *dns.Msg) *dns.Msg {
		reply := new(dns.Msg)
		reply.SetReply(request)
		reply.Rcode = dns.RcodeServerFailure
		return reply
	})
	got, err := (TrustedResolver{Address: address, Timeout: time.Second}).Lookup(context.Background(), "example.test", dns.TypeTXT)
	if err != nil || got.DNSSEC != DNSSECIndeterminate {
		t.Fatalf("Lookup() = %#v, %v", got, err)
	}
}

func TestSPFIdentityScope(t *testing.T) {
	detached, err := NewSPFIdentity(evidence.Detached, "", "", "")
	if err != nil || !detached.NotApplicable {
		t.Fatalf("detached = %#v, %v", detached, err)
	}
	if _, err := NewSPFIdentity(evidence.Detached, "sender@example.test", "", ""); err == nil {
		t.Fatal("detached SMTP metadata accepted")
	}
	local, err := NewSPFIdentity(evidence.LocalIngress, "", "mx.example.test", "192.0.2.5")
	if err != nil || local.HELO == "" {
		t.Fatalf("local = %#v, %v", local, err)
	}
}

func TestPTRNameForIP(t *testing.T) {
	got, err := PTRNameForIP("192.0.2.1")
	if err != nil || got != "1.2.0.192.in-addr.arpa." {
		t.Fatalf("PTRNameForIP() = %q, %v", got, err)
	}
}
