//go:build integration

package integration

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// dnsStub изображает публичный DNS: отвечает CNAME на
// _acme-challenge.<домен> и пересылает всё остальное в acme-dns.
// Именно так выглядит цепочка в бою, только вместо зоны клиента — стаб.
type dnsStub struct {
	challengeName string // _acme-challenge.test.example.com.
	target        string // <uuid>.acme.test.
	upstream      string // адрес acme-dns, например 127.0.0.1:5354
	servers       []*dns.Server
}

func startDNSStub(t *testing.T, addr, challengeName, target, upstream string) *dnsStub {
	t.Helper()

	s := &dnsStub{
		challengeName: dns.Fqdn(challengeName),
		target:        dns.Fqdn(target),
		upstream:      upstream,
	}

	// Нужны оба протокола: lego спрашивает по UDP, а pebble ходит по TCP.
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("не удалось занять %s по udp: %v", addr, err)
	}
	s.servers = append(s.servers, &dns.Server{PacketConn: pc, Handler: s})

	l, err := net.Listen("tcp", addr)
	if err != nil {
		pc.Close()
		t.Fatalf("не удалось занять %s по tcp: %v", addr, err)
	}
	s.servers = append(s.servers, &dns.Server{Listener: l, Handler: s})

	for _, srv := range s.servers {
		go func() {
			if err := srv.ActivateAndServe(); err != nil {
				t.Logf("DNS-стаб остановлен: %v", err)
			}
		}()
	}

	t.Cleanup(func() {
		for _, srv := range s.servers {
			srv.Shutdown()
		}
	})

	// Даём серверу подняться до первого запроса.
	time.Sleep(100 * time.Millisecond)

	return s
}

func (s *dnsStub) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	for _, q := range r.Question {
		if strings.EqualFold(q.Name, s.challengeName) {
			s.answerChallenge(m, q)
			continue
		}
		s.forward(m, q)
	}

	w.WriteMsg(m)
}

// answerChallenge возвращает CNAME и, для запроса TXT, ещё и значения,
// полученные из acme-dns: так поступает рекурсивный резолвер.
func (s *dnsStub) answerChallenge(m *dns.Msg, q dns.Question) {
	m.Answer = append(m.Answer, &dns.CNAME{
		Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 1},
		Target: s.target,
	})

	if q.Qtype != dns.TypeTXT {
		return
	}

	req := new(dns.Msg)
	req.SetQuestion(s.target, dns.TypeTXT)

	resp, err := dns.Exchange(req, s.upstream)
	if err != nil {
		m.Rcode = dns.RcodeServerFailure
		return
	}
	m.Answer = append(m.Answer, resp.Answer...)
}

func (s *dnsStub) forward(m *dns.Msg, q dns.Question) {
	req := new(dns.Msg)
	req.SetQuestion(q.Name, q.Qtype)

	resp, err := dns.Exchange(req, s.upstream)
	if err != nil {
		m.Rcode = dns.RcodeServerFailure
		return
	}

	m.Answer = append(m.Answer, resp.Answer...)
	m.Ns = append(m.Ns, resp.Ns...)
}
