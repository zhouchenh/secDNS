package server

import (
	"testing"

	"github.com/miekg/dns"
)

func TestUDPSize(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	if got := udpSize(q); got != dns.MinMsgSize {
		t.Fatalf("no-EDNS udpSize = %d, want %d", got, dns.MinMsgSize)
	}

	q2 := new(dns.Msg)
	q2.SetQuestion("example.com.", dns.TypeA)
	q2.SetEdns0(4096, false)
	if got := udpSize(q2); got != 4096 {
		t.Fatalf("EDNS udpSize = %d, want 4096", got)
	}

	q3 := new(dns.Msg)
	q3.SetQuestion("example.com.", dns.TypeA)
	q3.SetEdns0(200, false) // below the 512 floor
	if got := udpSize(q3); got != dns.MinMsgSize {
		t.Fatalf("small-EDNS udpSize = %d, want %d", got, dns.MinMsgSize)
	}
}

func TestClampUDPResponseTruncatesOversized(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA) // no EDNS -> 512-octet limit

	reply := new(dns.Msg)
	reply.SetReply(q)
	for i := 0; i < 50; i++ {
		reply.Answer = append(reply.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
			Txt: []string{"a-reasonably-long-txt-record-value-used-to-inflate-the-message-size"},
		})
	}
	if reply.Len() <= dns.MinMsgSize {
		t.Fatalf("test setup: reply not large enough (%d octets)", reply.Len())
	}
	origAnswers := len(reply.Answer)

	out := clampUDPResponse(reply, q)
	if !out.Truncated {
		t.Fatalf("expected the TC bit to be set on the clamped response")
	}
	if out.Len() > dns.MinMsgSize {
		t.Fatalf("clamped response is %d octets, exceeds %d", out.Len(), dns.MinMsgSize)
	}
	if reply.Truncated || len(reply.Answer) != origAnswers {
		t.Fatalf("the original (possibly shared) reply was mutated: truncated=%v answers=%d", reply.Truncated, len(reply.Answer))
	}
}

func TestClampUDPResponseLeavesSmallUnchanged(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	reply := new(dns.Msg)
	reply.SetReply(q)
	a, err := dns.NewRR("example.com. 60 IN A 93.184.216.34")
	if err != nil {
		t.Fatalf("NewRR: %v", err)
	}
	reply.Answer = []dns.RR{a}

	out := clampUDPResponse(reply, q)
	if out != reply {
		t.Fatalf("a small reply should be returned as-is without copying")
	}
	if out.Truncated {
		t.Fatalf("a small reply should not be marked truncated")
	}
}
