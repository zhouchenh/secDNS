package resolver

import (
	"errors"
	"github.com/miekg/dns"
	resolverpkg "github.com/zhouchenh/secDNS/pkg/upstream/resolver"
	"testing"
)

func TestNoAnswerResolveDepthLimit(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	if _, err := NoAnswer.Resolve(query, -1); !errors.Is(err, resolverpkg.ErrLoopDetected) {
		t.Fatalf("expected ErrLoopDetected, got %v", err)
	}
}

func TestNoAnswerResolveReturnsEmptyReply(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeAAAA)
	resp, err := NoAnswer.Resolve(query, 5)
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected success rcode, got %d", resp.Rcode)
	}
	if len(resp.Answer) != 0 {
		t.Fatalf("expected no answers, got %d", len(resp.Answer))
	}
	if resp.Question[0] != query.Question[0] {
		t.Fatalf("question mismatch: %+v vs %+v", resp.Question[0], query.Question[0])
	}
}
