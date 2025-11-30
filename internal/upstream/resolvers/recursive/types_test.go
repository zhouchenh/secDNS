package recursive

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/zhouchenh/secDNS/internal/edns/ecs"
)

func TestIsTerminalNoDataWithSOA(t *testing.T) {
	msg := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess}}
	msg.Ns = []dns.RR{
		&dns.SOA{
			Hdr:     dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
			Ns:      "ns1.example.",
			Mbox:    "hostmaster.example.",
			Serial:  1,
			Refresh: 7200,
			Retry:   3600,
			Expire:  1209600,
			Minttl:  300,
		},
	}

	nsNames := extractNS(msg)
	if !isTerminalNoData(msg, nsNames) {
		t.Fatalf("expected authoritative NODATA with SOA to be terminal")
	}
}

func TestIsTerminalNoDataReferral(t *testing.T) {
	msg := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess}}
	msg.Ns = []dns.RR{
		&dns.NS{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "ns1.example."},
		&dns.NS{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "ns2.example."},
	}

	nsNames := extractNS(msg)
	if isTerminalNoData(msg, nsNames) {
		t.Fatalf("referral with NS records should not be treated as terminal NODATA")
	}
}

func TestIsTerminalNoDataNoAuthority(t *testing.T) {
	msg := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess}}

	nsNames := extractNS(msg)
	if !isTerminalNoData(msg, nsNames) {
		t.Fatalf("empty NOERROR response without referrals should be treated as terminal")
	}
}

func TestApplyECSPassthroughAddsClientSubnet(t *testing.T) {
	r := &Recursive{}
	base := &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        1,
		SourceNetmask: 24,
		SourceScope:   0,
		Address:       net.IP{192, 0, 2, 0},
	}
	msg := new(dns.Msg)
	msg.SetQuestion("example.", dns.TypeA)

	if err := r.applyECS(msg, base); err != nil {
		t.Fatalf("applyECS returned error: %v", err)
	}
	if opt := extractECSOption(msg); opt == nil {
		t.Fatalf("expected ECS option to be added")
	} else {
		if opt.Family != base.Family || opt.SourceNetmask != base.SourceNetmask || !opt.Address.Equal(base.Address) {
			t.Fatalf("expected ECS to match base, got %+v", opt)
		}
	}
}

func TestApplyECSOverridePrefersConfig(t *testing.T) {
	cfg, err := ecs.ParseConfig(string(ecs.ModeOverride), "203.0.113.0/24")
	if err != nil {
		t.Fatalf("unexpected config parse error: %v", err)
	}
	r := &Recursive{ecsConfig: cfg}

	base := &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        1,
		SourceNetmask: 24,
		Address:       net.IP{198, 51, 100, 0},
	}
	msg := new(dns.Msg)
	msg.SetQuestion("example.", dns.TypeA)

	if err := r.applyECS(msg, base); err != nil {
		t.Fatalf("applyECS returned error: %v", err)
	}
	ecsOpt := extractECSOption(msg)
	if ecsOpt == nil {
		t.Fatalf("expected ECS option to be present")
	}
	if ecsOpt.Address.String() != "203.0.113.0" || ecsOpt.SourceNetmask != 24 {
		t.Fatalf("expected override ECS to use config, got %s/%d", ecsOpt.Address.String(), ecsOpt.SourceNetmask)
	}
	if ecsOpt.Address.Equal(base.Address) {
		t.Fatalf("expected override to replace client ECS")
	}
}

func TestSingleflightKeyDiffersByECS(t *testing.T) {
	msg1 := new(dns.Msg)
	msg1.SetQuestion("example.", dns.TypeA)
	msg1.SetEdns0(1232, true)
	msg2 := msg1.Copy()

	base1 := &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: net.IP{192, 0, 2, 0}}
	base2 := &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 16, Address: net.IP{198, 51, 100, 0}}

	_ = (&Recursive{}).applyECS(msg1, base1)
	_ = (&Recursive{}).applyECS(msg2, base2)

	key1 := singleflightKey(msg1)
	key2 := singleflightKey(msg2)
	if key1 == key2 {
		t.Fatalf("singleflight key should differ when ECS differs")
	}
}
