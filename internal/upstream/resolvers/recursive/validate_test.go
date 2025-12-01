package recursive

import (
	"crypto"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestValidatorPositiveChain(t *testing.T) {
	now := time.Now()
	rootKey, rootPriv := mustGenerateKey(".")
	childKey, childPriv := mustGenerateKey("example.")

	ds := childKey.ToDS(dns.SHA256)
	ds.Hdr.Ttl = 600
	dsSig := mustSign([]dns.RR{ds}, rootKey, rootPriv, ".", dns.TypeDS, now)
	rootDNSKEYSig := mustSign([]dns.RR{rootKey}, rootKey, rootPriv, ".", dns.TypeDNSKEY, now)

	dnskeySig := mustSign([]dns.RR{childKey}, childKey, childPriv, "example.", dns.TypeDNSKEY, now)

	a := &dns.A{Hdr: dns.RR_Header{Name: "www.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.IP{1, 2, 3, 4}}
	aSig := mustSign([]dns.RR{a}, childKey, childPriv, "example.", dns.TypeA, now)

	v := newValidator()
	v.trustAnchors = []dns.RR{rootKey}
	v.now = func() time.Time { return now }
	v.resolveDS = func(name string) (*dns.Msg, error) {
		if dns.Fqdn(name) == "example." {
			return &dns.Msg{Answer: []dns.RR{ds, dsSig}}, nil
		}
		return &dns.Msg{}, nil
	}
	v.resolveDNSKEY = func(name string) (*dns.Msg, error) {
		switch dns.Fqdn(name) {
		case ".":
			return &dns.Msg{Answer: []dns.RR{rootKey, rootDNSKEYSig}}, nil
		case "example.":
			return &dns.Msg{Answer: []dns.RR{childKey, dnskeySig}}, nil
		}
		return &dns.Msg{}, nil
	}

	msg := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess}}
	msg.Answer = []dns.RR{a, aSig}
	q := dns.Question{Name: "www.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}

	secure, insecure, serr := v.validateMessage(msg, q, false)
	t.Logf("message validation secure=%v insecure=%v err=%v", secure, insecure, serr)
	validated, err := v.validateResponse(msg, q, "strict", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !validated {
		t.Fatalf("expected validation success")
	}
}

func TestValidatorDsMismatch(t *testing.T) {
	now := time.Now()
	rootKey, rootPriv := mustGenerateKey(".")
	childKey, childPriv := mustGenerateKey("example.")

	badKey, _ := mustGenerateKey("bad.example.")
	ds := badKey.ToDS(dns.SHA256)
	ds.Hdr.Name = "example."
	ds.Hdr.Ttl = 600
	dsSig := mustSign([]dns.RR{ds}, rootKey, rootPriv, ".", dns.TypeDS, now)
	rootDNSKEYSig := mustSign([]dns.RR{rootKey}, rootKey, rootPriv, ".", dns.TypeDNSKEY, now)
	dnskeySig := mustSign([]dns.RR{childKey}, childKey, childPriv, "example.", dns.TypeDNSKEY, now)
	a := &dns.A{Hdr: dns.RR_Header{Name: "www.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.IP{5, 5, 5, 5}}
	aSig := mustSign([]dns.RR{a}, childKey, childPriv, "example.", dns.TypeA, now)

	v := newValidator()
	v.trustAnchors = []dns.RR{rootKey}
	v.now = func() time.Time { return now }
	v.resolveDS = func(string) (*dns.Msg, error) {
		return &dns.Msg{Answer: []dns.RR{ds, dsSig}}, nil
	}
	v.resolveDNSKEY = func(string) (*dns.Msg, error) {
		return &dns.Msg{Answer: []dns.RR{rootKey, rootDNSKEYSig, childKey, dnskeySig}}, nil
	}
	t.Logf("ds name=%s sig name=%s", ds.Hdr.Name, dsSig.Hdr.Name)
	dsSet, dsSigs := extractRRSet(&dns.Msg{Answer: []dns.RR{ds, dsSig}}, dns.TypeDS, "example.")
	t.Logf("extracted ds %d sigs %d", len(dsSet), len(dsSigs))
	t.Logf("ds matches child key: %v", dsMatchesDNSKEY([]dns.RR{ds}, []*dns.DNSKEY{childKey}))
	state, stateErr := v.trustedKeys("example.")
	t.Logf("trustedKeys(example.): state=%+v err=%v", state, stateErr)

	msg := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess}}
	msg.Answer = []dns.RR{a, aSig}
	q := dns.Question{Name: "www.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}

	secure, insecure, serr := v.validateMessage(msg, q, false)
	t.Logf("validation secure=%v insecure=%v err=%v", secure, insecure, serr)
	validated, err := v.validateResponse(msg, q, "strict", true)
	if err == nil {
		t.Fatalf("expected error for DS mismatch")
	}
	if validated {
		t.Fatalf("validation should fail on DS mismatch")
	}
}

func TestValidatorNSECNXDOMAIN(t *testing.T) {
	now := time.Now()
	rootKey, rootPriv := mustGenerateKey(".")
	childKey, childPriv := mustGenerateKey("example.")

	ds := childKey.ToDS(dns.SHA256)
	dsSig := mustSign([]dns.RR{ds}, rootKey, rootPriv, ".", dns.TypeDS, now)
	rootDNSKEYSig := mustSign([]dns.RR{rootKey}, rootKey, rootPriv, ".", dns.TypeDNSKEY, now)
	dnskeySig := mustSign([]dns.RR{childKey}, childKey, childPriv, "example.", dns.TypeDNSKEY, now)

	nsec1 := &dns.NSEC{Hdr: dns.RR_Header{Name: "a.example.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 600}, NextDomain: "z.example.", TypeBitMap: []uint16{dns.TypeNS}}
	nsec1Sig := mustSign([]dns.RR{nsec1}, childKey, childPriv, "example.", dns.TypeNSEC, now)
	nsec2 := &dns.NSEC{Hdr: dns.RR_Header{Name: "*.example.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 600}, NextDomain: "example.", TypeBitMap: []uint16{dns.TypeA}}
	nsec2Sig := mustSign([]dns.RR{nsec2}, childKey, childPriv, "example.", dns.TypeNSEC, now)
	nsec3 := &dns.NSEC{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 600}, NextDomain: "zzz.example.", TypeBitMap: []uint16{dns.TypeNS, dns.TypeSOA}}
	nsec3Sig := mustSign([]dns.RR{nsec3}, childKey, childPriv, "example.", dns.TypeNSEC, now)

	v := newValidator()
	v.trustAnchors = []dns.RR{rootKey}
	v.now = func() time.Time { return now }
	v.resolveDS = func(string) (*dns.Msg, error) { return &dns.Msg{Answer: []dns.RR{ds, dsSig}}, nil }
	v.resolveDNSKEY = func(name string) (*dns.Msg, error) {
		switch dns.Fqdn(name) {
		case ".":
			return &dns.Msg{Answer: []dns.RR{rootKey, rootDNSKEYSig}}, nil
		case "example.":
			return &dns.Msg{Answer: []dns.RR{childKey, dnskeySig}}, nil
		default:
			return &dns.Msg{}, nil
		}
	}

	msg := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError}}
	msg.Ns = []dns.RR{nsec1, nsec1Sig, nsec2, nsec2Sig, nsec3, nsec3Sig}
	q := dns.Question{Name: "no.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}

	validated, err := v.validateResponse(msg, q, "strict", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !validated {
		t.Fatalf("expected NXDOMAIN proof to validate")
	}
}

func TestValidatorInsecureDelegation(t *testing.T) {
	now := time.Now()
	rootKey, rootPriv := mustGenerateKey(".")
	childKey, childPriv := mustGenerateKey("example.")
	rootDNSKEYSig := mustSign([]dns.RR{rootKey}, rootKey, rootPriv, ".", dns.TypeDNSKEY, now)
	dnskeySig := mustSign([]dns.RR{childKey}, childKey, childPriv, "example.", dns.TypeDNSKEY, now)

	v := newValidator()
	v.trustAnchors = []dns.RR{rootKey}
	v.now = func() time.Time { return now }
	v.resolveDS = func(string) (*dns.Msg, error) { return &dns.Msg{}, nil }
	v.resolveDNSKEY = func(name string) (*dns.Msg, error) {
		switch dns.Fqdn(name) {
		case ".":
			return &dns.Msg{Answer: []dns.RR{rootKey, rootDNSKEYSig}}, nil
		case "example.":
			return &dns.Msg{Answer: []dns.RR{childKey, dnskeySig}}, nil
		default:
			return &dns.Msg{}, nil
		}
	}

	msg := &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess}}
	msg.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "www.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.IP{9, 9, 9, 9}}}
	q := dns.Question{Name: "www.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}

	validated, err := v.validateResponse(msg, q, "strict", true)
	if err != nil {
		t.Fatalf("unexpected error for insecure delegation: %v", err)
	}
	if validated {
		t.Fatalf("insecure delegation should not be marked validated")
	}
}

func mustGenerateKey(name string) (*dns.DNSKEY, crypto.Signer) {
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.RSASHA256,
	}
	privRaw, err := key.Generate(1024)
	if err != nil {
		panic(err)
	}
	signer, ok := privRaw.(crypto.Signer)
	if !ok {
		panic("generated key does not implement crypto.Signer")
	}
	return key, signer
}

func mustSign(rrs []dns.RR, key *dns.DNSKEY, priv crypto.Signer, signer string, covered uint16, now time.Time) *dns.RRSIG {
	sig := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(rrs[0].Header().Name),
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    rrs[0].Header().Ttl,
		},
		TypeCovered: covered,
		Algorithm:   key.Algorithm,
		Labels:      uint8(dns.CountLabel(rrs[0].Header().Name)),
		OrigTtl:     rrs[0].Header().Ttl,
		Expiration:  uint32(now.Add(24 * time.Hour).Unix()),
		Inception:   uint32(now.Add(-1 * time.Hour).Unix()),
		KeyTag:      key.KeyTag(),
		SignerName:  dns.Fqdn(signer),
	}
	if err := sig.Sign(priv, rrs); err != nil {
		panic(err)
	}
	return sig
}
