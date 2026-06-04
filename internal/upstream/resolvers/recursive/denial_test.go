package recursive

import (
	"testing"

	"github.com/miekg/dns"
)

func TestNSEC3ParamsUsable(t *testing.T) {
	mk := func(hash uint8, iter uint16, salt string) *dns.NSEC3 {
		return &dns.NSEC3{Hash: hash, Iterations: iter, Salt: salt}
	}
	if !nsec3ParamsUsable([]*dns.NSEC3{mk(dns.SHA1, 50, "ab")}, 100) {
		t.Fatalf("SHA-1 with iterations within the cap should be usable")
	}
	if nsec3ParamsUsable([]*dns.NSEC3{mk(dns.SHA1, 150, "ab")}, 100) {
		t.Fatalf("iterations above the cap must be unusable (CPU-DoS gate)")
	}
	if nsec3ParamsUsable([]*dns.NSEC3{mk(2, 0, "ab")}, 100) {
		t.Fatalf("an unknown hash algorithm must be unusable")
	}
	if nsec3ParamsUsable([]*dns.NSEC3{mk(dns.SHA1, 0, "ab"), mk(dns.SHA1, 5, "ab")}, 100) {
		t.Fatalf("mixed iteration counts must be unusable")
	}
	if nsec3ParamsUsable([]*dns.NSEC3{mk(dns.SHA1, 0, "ab"), mk(dns.SHA1, 0, "cd")}, 100) {
		t.Fatalf("mixed salts must be unusable")
	}
	if nsec3ParamsUsable(nil, 100) {
		t.Fatalf("an empty NSEC3 set must be unusable")
	}
}

func TestVerifyNSECCoverageNODATAExactMatch(t *testing.T) {
	nsec := func(owner, next string, types ...uint16) *dns.NSEC {
		return &dns.NSEC{
			Hdr:        dns.RR_Header{Name: owner, Rrtype: dns.TypeNSEC, Class: dns.ClassINET},
			NextDomain: next,
			TypeBitMap: types,
		}
	}
	// Exact-owner NODATA: AAAA absent, CNAME absent -> proof holds.
	exact := nsec("www.example.", "x.example.", dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC)
	if !verifyNSECCoverage("www.example.", dns.TypeAAAA, dns.RcodeSuccess, []*dns.NSEC{exact}) {
		t.Fatalf("exact-owner NODATA proof should be accepted")
	}
	// A covering (non-owner) NSEC proves non-existence, not NODATA -> must be rejected.
	covering := nsec("a.example.", "z.example.", dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC)
	if verifyNSECCoverage("www.example.", dns.TypeAAAA, dns.RcodeSuccess, []*dns.NSEC{covering}) {
		t.Fatalf("a covering (non-owner) NSEC must not be accepted as a NODATA proof")
	}
	// CNAME present at the exact owner -> the answer should have followed the alias.
	withCNAME := nsec("www.example.", "x.example.", dns.TypeCNAME, dns.TypeRRSIG, dns.TypeNSEC)
	if verifyNSECCoverage("www.example.", dns.TypeAAAA, dns.RcodeSuccess, []*dns.NSEC{withCNAME}) {
		t.Fatalf("NODATA with a CNAME present at the owner must be rejected")
	}
	// qtype present -> not NODATA.
	withType := nsec("www.example.", "x.example.", dns.TypeA, dns.TypeAAAA, dns.TypeRRSIG)
	if verifyNSECCoverage("www.example.", dns.TypeAAAA, dns.RcodeSuccess, []*dns.NSEC{withType}) {
		t.Fatalf("NODATA proof must fail when the qtype bit is set")
	}
}

func TestVerifyNSEC3CoverageNODATARequiresMatch(t *testing.T) {
	const salt = "aabbccdd"
	hashedOwner := func(name string) string {
		return dns.HashName(name, dns.SHA1, 0, salt) + ".example."
	}
	match := &dns.NSEC3{
		Hdr:        dns.RR_Header{Name: hashedOwner("www.example."), Rrtype: dns.TypeNSEC3, Class: dns.ClassINET},
		Hash:       dns.SHA1,
		Iterations: 0,
		Salt:       salt,
		TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG},
	}
	if !match.Match("www.example.") {
		t.Skipf("test setup: NSEC3.Match did not hold for the constructed owner")
	}
	// Matching NSEC3 with AAAA and CNAME bits clear -> NODATA accepted.
	if !verifyNSEC3Coverage("www.example.", dns.TypeAAAA, dns.RcodeSuccess, []*dns.NSEC3{match}, 100) {
		t.Fatalf("a matching NSEC3 NODATA proof should be accepted")
	}
	// A record that does not match qname must not prove NODATA (the removed bare-cover bug).
	nonMatch := &dns.NSEC3{
		Hdr:        dns.RR_Header{Name: hashedOwner("other.example."), Rrtype: dns.TypeNSEC3, Class: dns.ClassINET},
		Hash:       dns.SHA1,
		Iterations: 0,
		Salt:       salt,
		TypeBitMap: []uint16{dns.TypeA},
	}
	if verifyNSEC3Coverage("www.example.", dns.TypeAAAA, dns.RcodeSuccess, []*dns.NSEC3{nonMatch}, 100) {
		t.Fatalf("a non-matching NSEC3 must not prove NODATA")
	}
	// Over-cap iterations -> rejected by the parameter gate even though it would match.
	overcap := &dns.NSEC3{Hdr: match.Hdr, Hash: dns.SHA1, Iterations: 5000, Salt: salt, TypeBitMap: match.TypeBitMap}
	if verifyNSEC3Coverage("www.example.", dns.TypeAAAA, dns.RcodeSuccess, []*dns.NSEC3{overcap}, 100) {
		t.Fatalf("an over-cap NSEC3 must be rejected by the iteration gate")
	}
}
