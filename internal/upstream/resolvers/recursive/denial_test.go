package recursive

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// bumpHash returns the next base32hex string after h (with carry), so that (h, bumpHash(h))
// is an empty span — a record with NextDomain == bumpHash(owner) covers nothing.
func bumpHash(h string) string {
	const b32 = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
	b := []byte(h)
	for i := len(b) - 1; i >= 0; i-- {
		idx := strings.IndexByte(b32, b[i])
		if idx >= 0 && idx < 31 {
			b[i] = b32[idx+1]
			return string(b)
		}
		b[i] = '0' // carry into the next position
	}
	return string(b)
}

func TestVerifyNSEC3CoverageNXDOMAIN(t *testing.T) {
	const salt = "aabbccdd"
	ceHash := dns.HashName("example.", dns.SHA1, 0, salt)
	// ceMatch matches example. (the closest encloser) and, with NextDomain == its own
	// owner hash, covers nothing — so it cannot stand in for the next-closer/wildcard
	// covers on its own.
	ceMatch := &dns.NSEC3{
		Hdr:        dns.RR_Header{Name: ceHash + ".example.", Rrtype: dns.TypeNSEC3, Class: dns.ClassINET},
		Hash:       dns.SHA1,
		Iterations: 0,
		Salt:       salt,
		NextDomain: bumpHash(ceHash),
		TypeBitMap: []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeDNSKEY},
	}
	// cover spans the whole hash space, so it covers any next-closer name and any wildcard.
	cover := &dns.NSEC3{
		Hdr:        dns.RR_Header{Name: "00000000000000000000000000000000.example.", Rrtype: dns.TypeNSEC3, Class: dns.ClassINET},
		Hash:       dns.SHA1,
		Iterations: 0,
		Salt:       salt,
		NextDomain: "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV",
	}
	if !ceMatch.Match("example.") || ceMatch.Cover("sub.example.") || !cover.Cover("sub.example.") {
		t.Skipf("test setup: NSEC3 match/cover assumptions did not hold")
	}
	// Valid: closest encloser matches example., the next closer name (sub.example.) is
	// covered, and *.example. is covered.
	if !verifyNSEC3Coverage("sub.example.", dns.TypeA, dns.RcodeNameError, []*dns.NSEC3{ceMatch, cover}, 100) {
		t.Fatalf("a valid NSEC3 NXDOMAIN proof should validate")
	}
	// Reject: a bare covering NSEC3 with no matching closest encloser is not a proof.
	if verifyNSEC3Coverage("sub.example.", dns.TypeA, dns.RcodeNameError, []*dns.NSEC3{cover}, 100) {
		t.Fatalf("a covering NSEC3 without a closest-encloser match must not prove NXDOMAIN")
	}
	// Reject: a closest-encloser match with nothing covering the next closer name (RFC
	// 5155 section 8.3) is not a proof.
	if verifyNSEC3Coverage("sub.example.", dns.TypeA, dns.RcodeNameError, []*dns.NSEC3{ceMatch}, 100) {
		t.Fatalf("a closest-encloser match with no next-closer cover must not prove NXDOMAIN")
	}
}

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

func TestCanonicalLess(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"example.", "a.example.", true},      // ancestor sorts first
		{"a.example.", "example.", false},     //
		{"a.example.", "z.example.", true},    //
		{"*.example.", "a.example.", true},    // '*' (0x2a) < 'a' (0x61)
		{"a.example.", "a.example.", false},   // equal
		{"a.z.example.", "b.example.", false}, // right-to-left: 'z' > 'b' (byte order would disagree)
		{"b.example.", "a.z.example.", true},
	}
	for _, c := range cases {
		if got := canonicalLess(c.a, c.b); got != c.want {
			t.Errorf("canonicalLess(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestVerifyNSECCoverageNXDOMAIN(t *testing.T) {
	nsec := func(owner, next string, types ...uint16) *dns.NSEC {
		return &dns.NSEC{
			Hdr:        dns.RR_Header{Name: owner, Rrtype: dns.TypeNSEC, Class: dns.ClassINET},
			NextDomain: next,
			TypeBitMap: types,
		}
	}
	// Legitimate NXDOMAIN for nope.example.: covered by (a.example., z.example.), and
	// the wildcard *.example. is covered by (example., a.example.) -> proof holds.
	proof := []*dns.NSEC{
		nsec("example.", "a.example.", dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC),
		nsec("a.example.", "z.example.", dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC),
	}
	if !verifyNSECCoverage("nope.example.", dns.TypeA, dns.RcodeNameError, proof) {
		t.Fatalf("a legitimate NXDOMAIN proof should be accepted")
	}
	// R2-02 forgery: a wildcard *.example. EXISTS, so nope.example. should have been
	// answered by the wildcard, not NXDOMAIN. The covering NSEC must not prove NXDOMAIN
	// (the old closestEncloser collapsed to root and accepted this).
	forge := []*dns.NSEC{
		nsec("a.example.", "z.example.", dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC), // covers nope.example.
		nsec("*.example.", "a.example.", dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC), // the wildcard exists
	}
	if verifyNSECCoverage("nope.example.", dns.TypeA, dns.RcodeNameError, forge) {
		t.Fatalf("NXDOMAIN must be rejected when a wildcard at the closest encloser exists")
	}
}

func TestNSECProvesNoDS(t *testing.T) {
	nsec := func(owner string, types ...uint16) *dns.NSEC {
		return &dns.NSEC{
			Hdr:        dns.RR_Header{Name: owner, Rrtype: dns.TypeNSEC, Class: dns.ClassINET},
			NextDomain: "zzz.",
			TypeBitMap: types,
		}
	}
	// Valid: owner == delegation point, NS set, DS and SOA clear.
	good := nsec("example.", dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC)
	if !nsecProvesNoDS("example.", []*dns.NSEC{good}) {
		t.Fatalf("NS-only delegation NSEC should prove no DS")
	}
	// DS present -> a DS exists, not a no-DS proof.
	withDS := nsec("example.", dns.TypeNS, dns.TypeDS, dns.TypeRRSIG)
	if nsecProvesNoDS("example.", []*dns.NSEC{withDS}) {
		t.Fatalf("an NSEC with the DS bit set must not prove no DS")
	}
	// SOA present -> this is the child apex NSEC, not a parent-side proof (RFC 6840 4.3).
	withSOA := nsec("example.", dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG)
	if nsecProvesNoDS("example.", []*dns.NSEC{withSOA}) {
		t.Fatalf("a child-apex NSEC (SOA bit set) must not prove no DS")
	}
	// No NS -> not a delegation.
	noNS := nsec("example.", dns.TypeA, dns.TypeRRSIG)
	if nsecProvesNoDS("example.", []*dns.NSEC{noNS}) {
		t.Fatalf("an NSEC without the NS bit must not prove a delegation no-DS")
	}
	// Wrong owner -> proves nothing about example.
	other := nsec("other.", dns.TypeNS, dns.TypeRRSIG)
	if nsecProvesNoDS("example.", []*dns.NSEC{other}) {
		t.Fatalf("an NSEC owned by a different name must not prove no DS for example.")
	}
}

func TestNextCloserName(t *testing.T) {
	cases := []struct{ qname, ce, want string }{
		{"sub.example.", "example.", "sub.example."},
		{"a.b.example.", "example.", "b.example."},
		{"a.b.c.example.", "c.example.", "b.c.example."},
		{"example.", "example.", ""}, // ce not a proper ancestor
		{"example.", "other.", ""},   // ce longer/unrelated
	}
	for _, c := range cases {
		if got := nextCloserName(c.qname, c.ce); got != c.want {
			t.Errorf("nextCloserName(%q,%q)=%q want %q", c.qname, c.ce, got, c.want)
		}
	}
}

func TestNSEC3ProvesNoDS(t *testing.T) {
	const salt = "aabbccdd"
	ho := func(n string) string { return dns.HashName(n, dns.SHA1, 0, salt) + ".example." }
	mk := func(owner string, flags uint8, next string, types ...uint16) *dns.NSEC3 {
		return &dns.NSEC3{
			Hdr:        dns.RR_Header{Name: owner, Rrtype: dns.TypeNSEC3, Class: dns.ClassINET},
			Hash:       dns.SHA1,
			Flags:      flags,
			Iterations: 0,
			Salt:       salt,
			NextDomain: next,
			TypeBitMap: types,
		}
	}
	// Direct NODATA: NSEC3 matching the delegation, NS set, DS and SOA clear.
	nodata := mk(ho("sub.example."), 0, "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV", dns.TypeNS, dns.TypeRRSIG)
	if !nodata.Match("sub.example.") {
		t.Skipf("test setup: NSEC3.Match did not hold")
	}
	if !nsec3ProvesNoDS("sub.example.", []*dns.NSEC3{nodata}, 100) {
		t.Fatalf("a matching NS-only NSEC3 should prove no DS")
	}
	// DS bit set at the match -> a DS exists.
	withDS := mk(ho("sub.example."), 0, "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV", dns.TypeNS, dns.TypeDS)
	if nsec3ProvesNoDS("sub.example.", []*dns.NSEC3{withDS}, 100) {
		t.Fatalf("a matching NSEC3 with the DS bit must not prove no DS")
	}
	// Opt-out: closest encloser matches (example. apex) and an opt-out NSEC3 covers the
	// next closer name (sub.example.).
	ceMatch := mk(ho("example."), 0, "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV", dns.TypeNS, dns.TypeSOA, dns.TypeDNSKEY)
	optout := mk("00000000000000000000000000000000.example.", 0x01, "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV", dns.TypeNS)
	if !ceMatch.Match("example.") || !optout.Cover("sub.example.") {
		t.Skipf("test setup: opt-out match/cover assumptions did not hold")
	}
	if !nsec3ProvesNoDS("sub.example.", []*dns.NSEC3{ceMatch, optout}, 100) {
		t.Fatalf("opt-out span should prove an insecure (no-DS) delegation")
	}
	// Same span but the opt-out flag is clear -> not an opt-out proof.
	noOpt := mk("00000000000000000000000000000000.example.", 0x00, "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV", dns.TypeNS)
	if nsec3ProvesNoDS("sub.example.", []*dns.NSEC3{ceMatch, noOpt}, 100) {
		t.Fatalf("a covering NSEC3 without the opt-out flag must not prove no DS")
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
