package recursive

import (
	"testing"

	"github.com/miekg/dns"
)

// TestBindDSToDNSKEYRejectsUnvouchedSelfSign is the append-extra-key forgery: the
// DNSKEY RRset contains the legitimate (DS-vouched) key plus an attacker key, but the
// RRset is self-signed only by the attacker key. The parent DS vouches only for the
// legitimate key, which did NOT sign the RRset, so the set must be rejected. Checking
// the DS match and the self-signature independently (the old behavior) accepted it.
func TestBindDSToDNSKEYRejectsUnvouchedSelfSign(t *testing.T) {
	realKey, realPriv := genKey(t, "example.")
	evilKey, evilPriv := genKey(t, "example.")
	dnskeyRRs := []dns.RR{realKey, evilKey}

	ds := realKey.ToDS(dns.SHA256) // parent vouches ONLY for the real key
	if ds == nil {
		t.Fatalf("ToDS returned nil")
	}

	// DNSKEY RRset signed only by the un-vouched (attacker) key.
	evilSig := signRRset(t, dnskeyRRs, evilKey, evilPriv, "example.")
	if bindDSToDNSKEY([]dns.RR{ds}, dnskeyRRs, []*dns.RRSIG{evilSig}, []*dns.DNSKEY{realKey, evilKey}) {
		t.Fatalf("DNSKEY RRset self-signed only by an un-vouched key was accepted")
	}

	// Control: the same RRset signed by the DS-vouched key is accepted.
	realSig := signRRset(t, dnskeyRRs, realKey, realPriv, "example.")
	if !bindDSToDNSKEY([]dns.RR{ds}, dnskeyRRs, []*dns.RRSIG{realSig}, []*dns.DNSKEY{realKey, evilKey}) {
		t.Fatalf("DNSKEY RRset signed by the DS-vouched key was rejected")
	}
}
