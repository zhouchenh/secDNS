package recursive

import (
	"crypto"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// genKey generates an ECDSA P-256 zone signing key owned by zone.
func genKey(t *testing.T, zone string) (*dns.DNSKEY, crypto.Signer) {
	t.Helper()
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: dns.Fqdn(zone), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	priv, err := key.Generate(256)
	if err != nil {
		t.Fatalf("DNSKEY.Generate: %v", err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatalf("generated private key is not a crypto.Signer")
	}
	return key, signer
}

// signRRset signs rrs with key, claiming signerName as the RRSIG signer (which may
// differ from the RR owner — that is exactly the cross-zone-signer case to reject).
func signRRset(t *testing.T, rrs []dns.RR, key *dns.DNSKEY, priv crypto.Signer, signerName string) *dns.RRSIG {
	t.Helper()
	owner := rrs[0].Header().Name
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: rrs[0].Header().Ttl},
		TypeCovered: rrs[0].Header().Rrtype,
		Algorithm:   key.Algorithm,
		Labels:      uint8(dns.CountLabel(owner)),
		OrigTtl:     rrs[0].Header().Ttl,
		Expiration:  uint32(time.Now().Add(24 * time.Hour).Unix()),
		Inception:   uint32(time.Now().Add(-time.Hour).Unix()),
		KeyTag:      key.KeyTag(),
		SignerName:  dns.Fqdn(signerName),
	}
	if err := sig.Sign(priv, rrs); err != nil {
		t.Fatalf("RRSIG.Sign: %v", err)
	}
	return sig
}

func aRRset(owner string) []dns.RR {
	return []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: dns.Fqdn(owner), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
		A:   net.IP{192, 0, 2, 1},
	}}
}

// TestVerifyRRSetWithKeysAcceptsInBailiwickSigner confirms a legitimate signature —
// signer is the zone apex at/above the owner — still verifies.
func TestVerifyRRSetWithKeysAcceptsInBailiwickSigner(t *testing.T) {
	key, priv := genKey(t, "victim.example.")
	rrs := aRRset("www.victim.example.")
	sig := signRRset(t, rrs, key, priv, "victim.example.")

	ok, err := verifyRRSetWithKeys(rrs, []*dns.RRSIG{sig}, []*dns.DNSKEY{key}, false)
	if !ok {
		t.Fatalf("legitimate in-bailiwick signature was rejected: %v", err)
	}
}

// TestVerifyRRSetWithKeysRejectsCrossZoneSigner is the forgery case: a key owned by
// evil.example. produces a cryptographically valid RRSIG over www.victim.example.'s
// RRset, naming evil.example. as the signer. miekg's RRSIG.Verify accepts it (signer
// equals key owner, crypto is valid); the bailiwick check must reject it because
// evil.example. is not an ancestor of www.victim.example.
func TestVerifyRRSetWithKeysRejectsCrossZoneSigner(t *testing.T) {
	evilKey, evilPriv := genKey(t, "evil.example.")
	rrs := aRRset("www.victim.example.")
	sig := signRRset(t, rrs, evilKey, evilPriv, "evil.example.")

	// Sanity: the signature is cryptographically valid under the evil key (so the
	// only thing that can reject it is the bailiwick check).
	if err := sig.Verify(evilKey, rrs); err != nil {
		t.Fatalf("test setup: forged signature is not crypto-valid under its key: %v", err)
	}

	ok, _ := verifyRRSetWithKeys(rrs, []*dns.RRSIG{sig}, []*dns.DNSKEY{evilKey}, false)
	if ok {
		t.Fatalf("cross-zone signer forgery was accepted (signer evil.example. signed www.victim.example.)")
	}
}
