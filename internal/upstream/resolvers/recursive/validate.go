package recursive

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

var (
	errDNSSECNotImplemented = errors.New("dnssec validation not yet implemented")
	errDNSSECMissingSig     = errors.New("dnssec: no usable signatures")
	errDNSSECUntrustedKey   = errors.New("dnssec: no trusted key for signer")
	errDNSSECNoProof        = errors.New("dnssec: missing nsec/nsec3 proof")
	errDNSSECNoKeys         = errors.New("dnssec: missing dnskey rrset")
)

type dnssecValidator struct {
	trustAnchors  []dns.RR // Root trust anchors (DNSKEY/DS)
	now           func() time.Time
	resolveDNSKEY func(name string) (*dns.Msg, error)
	resolveDS     func(name string) (*dns.Msg, error)
	logger        func(msg string)
	nsec3MaxIter  uint16 // maximum accepted NSEC3 iteration count (RFC 9276)

	keyCache map[string]*keyState
	cacheMu  sync.Mutex
	metrics  *validationMetrics
}

type keyState struct {
	keys    []*dns.DNSKEY
	secure  bool
	expires time.Time
}

type validationMetrics struct {
	validated atomic.Uint64
	insecure  atomic.Uint64
	bogus     atomic.Uint64
	unsigned  atomic.Uint64
}

func newValidator() *dnssecValidator {
	return &dnssecValidator{
		trustAnchors: defaultTrustAnchors(),
		now:          time.Now,
		resolveDNSKEY: func(string) (*dns.Msg, error) {
			return nil, errDNSSECNotImplemented
		},
		resolveDS: func(string) (*dns.Msg, error) {
			return nil, errDNSSECNotImplemented
		},
		logger:       func(string) {},
		nsec3MaxIter: 100,
		keyCache:     map[string]*keyState{},
		metrics:      &validationMetrics{},
	}
}

// validateResponse attempts DNSSEC validation and returns whether the message was validated.
func (v *dnssecValidator) validateResponse(msg *dns.Msg, q dns.Question, policy string, shouldValidate bool) (bool, error) {
	if !shouldValidate {
		return false, nil
	}

	switch policy {
	case "off":
		return false, nil
	case "permissive", "strict":
	default:
		return false, fmt.Errorf("dnssec policy %q not supported", policy)
	}

	if err := v.checkRRSIGTimings(msg); err != nil {
		v.metrics.bogus.Add(1)
		if policy == "strict" {
			return false, err
		}
		v.logger(fmt.Sprintf("dnssec %s: rrsig time check failed: %v", policy, err))
		return false, nil
	}

	secure, insecure, err := v.validateMessage(msg, q, policy == "permissive")
	if err != nil {
		v.metrics.bogus.Add(1)
		if policy == "strict" {
			return false, err
		}
		v.logger(fmt.Sprintf("dnssec %s: validation failed: %v", policy, err))
		return false, nil
	}

	if secure {
		v.metrics.validated.Add(1)
		return true, nil
	}
	if insecure {
		v.metrics.insecure.Add(1)
		return false, nil
	}
	v.metrics.unsigned.Add(1)
	if policy == "strict" {
		return false, errDNSSECMissingSig
	}
	return false, nil
}

// validateMessage verifies signatures/proofs for the response. It returns (secureValidated, insecureDelegation, error).
func (v *dnssecValidator) validateMessage(msg *dns.Msg, q dns.Question, bestEffort bool) (bool, bool, error) {
	var (
		secureValidated = true
		insecureZone    bool
		anySig          bool
	)

	// If the delegation is explicitly insecure (no DS in any ancestor), skip strict validation and return insecure.
	if st := v.findTrustForName(normalizeName(q.Name)); st != nil && !st.secure {
		return false, true, nil
	}

	sections := [][]dns.RR{msg.Answer, msg.Ns}
	for _, sec := range sections {
		res, err := v.validateSection(sec, bestEffort)
		if err != nil {
			return false, false, err
		}
		if res.hasSig {
			anySig = true
		}
		if res.insecure || (res.hasSig && !res.secure) {
			secureValidated = false
		}
		if res.insecure {
			insecureZone = true
		}
	}

	// Negative answers: enforce NSEC/NSEC3 proof coverage.
	if msg.Rcode == dns.RcodeNameError || (msg.Rcode == dns.RcodeSuccess && len(msg.Answer) == 0) {
		proof, insecureProof, err := v.validateDenial(msg, q, bestEffort)
		if err != nil {
			return false, false, err
		}
		if proof {
			anySig = true
			if insecureProof {
				secureValidated = false
			}
		}
		if insecureProof {
			insecureZone = true
		}
	}

	if !anySig {
		// Treat unsigned zones with no DS as insecure instead of bogus.
		state, err := v.trustedKeys(normalizeName(q.Name))
		if err == nil && state != nil && !state.secure {
			return false, true, nil
		}
		if bestEffort {
			return false, insecureZone, nil
		}
		return false, insecureZone, errDNSSECMissingSig
	}
	return secureValidated, insecureZone, nil
}

type sectionValidation struct {
	secure   bool
	insecure bool
	hasSig   bool
}

func (v *dnssecValidator) validateSection(section []dns.RR, bestEffort bool) (sectionValidation, error) {
	result := sectionValidation{}
	rrsets := groupRRsets(section)
	for _, set := range rrsets {
		if len(set.sigs) == 0 {
			if bestEffort {
				continue
			}
			return result, errDNSSECMissingSig
		}
		result.hasSig = true
		signer := normalizeName(set.sigs[0].SignerName)
		state, err := v.trustedKeys(signer)
		if err != nil {
			if bestEffort {
				v.logger(fmt.Sprintf("dnssec: unable to fetch keys for %s: %v", signer, err))
				continue
			}
			return result, err
		}
		if state == nil || !state.secure {
			result.insecure = true
			if state == nil || len(state.keys) == 0 {
				continue
			}
		}
		verified, err := verifyRRSetWithKeys(set.rrs, set.sigs, state.keys, bestEffort)
		if err != nil {
			return result, err
		}
		if verified && state.secure {
			result.secure = true
		}
	}
	return result, nil
}

// validateDenial validates NSEC/NSEC3 proofs for NXDOMAIN/NODATA.
func (v *dnssecValidator) validateDenial(msg *dns.Msg, q dns.Question, bestEffort bool) (bool, bool, error) {
	proofs := collectProofRecords(msg.Ns)
	if len(proofs) == 0 {
		if bestEffort {
			return false, false, nil
		}
		return false, false, errDNSSECNoProof
	}

	secRes, err := v.validateSection(proofs, bestEffort)
	if err != nil {
		return false, false, err
	}
	if secRes.insecure {
		// Insecure delegation proofs indicate unsigned zone; consider it insecure.
		return false, true, nil
	}

	qname := normalizeName(q.Name)
	qtype := q.Qtype

	nsecRecords, nsec3Records := splitProofs(proofs)
	var covered bool
	if len(nsecRecords) > 0 {
		covered = verifyNSECCoverage(qname, qtype, msg.Rcode, nsecRecords)
	} else if len(nsec3Records) > 0 {
		covered = verifyNSEC3Coverage(qname, qtype, msg.Rcode, nsec3Records, v.nsec3MaxIter)
	} else {
		if bestEffort {
			return false, false, nil
		}
		return false, false, errDNSSECNoProof
	}

	if !covered {
		if bestEffort {
			return false, false, nil
		}
		return false, false, fmt.Errorf("dnssec: negative proof coverage failed for %s", qname)
	}

	if secRes.secure {
		return true, false, nil
	}
	return true, secRes.insecure, nil
}

// trustedKeys returns DNSKEYs for a zone validated to a trusted parent (or root).
func (v *dnssecValidator) trustedKeys(zone string) (*keyState, error) {
	zone = normalizeName(zone)

	v.cacheMu.Lock()
	if st, ok := v.keyCache[zone]; ok && v.now().Before(st.expires) {
		v.cacheMu.Unlock()
		return st, nil
	}
	v.cacheMu.Unlock()

	// Root: trust anchors.
	if zone == "." {
		anchors := keysForAnchors(v.trustAnchors)
		if len(anchors) == 0 {
			return nil, errDNSSECNoKeys
		}
		msg, err := v.resolveDNSKEY(zone)
		if err != nil {
			return nil, err
		}
		rrs, sigs := extractRRSet(msg, dns.TypeDNSKEY, zone)
		keys := toDNSKEYs(rrs)
		if len(keys) == 0 {
			return nil, errDNSSECNoKeys
		}
		if _, err := verifyRRSetWithKeys(rrs, sigs, anchors, false); err != nil {
			return nil, err
		}
		expire := rrsetExpiry(rrs, sigs, v.now())
		if expire.IsZero() {
			expire = v.now().Add(48 * time.Hour)
		}
		state := &keyState{keys: keys, secure: true, expires: expire}
		v.storeKeyState(zone, state)
		return state, nil
	}

	parent := parentZone(zone)
	parentState, err := v.trustedKeys(parent)
	if err != nil {
		return nil, err
	}

	dsMsg, err := v.resolveDS(zone)
	if err != nil {
		return nil, err
	}
	dsSet, dsSigs := extractRRSet(dsMsg, dns.TypeDS, zone)
	dsExpiry := rrsetExpiry(dsSet, dsSigs, v.now())
	if len(dsSet) == 0 {
		// No DS RRset. Declaring the child Insecure (unsigned) is only sound if the
		// parent authentically proves that no DS exists at the delegation point;
		// otherwise an on-path attacker who strips the DS RRset (and its NSEC/NSEC3
		// proof) would downgrade a secure child to unsigned and have forged data
		// accepted (RFC 4035 section 5.2, RFC 6840 section 5). If the parent is itself
		// insecure, insecurity is inherited and no proof is required.
		if parentState != nil && parentState.secure && len(parentState.keys) > 0 {
			if !v.proveNoDS(zone, dsMsg, parentState.keys) {
				return nil, fmt.Errorf("dnssec: no authenticated DS-absence proof for %s (possible downgrade)", zone)
			}
		}
		state := &keyState{secure: false, keys: nil, expires: fallbackExpiry(v.now())}
		if !dsExpiry.IsZero() && dsExpiry.Before(state.expires) {
			state.expires = dsExpiry
		}
		v.storeKeyState(zone, state)
		return state, nil
	}

	if parentState == nil || !parentState.secure || len(parentState.keys) == 0 {
		state := &keyState{secure: false, keys: nil, expires: fallbackExpiry(v.now())}
		v.storeKeyState(zone, state)
		return state, nil
	}

	if _, err := verifyRRSetWithKeys(dsSet, dsSigs, parentState.keys, false); err != nil {
		return nil, err
	}

	if !dsSetHasSupportedAlgo(dsSet) {
		// RFC 6840 section 5.2 / RFC 8624: an authenticated DS RRset whose algorithm
		// or digest types are all unsupported means the path to the child cannot be
		// verified; the child zone is treated as unsigned (Insecure), never
		// Bogus/SERVFAIL.
		state := &keyState{secure: false, keys: nil, expires: fallbackExpiry(v.now())}
		if !dsExpiry.IsZero() && dsExpiry.Before(state.expires) {
			state.expires = dsExpiry
		}
		v.storeKeyState(zone, state)
		return state, nil
	}

	dnskeyMsg, err := v.resolveDNSKEY(zone)
	if err != nil {
		return nil, err
	}
	dnskeyRRs, dnskeySigs := extractRRSet(dnskeyMsg, dns.TypeDNSKEY, zone)
	dnskeys := toDNSKEYs(dnskeyRRs)
	if len(dnskeys) == 0 {
		return nil, errDNSSECNoKeys
	}
	if !bindDSToDNSKEY(dsSet, dnskeyRRs, dnskeySigs, dnskeys) {
		return nil, fmt.Errorf("dnssec: no DS-vouched key signs the DNSKEY RRset for %s", zone)
	}

	expiry := rrsetExpiry(dnskeyRRs, dnskeySigs, v.now())
	if dsExpiry.IsZero() {
		dsExpiry = expiry
	}
	if !expiry.IsZero() && (dsExpiry.IsZero() || expiry.Before(dsExpiry)) {
		dsExpiry = expiry
	}

	state := &keyState{
		keys:    dnskeys,
		secure:  true,
		expires: dsExpiry,
	}
	if state.expires.IsZero() {
		state.expires = v.now().Add(24 * time.Hour)
	}
	v.storeKeyState(zone, state)
	return state, nil
}

func (v *dnssecValidator) storeKeyState(zone string, st *keyState) {
	v.cacheMu.Lock()
	defer v.cacheMu.Unlock()
	v.keyCache[zone] = st
}

func rrsetExpiry(rrs []dns.RR, sigs []*dns.RRSIG, now time.Time) time.Time {
	var ttlExpiry time.Time
	if len(rrs) > 0 {
		minTTL := rrs[0].Header().Ttl
		for _, rr := range rrs {
			if rr.Header().Ttl < minTTL {
				minTTL = rr.Header().Ttl
			}
		}
		ttlExpiry = now.Add(time.Duration(minTTL) * time.Second)
	}
	var sigExpiry time.Time
	if len(sigs) > 0 {
		minExp := sigs[0].Expiration
		for _, s := range sigs {
			if s.Expiration < minExp {
				minExp = s.Expiration
			}
		}
		sigExpiry = time.Unix(int64(minExp), 0)
	}
	switch {
	case ttlExpiry.IsZero():
		return sigExpiry
	case sigExpiry.IsZero():
		return ttlExpiry
	default:
		if ttlExpiry.Before(sigExpiry) {
			return ttlExpiry
		}
		return sigExpiry
	}
}

// bindDSToDNSKEY reports whether the zone's DNSKEY RRset is vouched for by the
// parent: some DS must match a key (KeyTag + Algorithm + digest) AND that same key
// must sign the DNSKEY RRset (RFC 4035 section 5.2). Checking the DS match and the
// DNSKEY self-signature independently would let an attacker append an extra key,
// self-sign the DNSKEY RRset with it, and pass both checks while the DS only vouches
// for the legitimate key. All key-tag matches are tried (RFC 4034 appendix B).
func bindDSToDNSKEY(dsSet []dns.RR, dnskeyRRs []dns.RR, dnskeySigs []*dns.RRSIG, keys []*dns.DNSKEY) bool {
	for _, dsRR := range dsSet {
		ds, ok := dsRR.(*dns.DS)
		if !ok {
			continue
		}
		for _, k := range keys {
			if ds.KeyTag != k.KeyTag() || ds.Algorithm != k.Algorithm {
				continue
			}
			gen := k.ToDS(ds.DigestType)
			if gen == nil || !strings.EqualFold(gen.Digest, ds.Digest) {
				continue
			}
			if vouched, _ := verifyRRSetWithKeys(dnskeyRRs, dnskeySigs, []*dns.DNSKEY{k}, false); vouched {
				return true
			}
		}
	}
	return false
}

// supportedSignAlgos and supportedDSDigests list the DNSSEC signing algorithms and
// DS digest types this validator can verify (RFC 8624). Anything else makes a zone
// Insecure (RFC 6840 section 5.2), never Bogus.
var supportedSignAlgos = map[uint8]bool{
	dns.RSASHA1:          true,
	dns.RSASHA1NSEC3SHA1: true,
	dns.RSASHA256:        true,
	dns.RSASHA512:        true,
	dns.ECDSAP256SHA256:  true,
	dns.ECDSAP384SHA384:  true,
	dns.ED25519:          true,
}

var supportedDSDigests = map[uint8]bool{
	dns.SHA1:   true,
	dns.SHA256: true,
	dns.SHA384: true,
}

// dsSetHasSupportedAlgo reports whether the DS RRset contains at least one DS whose
// signing algorithm and digest type are both supported. If not, the child zone must
// be treated as unsigned (RFC 6840 section 5.2).
func dsSetHasSupportedAlgo(dsSet []dns.RR) bool {
	for _, rr := range dsSet {
		ds, ok := rr.(*dns.DS)
		if !ok {
			continue
		}
		if supportedSignAlgos[ds.Algorithm] && supportedDSDigests[ds.DigestType] {
			return true
		}
	}
	return false
}

type rrsetWithSig struct {
	rrs  []dns.RR
	sigs []*dns.RRSIG
}

func groupRRsets(section []dns.RR) []rrsetWithSig {
	type key struct {
		name string
		typ  uint16
	}
	sets := make(map[key]*rrsetWithSig)
	for _, rr := range section {
		switch v := rr.(type) {
		case *dns.RRSIG:
			k := key{name: normalizeName(v.Hdr.Name), typ: v.TypeCovered}
			set := sets[k]
			if set == nil {
				set = &rrsetWithSig{}
				sets[k] = set
			}
			set.sigs = append(set.sigs, v)
		default:
			k := key{name: normalizeName(rr.Header().Name), typ: rr.Header().Rrtype}
			set := sets[k]
			if set == nil {
				set = &rrsetWithSig{}
				sets[k] = set
			}
			set.rrs = append(set.rrs, rr)
		}
	}
	var out []rrsetWithSig
	for _, v := range sets {
		out = append(out, *v)
	}
	return out
}

func verifyRRSetWithKeys(rrs []dns.RR, sigs []*dns.RRSIG, keys []*dns.DNSKEY, bestEffort bool) (bool, error) {
	if len(sigs) == 0 {
		if bestEffort {
			return false, nil
		}
		return false, errDNSSECMissingSig
	}
	if len(keys) == 0 {
		if bestEffort {
			return false, nil
		}
		return false, errDNSSECUntrustedKey
	}
	for _, sig := range sigs {
		// RFC 4035 section 5.3.1: the signer must be in bailiwick of the RRset owner.
		// miekg/dns RRSIG.Verify checks SignerName == key owner and the cryptography
		// but NOT that the signer is an ancestor of the RR owner, so without this a
		// cross-zone signer (the holder of any signed zone signing a forged RRset for
		// an unrelated name) would be accepted.
		if len(rrs) == 0 || !signerInBailiwick(sig, rrs[0].Header().Name) {
			continue
		}
		for _, key := range keys {
			if sig.KeyTag != key.KeyTag() || sig.Algorithm != key.Algorithm {
				continue
			}
			if err := sig.Verify(key, rrs); err == nil {
				return true, nil
			}
		}
	}
	if bestEffort {
		return false, nil
	}
	return false, fmt.Errorf("dnssec: signature verification failed for %s %s", sigs[0].SignerName, dns.TypeToString[sigs[0].TypeCovered])
}

// checkRRSIGTimings ensures RRSIG inception/expiration are valid relative to now.
func (v *dnssecValidator) checkRRSIGTimings(msg *dns.Msg) error {
	now := uint32(v.now().Unix())
	for _, rr := range append(append([]dns.RR{}, msg.Answer...), append(msg.Ns, msg.Extra...)...) {
		sig, ok := rr.(*dns.RRSIG)
		if !ok {
			continue
		}
		if now < sig.Inception {
			return fmt.Errorf("rrsig not yet valid (inception %d)", sig.Inception)
		}
		if now > sig.Expiration {
			return fmt.Errorf("rrsig expired (expiration %d)", sig.Expiration)
		}
	}
	return nil
}

func normalizeName(name string) string {
	name = dns.Fqdn(strings.ToLower(name))
	if name == "" {
		return "."
	}
	return name
}

func extractRRSet(msg *dns.Msg, rrType uint16, name string) ([]dns.RR, []*dns.RRSIG) {
	if msg == nil {
		return nil, nil
	}
	name = normalizeName(name)
	var rrs []dns.RR
	var sigs []*dns.RRSIG
	for _, rr := range append(msg.Answer, msg.Ns...) {
		if rr.Header().Rrtype == rrType && normalizeName(rr.Header().Name) == name {
			rrs = append(rrs, rr)
		}
		if s, ok := rr.(*dns.RRSIG); ok && s.TypeCovered == rrType && normalizeName(s.Hdr.Name) == name {
			sigs = append(sigs, s)
		}
	}
	return rrs, sigs
}

// collectProofRecords returns the NSEC/NSEC3 records from an authority section and
// only the RRSIGs that cover them. The RRSIG over the SOA (always present in an
// NXDOMAIN/NODATA authority for negative caching) must be excluded: it has no covered
// record in this set, so feeding it to validateSection would leave an orphan signature
// that fails strict verification and SERVFAILs every signed negative answer. The SOA's
// own signature is validated separately against the full authority section.
func collectProofRecords(nsecSection []dns.RR) []dns.RR {
	var out []dns.RR
	for _, rr := range nsecSection {
		switch v := rr.(type) {
		case *dns.NSEC, *dns.NSEC3:
			out = append(out, rr)
		case *dns.RRSIG:
			if v.TypeCovered == dns.TypeNSEC || v.TypeCovered == dns.TypeNSEC3 {
				out = append(out, rr)
			}
		}
	}
	return out
}

func splitProofs(rrs []dns.RR) ([]*dns.NSEC, []*dns.NSEC3) {
	var nsec []*dns.NSEC
	var nsec3 []*dns.NSEC3
	for _, rr := range rrs {
		switch v := rr.(type) {
		case *dns.NSEC:
			nsec = append(nsec, v)
		case *dns.NSEC3:
			nsec3 = append(nsec3, v)
		}
	}
	return nsec, nsec3
}

func verifyNSECCoverage(qname string, qtype uint16, rcode int, nsecs []*dns.NSEC) bool {
	qname = normalizeName(qname)
	// NXDOMAIN (RFC 4035 section 5.4): prove qname does not exist and that no wildcard
	// at the closest encloser could have synthesized an answer. The closest encloser is
	// derived from the NSEC that actually covers qname (the existing names immediately
	// bracketing the non-existence gap), never inferred as the root — so a single
	// covering NSEC plus an apex-wildcard NSEC can no longer "prove" NXDOMAIN for a
	// wildcard-answerable name.
	if rcode == dns.RcodeNameError {
		ce, ok := nsecClosestEncloser(qname, nsecs)
		if !ok || ce == qname {
			return false
		}
		wildcard := normalizeName("*." + ce)
		return nsecCoversName(wildcard, nsecs)
	}
	// NODATA: an NSEC whose owner is EXACTLY qname with the qtype and CNAME bits clear.
	// A covering (non-owner) NSEC proves the name does not exist, which is not a NODATA
	// proof, so it is no longer accepted (RFC 4035 section 4.4.1).
	for _, n := range nsecs {
		if normalizeName(n.Hdr.Name) == qname && !typeInBitmap(n.TypeBitMap, qtype) && !typeInBitmap(n.TypeBitMap, dns.TypeCNAME) {
			return true
		}
	}
	return false
}

// nsec3ParamsUsable gates an NSEC3 set before any hashing (RFC 5155 section 12.1.3,
// RFC 9276): the hash must be SHA-1, the iteration count must not exceed maxIter, and
// every record must share the same hash/iterations/salt. miekg's HashName returns ""
// for an unknown hash, which would make Cover/Match match arbitrary names, and a large
// iteration count is a CPU-exhaustion vector — so this must run before Cover/Match.
func nsec3ParamsUsable(nsec3s []*dns.NSEC3, maxIter uint16) bool {
	if len(nsec3s) == 0 {
		return false
	}
	p := nsec3s[0]
	if p.Hash != dns.SHA1 || p.Iterations > maxIter {
		return false
	}
	for _, n := range nsec3s {
		if n.Hash != p.Hash || n.Iterations != p.Iterations || !strings.EqualFold(n.Salt, p.Salt) {
			return false
		}
	}
	return true
}

func verifyNSEC3Coverage(qname string, qtype uint16, rcode int, nsec3s []*dns.NSEC3, maxIter uint16) bool {
	qname = normalizeName(qname)
	if !nsec3ParamsUsable(nsec3s, maxIter) {
		return false
	}
	params := nsec3s[0]
	if rcode == dns.RcodeNameError {
		// Proof 1: qname does not exist (a covering NSEC3).
		var hasNameProof bool
		for _, n := range nsec3s {
			if n.Cover(qname) {
				hasNameProof = true
				break
			}
		}
		if !hasNameProof {
			return false
		}
		// Proof 2: the wildcard at the closest encloser does not exist.
		closest := closestEncloserNSEC3(qname, nsec3s, params)
		if closest == "" {
			return false
		}
		wildcard := normalizeName("*." + closest)
		for _, n := range nsec3s {
			if n.Cover(wildcard) {
				return true
			}
		}
		return false
	}
	// NODATA: an NSEC3 that MATCHES qname (exact owner-hash) with the qtype and CNAME
	// bits clear. A covering (non-matching) record proves non-existence, not NODATA, so
	// it is no longer accepted (RFC 5155 section 8.5 / RFC 4035 section 4.4.1).
	for _, n := range nsec3s {
		if n.Match(qname) && !typeInBitmap(n.TypeBitMap, qtype) && !typeInBitmap(n.TypeBitMap, dns.TypeCNAME) {
			return true
		}
	}
	return false
}

func nsecCoversName(name string, nsecs []*dns.NSEC) bool {
	for _, n := range nsecs {
		owner := normalizeName(n.Hdr.Name)
		next := normalizeName(n.NextDomain)
		if nsecNameCovered(owner, next, name) {
			return true
		}
	}
	return false
}

// canonicalLess reports whether a sorts strictly before b in DNSSEC canonical name
// order (RFC 4034 section 6.1): labels are compared from the rightmost (TLD) label
// inward, each as a case-insensitive octet string; a shorter name (a proper ancestor)
// sorts first. Plain Go string comparison is not equivalent for multi-label names.
func canonicalLess(a, b string) bool {
	al := dns.SplitDomainName(a)
	bl := dns.SplitDomainName(b)
	i, j := len(al)-1, len(bl)-1
	for i >= 0 && j >= 0 {
		ai := strings.ToLower(al[i])
		bj := strings.ToLower(bl[j])
		if ai != bj {
			return ai < bj
		}
		i--
		j--
	}
	return i < j // the name with fewer remaining labels sorts first
}

// nsecNameCovered reports whether name falls strictly inside the gap an NSEC proves
// to be empty, i.e. owner < name < next in canonical order (with wrap-around for the
// last NSEC). An endpoint (name == owner or name == next) exists and is not covered.
func nsecNameCovered(owner, next, name string) bool {
	if name == owner || name == next {
		return false
	}
	if canonicalLess(owner, next) {
		return canonicalLess(owner, name) && canonicalLess(name, next)
	}
	// Wrap-around: the last NSEC's next is the zone apex (<= owner canonically).
	return canonicalLess(owner, name) || canonicalLess(name, next)
}

// longestCommonAncestor returns the deepest DNS name that is an ancestor (or self) of
// both a and b, comparing labels from the right (RFC 4034 section 6.1).
func longestCommonAncestor(a, b string) string {
	al := dns.SplitDomainName(a)
	bl := dns.SplitDomainName(b)
	i, j := len(al)-1, len(bl)-1
	var common []string
	for i >= 0 && j >= 0 && strings.EqualFold(al[i], bl[j]) {
		common = append([]string{al[i]}, common...)
		i--
		j--
	}
	if len(common) == 0 {
		return "."
	}
	return normalizeName(strings.Join(common, "."))
}

// nsecClosestEncloser returns the closest encloser of qname proven by the NSEC chain.
// It requires an NSEC covering qname (proving qname does not exist) and derives the
// closest encloser as the deepest ancestor of qname that the covering NSEC shows to
// exist — the longer of the common ancestors of qname with the covering NSEC's owner
// and next names (RFC 4035 section 5.4).
func nsecClosestEncloser(qname string, nsecs []*dns.NSEC) (string, bool) {
	for _, n := range nsecs {
		owner := normalizeName(n.Hdr.Name)
		next := normalizeName(n.NextDomain)
		if !nsecNameCovered(owner, next, qname) {
			continue
		}
		a := longestCommonAncestor(qname, owner)
		b := longestCommonAncestor(qname, next)
		if dns.CountLabel(b) > dns.CountLabel(a) {
			return b, true
		}
		return a, true
	}
	return "", false
}

func closestEncloserNSEC3(qname string, nsec3s []*dns.NSEC3, params *dns.NSEC3) string {
	labels := dns.SplitDomainName(qname)
	for i := 0; i < len(labels); i++ {
		candidate := normalizeName(strings.Join(labels[i:], "."))
		for _, n := range nsec3s {
			if n.Hash == params.Hash && n.Iterations == params.Iterations && n.Salt == params.Salt && n.Match(candidate) {
				return candidate
			}
		}
	}
	return ""
}

// proveNoDS reports whether dsMsg authentically proves that zone has no DS RRset,
// using NSEC/NSEC3 records signed by the parent (parentKeys). A secure parent must
// supply this proof before a child may be treated as an insecure (unsigned)
// delegation; without it, stripping the DS RRset would downgrade a secure child
// (RFC 4035 section 5.2, RFC 6840 section 5).
func (v *dnssecValidator) proveNoDS(zone string, dsMsg *dns.Msg, parentKeys []*dns.DNSKEY) bool {
	if dsMsg == nil {
		return false
	}
	nsecs, nsec3s := validatedDenialRecords(dsMsg.Ns, parentKeys)
	if nsecProvesNoDS(zone, nsecs) {
		return true
	}
	return nsec3ProvesNoDS(zone, nsec3s, v.nsec3MaxIter)
}

// validatedDenialRecords returns the NSEC and NSEC3 records from section whose RRSIGs
// verify against keys (signer in bailiwick). Unsigned or unverifiable records are
// dropped so that only parent-authenticated proofs are considered.
func validatedDenialRecords(section []dns.RR, keys []*dns.DNSKEY) ([]*dns.NSEC, []*dns.NSEC3) {
	var nsecs []*dns.NSEC
	var nsec3s []*dns.NSEC3
	for _, set := range groupRRsets(section) {
		if len(set.rrs) == 0 {
			continue
		}
		switch set.rrs[0].(type) {
		case *dns.NSEC, *dns.NSEC3:
		default:
			continue
		}
		if ok, _ := verifyRRSetWithKeys(set.rrs, set.sigs, keys, true); !ok {
			continue
		}
		for _, rr := range set.rrs {
			switch r := rr.(type) {
			case *dns.NSEC:
				nsecs = append(nsecs, r)
			case *dns.NSEC3:
				nsec3s = append(nsec3s, r)
			}
		}
	}
	return nsecs, nsec3s
}

// nsecProvesNoDS reports whether an NSEC owned by zone proves there is no DS RRset:
// the DS bit must be clear, the SOA bit must be clear (so the child zone's own apex
// NSEC cannot be replayed as a parent-side no-DS proof, RFC 6840 section 4.3), and the
// NS bit must be set (the owner is a delegation point). Matches Unbound's
// val_nsec_proves_no_ds semantics.
func nsecProvesNoDS(zone string, nsecs []*dns.NSEC) bool {
	zone = normalizeName(zone)
	for _, n := range nsecs {
		if normalizeName(n.Hdr.Name) != zone {
			continue
		}
		if typeInBitmap(n.TypeBitMap, dns.TypeDS) || typeInBitmap(n.TypeBitMap, dns.TypeSOA) {
			continue
		}
		if !typeInBitmap(n.TypeBitMap, dns.TypeNS) {
			continue
		}
		return true
	}
	return false
}

// nsec3ProvesNoDS reports whether an NSEC3 set proves there is no DS RRset at zone,
// either directly (an NSEC3 matching zone with NS set, SOA and DS clear) or via an
// opt-out span (a matching NSEC3 for the closest encloser and an opt-out NSEC3 covering
// the next closer name, RFC 5155 section 6 / section 7.2.4).
func nsec3ProvesNoDS(zone string, nsec3s []*dns.NSEC3, maxIter uint16) bool {
	if len(nsec3s) == 0 || !nsec3ParamsUsable(nsec3s, maxIter) {
		return false
	}
	zone = normalizeName(zone)
	params := nsec3s[0]
	// Direct NODATA: an NSEC3 matching zone, DS and SOA clear, NS set.
	for _, n := range nsec3s {
		if !n.Match(zone) {
			continue
		}
		if typeInBitmap(n.TypeBitMap, dns.TypeDS) || typeInBitmap(n.TypeBitMap, dns.TypeSOA) {
			return false
		}
		return typeInBitmap(n.TypeBitMap, dns.TypeNS)
	}
	// Opt-out: the closest encloser exists and the next closer name is covered by an
	// NSEC3 whose opt-out flag is set.
	ce := closestEncloserNSEC3(zone, nsec3s, params)
	if ce == "" || ce == zone {
		return false
	}
	nextCloser := nextCloserName(zone, ce)
	if nextCloser == "" {
		return false
	}
	for _, n := range nsec3s {
		if n.Cover(nextCloser) && n.Flags&0x01 == 1 {
			return true
		}
	}
	return false
}

// nextCloserName returns the name one label longer than ce on the path from ce to
// qname (the "next closer name", RFC 5155 section 1.3). It returns "" if ce is not a
// proper ancestor of qname.
func nextCloserName(qname, ce string) string {
	qLabels := dns.SplitDomainName(normalizeName(qname))
	ceLabels := dns.SplitDomainName(normalizeName(ce))
	if len(ceLabels) >= len(qLabels) {
		return ""
	}
	idx := len(qLabels) - len(ceLabels) - 1
	return normalizeName(strings.Join(qLabels[idx:], "."))
}

func typeInBitmap(types []uint16, qtype uint16) bool {
	for _, t := range types {
		if t == qtype {
			return true
		}
	}
	return false
}

func fallbackExpiry(now time.Time) time.Time {
	return now.Add(10 * time.Minute)
}

func keysForAnchors(anchors []dns.RR) []*dns.DNSKEY {
	var out []*dns.DNSKEY
	for _, rr := range anchors {
		if k, ok := rr.(*dns.DNSKEY); ok {
			out = append(out, k)
		}
	}
	return out
}

func toDNSKEYs(rrs []dns.RR) []*dns.DNSKEY {
	var out []*dns.DNSKEY
	for _, rr := range rrs {
		if k, ok := rr.(*dns.DNSKEY); ok {
			out = append(out, k)
		}
	}
	return out
}

func (v *dnssecValidator) findTrustForName(name string) *keyState {
	zone := normalizeName(name)
	if zone != "." {
		zone = parentZone(zone)
	}
	for {
		st, err := v.trustedKeys(zone)
		if err == nil && st != nil {
			return st
		}
		if zone == "." {
			return st
		}
		zone = parentZone(zone)
	}
}
