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
		logger:   func(string) {},
		keyCache: map[string]*keyState{},
		metrics:  &validationMetrics{},
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
		covered = verifyNSEC3Coverage(qname, qtype, msg.Rcode, nsec3Records)
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
		keys := keysForAnchors(v.trustAnchors)
		expire := v.now().Add(48 * time.Hour)
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

	dnskeyMsg, err := v.resolveDNSKEY(zone)
	if err != nil {
		return nil, err
	}
	dnskeyRRs, dnskeySigs := extractRRSet(dnskeyMsg, dns.TypeDNSKEY, zone)
	dnskeys := toDNSKEYs(dnskeyRRs)
	if len(dnskeys) == 0 {
		return nil, errDNSSECNoKeys
	}
	if _, err := verifyRRSetWithKeys(dnskeyRRs, dnskeySigs, dnskeys, false); err != nil {
		return nil, err
	}
	if !dsMatchesDNSKEY(dsSet, dnskeys) {
		return nil, fmt.Errorf("dnssec: ds mismatch for %s", zone)
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

func dsMatchesDNSKEY(dsSet []dns.RR, keys []*dns.DNSKEY) bool {
	for _, dsRR := range dsSet {
		ds, ok := dsRR.(*dns.DS)
		if !ok {
			continue
		}
		for _, k := range keys {
			if ds.KeyTag != k.KeyTag() || ds.Algorithm != k.Algorithm {
				continue
			}
			if generated := k.ToDS(ds.DigestType); generated != nil && strings.EqualFold(generated.Digest, ds.Digest) {
				return true
			}
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

func collectProofRecords(nsecSection []dns.RR) []dns.RR {
	var out []dns.RR
	for _, rr := range nsecSection {
		switch rr.(type) {
		case *dns.NSEC, *dns.NSEC3, *dns.RRSIG:
			out = append(out, rr)
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
	// NXDOMAIN: need proof that name doesn't exist and that wildcard closest encloser doesn't exist.
	if rcode == dns.RcodeNameError {
		if !nsecCoversName(qname, nsecs) {
			return false
		}
		closest := closestEncloser(qname, nsecs)
		wildcard := normalizeName("*." + closest)
		return nsecCoversName(wildcard, nsecs)
	}
	// NODATA: need proof that the name exists but the type does not.
	for _, n := range nsecs {
		owner := normalizeName(n.Hdr.Name)
		if owner == qname && !typeInBitmap(n.TypeBitMap, qtype) {
			return true
		}
		if covers := nsecNameCovered(owner, normalizeName(n.NextDomain), qname); covers && !typeInBitmap(n.TypeBitMap, qtype) {
			return true
		}
	}
	return false
}

func verifyNSEC3Coverage(qname string, qtype uint16, rcode int, nsec3s []*dns.NSEC3) bool {
	qname = normalizeName(qname)
	// Choose parameter set from first record.
	params := nsec3s[0]
	if rcode == dns.RcodeNameError {
		// Proof 1: qname does not exist.
		var hasNameProof bool
		for _, n := range nsec3s {
			if n.Hash == params.Hash && n.Iterations == params.Iterations && n.Salt == params.Salt && n.Cover(qname) {
				hasNameProof = true
				break
			}
		}
		if !hasNameProof {
			return false
		}
		// Proof 2: wildcard does not exist for closest encloser.
		closest := closestEncloserNSEC3(qname, nsec3s, params)
		if closest == "" {
			return false
		}
		wildcard := normalizeName("*." + closest)
		for _, n := range nsec3s {
			if n.Hash == params.Hash && n.Iterations == params.Iterations && n.Salt == params.Salt && n.Cover(wildcard) {
				return true
			}
		}
		return false
	}
	// NODATA: qname exists but type missing -> either matched hash lacking type or covered by other interval.
	for _, n := range nsec3s {
		if n.Match(qname) && !typeInBitmap(n.TypeBitMap, qtype) {
			return true
		}
		if n.Cover(qname) {
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

func nsecNameCovered(owner, next, name string) bool {
	if owner == name {
		return true
	}
	if owner < next {
		return owner < name && name < next
	}
	// Wrap-around interval.
	return owner < name || name < next
}

func closestEncloser(qname string, nsecs []*dns.NSEC) string {
	labels := dns.SplitDomainName(qname)
	for i := 0; i < len(labels); i++ {
		candidate := normalizeName(strings.Join(labels[i:], "."))
		for _, n := range nsecs {
			if normalizeName(n.Hdr.Name) == candidate {
				return candidate
			}
		}
	}
	return "."
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
