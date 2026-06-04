package recursive

import (
	"errors"

	"github.com/miekg/dns"
	"github.com/zhouchenh/secDNS/internal/logger"
)

// DNSSEC validation policies. The shipped default is permissive; documentation
// recommends strict.
const (
	policyOff        = "off"
	policyPermissive = "permissive"
	policyStrict     = "strict"
)

// secStatus is the DNSSEC security status of an answer (RFC 4033 section 5).
type secStatus uint8

const (
	statusIndeterminate secStatus = iota // no trust anchor reaches this name
	statusInsecure                       // proven unsigned (authenticated DS absence) or unsupported-algorithm only
	statusSecure                         // the answering RRset chains to a trust anchor and verifies
	statusBogus                          // signatures or proofs are present but failed; the chain is broken
)

func (s secStatus) String() string {
	switch s {
	case statusInsecure:
		return "insecure"
	case statusSecure:
		return "secure"
	case statusBogus:
		return "bogus"
	default:
		return "indeterminate"
	}
}

// validationResult is the per-waiter outcome applied to a response: whether to set
// the AD bit and whether to replace the answer with SERVFAIL.
type validationResult struct {
	status   secStatus
	setAD    bool
	servfail bool
}

// signerInBailiwick reports whether an RRSIG's signer is the zone apex at or above
// the owner name it signs (RFC 4035 section 5.3.1). miekg/dns RRSIG.Verify checks
// that SignerName equals the key's owner and the cryptography, but NOT that the
// signer is in bailiwick of the RR owner; without that ancestry check the holder of
// any DNSSEC-signed zone could produce a cryptographically valid signature over a
// forged RRset for an unrelated name (claiming their own zone as the signer).
//
// This is the primitive that the per-RRset verify path uses to reject such
// cross-zone signers; it becomes an enforced precondition once chain validation is
// wired in (the follow-up PR). It does not, on its own, change the current
// classification.
func signerInBailiwick(sig *dns.RRSIG, ownerFQDN string) bool {
	if sig == nil {
		return false
	}
	return dns.IsSubDomain(dns.CanonicalName(sig.SignerName), dns.CanonicalName(ownerFQDN))
}

// applyPolicy is the single chokepoint that turns a DNSSEC security status into the
// per-waiter (AD, SERVFAIL) decision, given the validation policy and the client's
// CD/DO/AD request bits. It is a pure function; the normative decision table is in
// the DNSSEC design (section 2.5).
//
// AD is asserted only when the answer is Secure, the client requested DNSSEC (the DO
// or AD bit was set, RFC 6840 section 5.8), CD is not set, the policy validates, and
// the whole Answer+Authority section is authentic (RFC 4035 section 3.2.3, the
// `authentic` argument). Insecure is never SERVFAIL; strict SERVFAILs only on Bogus.
func applyPolicy(status secStatus, policy string, clientCD, clientDO, clientAD, honorCD, authentic bool) validationResult {
	if clientCD && honorCD {
		// RFC 4035 section 3.2.2 / RFC 6840 section 5.9: a CD=1 query must not be
		// validation-rejected, and AD must never be asserted when validation was
		// bypassed (RFC 6840 section 5.8).
		return validationResult{status: status}
	}
	adEligible := status == statusSecure && (clientDO || clientAD) && authentic
	switch policy {
	case policyOff:
		return validationResult{status: status}
	case policyPermissive:
		return validationResult{status: status, setAD: adEligible}
	case policyStrict:
		return validationResult{status: status, setAD: adEligible, servfail: status == statusBogus}
	default:
		// Unknown policy: fail closed.
		return validationResult{status: statusBogus, servfail: true}
	}
}

// validatedMsg carries a resolved answer together with its policy-independent DNSSEC
// security status across the singleflight boundary, so the (AD, SERVFAIL) decision
// can be stamped per waiter — with that waiter's own CD/DO/AD bits — instead of on
// the shared object.
type validatedMsg struct {
	msg       *dns.Msg
	status    secStatus
	authentic bool
}

// dnssecOK reports whether the query set the EDNS0 DO (DNSSEC OK) bit.
func dnssecOK(msg *dns.Msg) bool {
	if opt := msg.IsEdns0(); opt != nil {
		return opt.Do()
	}
	return false
}

// classifyTerminal computes the policy-independent DNSSEC security status of a
// resolved terminal answer plus its AD-eligibility (whole-message authenticity).
//
// This is a bridge over the existing validator: it maps the current
// (validated, error) verdict into the tri-state. The full per-RRset chain and
// denial-of-existence classification replaces these internals in later PRs; here it
// already lets applyPolicy enforce the correct gating (Insecure serves in strict,
// AD requires DO/AD + CD=0, strict SERVFAILs only Bogus).
func (r *Recursive) classifyTerminal(msg *dns.Msg, q dns.Question) (secStatus, bool) {
	switch r.ValidateDNSSEC {
	case policyPermissive, policyStrict:
	default:
		return statusIndeterminate, false // "off" or unknown: no validation, never AD
	}
	validated, err := r.validator.validateResponse(msg, q, policyStrict, true)
	switch {
	case err != nil:
		// "No usable signatures" is ambiguous (legitimately unsigned vs a stripped
		// signature); treat it as Insecure until the authenticated DS-absence proof
		// lands, so strict no longer SERVFAILs unsigned zones (LAB C-01). A broken
		// chain or a failed signature verification is genuine Bogus.
		if errors.Is(err, errDNSSECMissingSig) {
			return statusInsecure, false
		}
		// A broken chain or failed signature is genuine Bogus. Under strict this
		// becomes SERVFAIL (applyPolicy) with no other operator-visible cause, so
		// surface the discarded reason at Debug — gated behind --log-level debug, it
		// does not flood the default (warning) level but makes the SERVFAIL
		// diagnosable when an operator goes looking.
		logger.Debug().
			Str("qname", q.Name).
			Str("qtype", dns.TypeToString[q.Qtype]).
			Str("reason", err.Error()).
			Msg("dnssec: answer classified bogus")
		return statusBogus, false
	case validated:
		return statusSecure, true
	default:
		return statusInsecure, false
	}
}
