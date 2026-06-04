package recursive

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/zhouchenh/secDNS/internal/logger"
)

func TestApplyPolicyDecisionTable(t *testing.T) {
	// honorCD is true for every row except where noted; the CD=1 short-circuit is
	// exercised separately below.
	const honor = true
	cases := []struct {
		name                          string
		status                        secStatus
		policy                        string
		cd, do, ad, honorCD, authentic bool
		wantAD, wantServfail          bool
	}{
		// Secure + DNSSEC-aware client (DO) + authentic -> AD on validating policies.
		{"secure permissive DO authentic", statusSecure, policyPermissive, false, true, false, honor, true, true, false},
		{"secure strict DO authentic", statusSecure, policyStrict, false, true, false, honor, true, true, false},
		{"secure strict AD-bit authentic", statusSecure, policyStrict, false, false, true, honor, true, true, false},
		// Secure but client did not ask for DNSSEC (plain stub) -> no AD (RFC 6840 5.8).
		{"secure permissive plain query", statusSecure, policyPermissive, false, false, false, honor, true, false, false},
		// Secure but not whole-section authentic -> no AD (RFC 4035 3.2.3).
		{"secure DO not authentic", statusSecure, policyStrict, false, true, false, honor, false, false, false},
		// off never asserts AD even when Secure+DO+authentic.
		{"secure off", statusSecure, policyOff, false, true, false, honor, true, false, false},
		// Insecure is never AD and never SERVFAIL (the LAB C-01 fix in strict).
		{"insecure strict DO", statusInsecure, policyStrict, false, true, false, honor, true, false, false},
		{"insecure permissive DO", statusInsecure, policyPermissive, false, true, false, honor, true, false, false},
		// Bogus: SERVFAIL only in strict (CD=0); served (no AD) in permissive/off.
		{"bogus strict", statusBogus, policyStrict, false, true, false, honor, false, false, true},
		{"bogus permissive", statusBogus, policyPermissive, false, true, false, honor, false, false, false},
		{"bogus off", statusBogus, policyOff, false, true, false, honor, false, false, false},
		// Indeterminate behaves like Insecure: serve, no AD, no SERVFAIL.
		{"indeterminate strict", statusIndeterminate, policyStrict, false, true, false, honor, true, false, false},
		// CD=1 (honored): serve as received, never AD, never SERVFAIL, any status/policy.
		{"cd1 bogus strict honored", statusBogus, policyStrict, true, true, false, true, false, false, false},
		{"cd1 secure strict honored", statusSecure, policyStrict, true, true, false, true, true, false, false},
		// CD=1 NOT honored (forced-validation deviation): validation applies.
		{"cd1 bogus strict not honored", statusBogus, policyStrict, true, true, false, false, false, false, true},
		// Unknown policy fails closed.
		{"unknown policy", statusSecure, "weird", false, true, false, honor, false, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := applyPolicy(c.status, c.policy, c.cd, c.do, c.ad, c.honorCD, c.authentic)
			if got.setAD != c.wantAD {
				t.Errorf("setAD = %v, want %v", got.setAD, c.wantAD)
			}
			if got.servfail != c.wantServfail {
				t.Errorf("servfail = %v, want %v", got.servfail, c.wantServfail)
			}
		})
	}
}

// TestApplyPolicyInvariants asserts the sign-off contract holds across the whole
// input space: AD only when Secure+CD=0+(DO|AD)+authentic on a validating policy,
// Insecure never SERVFAILs, strict SERVFAILs only Bogus(CD=0).
func TestApplyPolicyInvariants(t *testing.T) {
	statuses := []secStatus{statusIndeterminate, statusInsecure, statusSecure, statusBogus}
	policies := []string{policyOff, policyPermissive, policyStrict}
	bools := []bool{false, true}
	for _, st := range statuses {
		for _, p := range policies {
			for _, cd := range bools {
				for _, do := range bools {
					for _, ad := range bools {
						for _, auth := range bools {
							r := applyPolicy(st, p, cd, do, ad, true, auth)
							if r.setAD {
								if st != statusSecure || cd || !(do || ad) || !auth || p == policyOff {
									t.Fatalf("AD set wrongly for status=%v policy=%s cd=%v do=%v ad=%v auth=%v", st, p, cd, do, ad, auth)
								}
							}
							if r.servfail {
								if p != policyStrict || st != statusBogus || cd {
									t.Fatalf("SERVFAIL set wrongly for status=%v policy=%s cd=%v", st, p, cd)
								}
							}
							if st == statusInsecure && r.servfail {
								t.Fatalf("Insecure must never SERVFAIL (policy=%s)", p)
							}
						}
					}
				}
			}
		}
	}
}

// withDebugLogger redirects the package logger to a buffer at Debug level for the
// duration of the test and restores the prior output/level afterwards.
func withDebugLogger(t *testing.T) *bytes.Buffer {
	t.Helper()
	prevOut := logger.Output()
	prevLevel := logger.LogLevel()
	buf := new(bytes.Buffer)
	logger.SetOutput(buf)
	logger.SetLogLevel(logger.DebugLevel)
	t.Cleanup(func() {
		logger.SetOutput(prevOut)
		logger.SetLogLevel(prevLevel)
	})
	return buf
}

// TestClassifyTerminalLogsBogusReason verifies that a genuine Bogus classification
// (here: an expired RRSIG, a non-missing-sig failure) surfaces the discarded reason
// at Debug with the qname/qtype, so a strict-mode SERVFAIL is diagnosable.
func TestClassifyTerminalLogsBogusReason(t *testing.T) {
	buf := withDebugLogger(t)

	r := &Recursive{ValidateDNSSEC: policyStrict, validator: newValidator()}
	fixedNow := time.Unix(2_000_000_000, 0) // pin "now" so the RRSIG below is unambiguously expired
	r.validator.now = func() time.Time { return fixedNow }

	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	msg := new(dns.Msg)
	msg.SetQuestion(q.Name, q.Qtype)
	msg.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(1, 2, 3, 4)},
		&dns.RRSIG{
			Hdr:         dns.RR_Header{Name: q.Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 60},
			TypeCovered: dns.TypeA,
			Inception:   1_000_000_000,
			Expiration:  1_500_000_000, // before fixedNow -> expired -> bogus, not missing-sig
			SignerName:  q.Name,
		},
	}

	status, authentic := r.classifyTerminal(msg, q)
	if status != statusBogus {
		t.Fatalf("status = %v, want bogus", status)
	}
	if authentic {
		t.Fatalf("a bogus answer must not be reported authentic")
	}
	out := buf.String()
	for _, want := range []string{"answer classified bogus", "example.com.", "A", "expired"} {
		if !strings.Contains(out, want) {
			t.Fatalf("diagnostic missing %q; got %q", want, out)
		}
	}
}

// TestClassifyTerminalInsecureDoesNotLog verifies the diagnostic is reserved for
// genuine Bogus: a missing-signature answer classifies Insecure (served in strict)
// and must not emit the bogus diagnostic.
func TestClassifyTerminalInsecureDoesNotLog(t *testing.T) {
	buf := withDebugLogger(t)

	r := &Recursive{ValidateDNSSEC: policyStrict, validator: newValidator()}
	q := dns.Question{Name: "unsigned.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	msg := new(dns.Msg)
	msg.SetQuestion(q.Name, q.Qtype)
	msg.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(1, 2, 3, 4)},
	}

	status, _ := r.classifyTerminal(msg, q)
	if status != statusInsecure {
		t.Fatalf("status = %v, want insecure", status)
	}
	if strings.Contains(buf.String(), "answer classified bogus") {
		t.Fatalf("missing-sig (insecure) must not log a bogus diagnostic; got %q", buf.String())
	}
}

func TestSignerInBailiwick(t *testing.T) {
	sig := func(signer string) *dns.RRSIG {
		return &dns.RRSIG{Hdr: dns.RR_Header{Rrtype: dns.TypeRRSIG}, SignerName: signer}
	}
	cases := []struct {
		signer, owner string
		want          bool
	}{
		{"example.com.", "www.example.com.", true},   // ancestor
		{"example.com.", "example.com.", true},        // apex == owner
		{".", "example.com.", true},                   // root signs anything
		{"EXAMPLE.com.", "www.example.com.", true},    // case-insensitive
		{"evil.example.", "victim.bank.", false},      // unrelated zone (the forgery case)
		{"www.example.com.", "example.com.", false},   // signer below owner
		{"notexample.com.", "example.com.", false},    // sibling-ish, not an ancestor
	}
	for _, c := range cases {
		if got := signerInBailiwick(sig(c.signer), c.owner); got != c.want {
			t.Errorf("signerInBailiwick(%q signs %q) = %v, want %v", c.signer, c.owner, got, c.want)
		}
	}
	if signerInBailiwick(nil, "example.com.") {
		t.Errorf("nil signature must not be in bailiwick")
	}
}
