package diagnostics

import (
	"github.com/miekg/dns"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCorrelationPrivacyAndIdentity(t *testing.T) {
	t.Setenv("SECDNS_QUERY_TRACE_UNTIL", strconv.FormatInt(time.Now().Add(time.Minute).Unix(), 10))
	q := new(dns.Msg)
	q.SetQuestion("secdnshealth0123456789abcdef01234567.1-1-1-1.sslip.io.", dns.TypeAAAA)
	t.Setenv("SECDNS_QUERY_TRACE_SALT", "")
	if CorrelationToken(q) != "" {
		t.Fatal("enabled without salt")
	}
	t.Setenv("SECDNS_QUERY_TRACE_SALT", strings.Repeat("ab", 32))
	a := CorrelationToken(q)
	if len(a) != 64 || strings.Contains(a, "synthetic") {
		t.Fatal("invalid digest")
	}
	if CorrelationToken(q.Copy()) != a {
		t.Fatal("copy mismatch")
	}
	q.Question[0].Name = "secdnshealth1123456789abcdef01234567.1-1-1-1.sslip.io."
	if CorrelationToken(q) == a {
		t.Fatal("nonce collision")
	}
	q.Question[0].Name = "secdnshealth0123456789abcdef01234567.1-1-1-1.sslip.io."
	q.Id++
	if CorrelationToken(q) == a {
		t.Fatal("id collision")
	}
	t.Setenv("SECDNS_QUERY_TRACE_SALT", strings.Repeat("cd", 32))
	if CorrelationToken(q) == a {
		t.Fatal("salt collision")
	}
	t.Setenv("SECDNS_QUERY_TRACE_UNTIL", "0")
	if CorrelationToken(q) != "" {
		t.Fatal("expired trace")
	}
}

func TestCorrelationCanonicalAndScope(t *testing.T) {
	t.Setenv("SECDNS_QUERY_TRACE_SALT", strings.Repeat("ab", 32))
	t.Setenv("SECDNS_QUERY_TRACE_UNTIL", strconv.FormatInt(time.Now().Add(time.Minute).Unix(), 10))
	q := new(dns.Msg)
	q.SetQuestion("secdnshealth0123456789abcdef01234567.1-1-1-1.sslip.io.", dns.TypeAAAA)
	a := CorrelationToken(q)
	q.Question[0].Name = strings.ToUpper(strings.TrimSuffix(q.Question[0].Name, "."))
	if a == "" || CorrelationToken(q) != a {
		t.Fatal("canonical mismatch")
	}
	q.Question[0].Qtype = dns.TypeA
	if CorrelationToken(q) == a {
		t.Fatal("type collision")
	}
	q.Question[0].Qtype = dns.TypeAAAA
	q.Question[0].Qclass = dns.ClassCHAOS
	if CorrelationToken(q) == a {
		t.Fatal("class collision")
	}
	q.Question[0].Name = "ordinary.example."
	if CorrelationToken(q) != "" {
		t.Fatal("ordinary query captured")
	}
	q.Question[0].Name = "secdnshealth0123456789abcdef01234567.1-1-1-1.sslip.io."
	t.Setenv("SECDNS_QUERY_TRACE_UNTIL", strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10))
	if CorrelationToken(q) != "" {
		t.Fatal("unbounded expiry")
	}
}
