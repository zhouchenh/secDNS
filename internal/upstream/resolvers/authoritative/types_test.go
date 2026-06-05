package authoritative

import (
	"errors"
	"testing"

	"github.com/miekg/dns"
	"github.com/zhouchenh/secDNS/internal/recordstore"
	resolverpkg "github.com/zhouchenh/secDNS/pkg/upstream/resolver"
)

func newResolver(t *testing.T, storeName string) (*Authoritative, *recordstore.Store) {
	t.Helper()
	a := &Authoritative{Store: storeName}
	return a, recordstore.GetOrCreate(storeName)
}

func query(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	return m
}

func TestResolveTXTHit(t *testing.T) {
	a, store := newResolver(t, "auth-txt")
	store.Set(recordstore.Record{Name: "_acme-challenge.example.com.", Type: dns.TypeTXT, Values: []string{"token-value"}, TTL: 60})

	resp, err := a.Resolve(query("_acme-challenge.example.com", dns.TypeTXT), 4)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !resp.Authoritative {
		t.Fatalf("authoritative bit must be set")
	}
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("expected one answer, got rcode=%d answers=%d", resp.Rcode, len(resp.Answer))
	}
	txt, ok := resp.Answer[0].(*dns.TXT)
	if !ok || len(txt.Txt) != 1 || txt.Txt[0] != "token-value" {
		t.Fatalf("unexpected TXT answer: %+v", resp.Answer[0])
	}
}

func TestResolveAMultiValue(t *testing.T) {
	a, store := newResolver(t, "auth-a")
	store.Set(recordstore.Record{Name: "host.example.", Type: dns.TypeA, Values: []string{"1.2.3.4", "5.6.7.8", "not-an-ip"}, TTL: 30})

	resp, err := a.Resolve(query("host.example", dns.TypeA), 4)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// The two valid IPs are served; the malformed value is skipped.
	if len(resp.Answer) != 2 {
		t.Fatalf("expected 2 A answers (malformed skipped), got %d", len(resp.Answer))
	}
	if a0, ok := resp.Answer[0].(*dns.A); !ok || a0.Hdr.Ttl != 30 {
		t.Fatalf("unexpected A answer: %+v", resp.Answer[0])
	}
}

func TestResolveNXDOMAIN(t *testing.T) {
	a, _ := newResolver(t, "auth-nx")
	resp, err := a.Resolve(query("absent.example", dns.TypeA), 4)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN, got rcode=%d", resp.Rcode)
	}
	if len(resp.Answer) != 0 {
		t.Fatalf("NXDOMAIN must have no answers")
	}
	if len(resp.Ns) != 1 {
		t.Fatalf("expected a SOA in the authority section, got %d records", len(resp.Ns))
	}
	soa, ok := resp.Ns[0].(*dns.SOA)
	if !ok || soa.Minttl != 60 {
		t.Fatalf("unexpected SOA: %+v", resp.Ns[0])
	}
}

func TestResolveNODATA(t *testing.T) {
	a, store := newResolver(t, "auth-nodata")
	store.Set(recordstore.Record{Name: "host.example.", Type: dns.TypeA, Values: []string{"1.2.3.4"}, TTL: 60})

	// Name exists (A) but AAAA is queried -> NODATA: NOERROR, no answer, SOA present.
	resp, err := a.Resolve(query("host.example", dns.TypeAAAA), 4)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("NODATA must be NOERROR, got rcode=%d", resp.Rcode)
	}
	if len(resp.Answer) != 0 || len(resp.Ns) != 1 {
		t.Fatalf("NODATA must have no answer and a SOA, got answer=%d ns=%d", len(resp.Answer), len(resp.Ns))
	}
}

func TestResolveCNAMEForOtherType(t *testing.T) {
	a, store := newResolver(t, "auth-cname")
	store.Set(recordstore.Record{Name: "alias.example.", Type: dns.TypeCNAME, Values: []string{"target.example.com"}, TTL: 60})

	// An A query for a name that only has a CNAME returns the CNAME.
	resp, err := a.Resolve(query("alias.example", dns.TypeA), 4)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected the CNAME to be returned, got %d answers", len(resp.Answer))
	}
	cname, ok := resp.Answer[0].(*dns.CNAME)
	if !ok || cname.Target != "target.example.com." {
		t.Fatalf("unexpected CNAME answer: %+v", resp.Answer[0])
	}
}

func TestResolveDepthLimit(t *testing.T) {
	a, _ := newResolver(t, "auth-depth")
	if _, err := a.Resolve(query("x.example", dns.TypeA), -1); !errors.Is(err, resolverpkg.ErrLoopDetected) {
		t.Fatalf("expected ErrLoopDetected at negative depth, got %v", err)
	}
}

func TestDescriptorParsesConfig(t *testing.T) {
	describable, ok := resolverpkg.GetResolverDescriptorByTypeName("authoritative")
	if !ok {
		t.Fatalf("authoritative resolver not registered")
	}
	obj, s, f := describable.Describe(map[string]interface{}{"store": "zone1", "negativeTTL": float64(120)})
	if s < 1 || f > 0 {
		t.Fatalf("describe failed: s=%d f=%d", s, f)
	}
	a := obj.(*Authoritative)
	if a.Store != "zone1" || a.NegativeTTL != 120 {
		t.Fatalf("unexpected parsed config: %+v", a)
	}

	// Empty config uses the defaults.
	obj2, s2, f2 := describable.Describe(map[string]interface{}{})
	if s2 < 1 || f2 > 0 {
		t.Fatalf("describe of empty config failed: s=%d f=%d", s2, f2)
	}
	if d := obj2.(*Authoritative); d.Store != "" || d.NegativeTTL != 60 {
		t.Fatalf("unexpected defaults: %+v", d)
	}
}
