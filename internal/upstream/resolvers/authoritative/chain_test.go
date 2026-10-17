package authoritative

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/core"
	"github.com/zhouchenh/secDNS/internal/recordstore"
	"github.com/zhouchenh/secDNS/internal/rules/providers/collection"
	"github.com/zhouchenh/secDNS/internal/rules/providers/collection/rule"
	resolverpkg "github.com/zhouchenh/secDNS/pkg/upstream/resolver"
	"sync"
	"testing"
	"time"
)

func chainResolver(t *testing.T) (*Authoritative, *recordstore.Store) {
	a, s := newResolver(t, t.Name())
	a.CompleteCNAME = true
	return a, s
}
func set(s *recordstore.Store, n string, typ uint16, ttl uint32, v ...string) {
	s.Set(recordstore.Record{Name: n, Type: typ, TTL: ttl, Values: v})
}
func assertFailure(t *testing.T, a *Authoritative, n string, depth int) {
	t.Helper()
	m, e := a.Resolve(query(n, dns.TypeA), depth)
	if e != nil || m == nil || m.Rcode != dns.RcodeServerFailure || len(m.Answer) != 0 || len(m.Ns) != 0 || m.Authoritative {
		t.Fatalf("expected contained SERVFAIL: msg=%v error=%v", m, e)
	}
}
func TestCompleteChainTTLsTypesAndDefault(t *testing.T) {
	a, s := chainResolver(t)
	set(s, "ALIAS.example.", dns.TypeCNAME, 300, "Mid.Example.")
	set(s, "mid.example.", dns.TypeCNAME, 600, "target.example.")
	set(s, "target.example.", dns.TypeA, 86400, "192.0.2.1")
	set(s, "target.example.", dns.TypeAAAA, 700, "2001:db8::1")
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
		m, e := a.Resolve(query("Alias.Example.", qt), 2)
		if e != nil || m.Rcode != 0 || len(m.Answer) != 3 || !m.Authoritative {
			t.Fatal("chain failure")
		}
		if m.Answer[0].Header().Name != "Alias.Example." || m.Answer[1].Header().Name != "Mid.Example." || m.Answer[2].Header().Name != "target.example." {
			t.Fatal("owner lost")
		}
		last := uint32(86400)
		if qt == dns.TypeAAAA {
			last = 700
		}
		for j, ttl := range []uint32{300, 600, last} {
			if m.Answer[j].Header().Ttl != ttl {
				t.Fatal("TTL changed")
			}
		}
	}
	for _, qt := range []uint16{dns.TypeCNAME, dns.TypeTXT, dns.TypeANY} {
		m, e := a.Resolve(query("alias.example.", qt), 2)
		if e != nil || len(m.Answer) != 1 {
			t.Fatal("non-address query changed")
		}
	}
	a.CompleteCNAME = false
	m, e := a.Resolve(query("alias.example.", dns.TypeA), 2)
	if e != nil || len(m.Answer) != 1 {
		t.Fatal("default behavior changed")
	}
}
func TestChainMissingTargetsAndFamilies(t *testing.T) {
	for _, present := range []bool{false, true} {
		t.Run(fmt.Sprint(present), func(t *testing.T) {
			a, s := chainResolver(t)
			set(s, "alias.example.", dns.TypeCNAME, 300, "target.example.")
			if present {
				set(s, "target.example.", dns.TypeAAAA, 600, "2001:db8::1")
			}
			m, e := a.Resolve(query("alias.example.", dns.TypeA), 1)
			if e != nil || m.Rcode != 0 || len(m.Answer) != 1 || len(m.Ns) != 0 {
				t.Fatal("invented negative authority")
			}
		})
	}
	a, s := chainResolver(t)
	set(s, "direct.example.", dns.TypeA, 50, "192.0.2.1")
	for _, tc := range []struct {
		name string
		qt   uint16
		rc   int
	}{{"direct.example.", dns.TypeAAAA, 0}, {"missing.example.", dns.TypeA, dns.RcodeNameError}} {
		m, e := a.Resolve(query(tc.name, tc.qt), 0)
		if e != nil || m.Rcode != tc.rc || len(m.Ns) != 1 {
			t.Fatal("direct negative behavior changed")
		}
	}
}
func TestChainBoundariesAndCycles(t *testing.T) {
	for _, count := range []int{1, 16, 17} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			a, s := chainResolver(t)
			for j := 0; j < count; j++ {
				set(s, fmt.Sprintf("n%d.example.", j), dns.TypeCNAME, 60, fmt.Sprintf("n%d.example.", j+1))
			}
			set(s, fmt.Sprintf("n%d.example.", count), dns.TypeA, 60, "192.0.2.1")
			if count > 16 {
				assertFailure(t, a, "n0.example.", 32)
			} else {
				m, e := a.Resolve(query("n0.example.", dns.TypeA), count)
				if e != nil || len(m.Answer) != count+1 {
					t.Fatal("exact budget failed")
				}
			}
			assertFailure(t, a, "n0.example.", count-1)
		})
	}
	for _, depth := range []int{-1, 0} {
		a, s := chainResolver(t)
		set(s, "a.example.", dns.TypeCNAME, 60, "b.example.")
		assertFailure(t, a, "a.example.", depth)
	}
	for _, target := range []string{"A.Example.", "b.example."} {
		t.Run(target, func(t *testing.T) {
			a, s := chainResolver(t)
			set(s, "a.example.", dns.TypeCNAME, 60, target)
			set(s, "b.example.", dns.TypeCNAME, 60, "A.Example.")
			assertFailure(t, a, "a.example.", 32)
		})
	}
	a, s := chainResolver(t)
	set(s, "direct.example.", dns.TypeA, 60, "192.0.2.1")
	m, e := a.Resolve(query("direct.example.", dns.TypeA), 0)
	if e != nil || len(m.Answer) != 1 {
		t.Fatal("depth0 direct answer failed")
	}
}
func TestChainMalformedAndConflictingData(t *testing.T) {
	for j, values := range [][]string{nil, {""}, {"a.example.", "b.example."}, {"bad..example."}, {" target.example."}} {
		t.Run(fmt.Sprint(j), func(t *testing.T) {
			a, s := chainResolver(t)
			set(s, "alias.example.", dns.TypeCNAME, 60, values...)
			assertFailure(t, a, "alias.example.", 32)
		})
	}
	for _, typ := range []uint16{dns.TypeA, dns.TypeTXT} {
		t.Run(dns.TypeToString[typ], func(t *testing.T) {
			a, s := chainResolver(t)
			set(s, "alias.example.", dns.TypeCNAME, 60, "target.example.")
			set(s, "alias.example.", typ, 60, "192.0.2.1")
			assertFailure(t, a, "alias.example.", 32)
		})
	}
	a, s := chainResolver(t)
	set(s, "alias.example.", dns.TypeCNAME, 60, "target.example.")
	set(s, "target.example.", dns.TypeA, 60, "bad")
	assertFailure(t, a, "alias.example.", 32)
	s.Set(recordstore.Record{Name: "alias.example.", Type: dns.TypeTXT, Values: []string{"expired"}, ExpiresAt: time.Now().Add(-time.Second)})
	set(s, "target.example.", dns.TypeA, 60, "192.0.2.1")
	m, e := a.Resolve(query("alias.example.", dns.TypeA), 1)
	if e != nil || len(m.Answer) != 2 {
		t.Fatal("expired conflict should be ignored")
	}
}

type fallbackSpy struct{ calls int }

func (*fallbackSpy) Type() descriptor.Type { return nil }
func (*fallbackSpy) TypeName() string      { return "test-spy" }
func (s *fallbackSpy) Resolve(q *dns.Msg, _ int) (*dns.Msg, error) {
	s.calls++
	m := new(dns.Msg)
	m.SetReply(q)
	return m, nil
}
func TestChainFailureDoesNotFallThroughCore(t *testing.T) {
	a, s := chainResolver(t)
	set(s, "loop.example.", dns.TypeCNAME, 60, "LOOP.example.")
	spy := new(fallbackSpy)
	i := core.NewInstance()
	i.SetDefaultResolver(spy)
	i.AcceptProvider(&collection.Collection{Rules: []*rule.NameResolutionRule{{Name: "\"loop.example.\"", Resolver: a}}}, func(e error) { t.Fatal(e) })
	r, _ := i.GetResolver()
	for _, depth := range []int{0, 1, 32} {
		m, e := r.Resolve(query("loop.example.", dns.TypeA), depth)
		if e != nil || m.Rcode != dns.RcodeServerFailure || spy.calls != 0 {
			t.Fatal("failure escaped to default")
		}
	}
}
func TestChainDescriptorOptIn(t *testing.T) {
	d, _ := resolverpkg.GetResolverDescriptorByTypeName("authoritative")
	for _, enabled := range []bool{false, true} {
		o, s, f := d.Describe(map[string]interface{}{"completeCNAME": enabled})
		if s < 1 || f > 0 || o.(*Authoritative).CompleteCNAME != enabled {
			t.Fatal("descriptor option")
		}
	}
	o, _, _ := d.Describe(map[string]interface{}{})
	if o.(*Authoritative).CompleteCNAME {
		t.Fatal("default enabled")
	}
}
func TestChainConcurrentCRUD(t *testing.T) {
	a, s := chainResolver(t)
	set(s, "alias.example.", dns.TypeCNAME, 60, "target.example.")
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for j := 0; j < 200; j++ {
			set(s, "target.example.", dns.TypeA, 60, "192.0.2.1")
			s.Delete("target.example.", dns.TypeA)
		}
	}()
	go func() {
		defer wg.Done()
		for j := 0; j < 200; j++ {
			m, e := a.Resolve(query("alias.example.", dns.TypeA), 2)
			if e != nil || m.Rcode != 0 || len(m.Answer) < 1 || len(m.Answer) > 2 {
				t.Error("invalid concurrent reply")
			}
		}
	}()
	wg.Wait()
}
