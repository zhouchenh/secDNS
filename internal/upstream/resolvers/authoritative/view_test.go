package authoritative

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/zhouchenh/secDNS/internal/recordset"
	"github.com/zhouchenh/secDNS/internal/recordstore"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var versionedTestSequence atomic.Uint64

func TestVersionedAuthorityPinnedGeneration(t *testing.T) {
	name := fmt.Sprintf("%s-%d", t.Name(), versionedTestSequence.Add(1))
	cleanup, e := recordstore.PrepareBindings(nil, map[string]recordstore.VersionedConfig{name: {Backend: "memory", RulesetID: "r", LineageID: "l"}})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = cleanup() })
	_, v := recordstore.Binding(name)
	records := func(i int) []recordset.Record {
		target := fmt.Sprintf("target%d.invalid.", i%2)
		return []recordset.Record{{Name: "alias.invalid.", Type: "CNAME", Values: []string{target}, TTLSeconds: uint32(i % 2)}, {Name: target, Type: "A", Values: []string{fmt.Sprintf("192.0.2.%d", 1+i%2)}, TTLSeconds: uint32(i % 2)}}
	}
	if _, e = v.Replace(recordstore.Expected{RulesetID: "r", LineageID: "l", Revision: 1}, "initial", records(0)); e != nil {
		t.Fatal(e)
	}
	a := &Authoritative{Store: name, CompleteCNAME: true}
	var wg sync.WaitGroup
	errs := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 1; i <= 200; i++ {
			if _, e := v.Replace(recordstore.Expected{RulesetID: "r", LineageID: "l", Revision: uint64(i + 1)}, fmt.Sprintf("op%d", i), records(i)); e != nil {
				errs <- e
				return
			}
		}
	}()
	for i := 0; i < 500; i++ {
		reply, e := a.Resolve(query("alias.invalid.", dns.TypeA), 16)
		if e != nil || len(reply.Answer) != 2 {
			t.Fatalf("mixed/missing generation: %v %v", reply, e)
		}
		cn := reply.Answer[0].(*dns.CNAME)
		ip := reply.Answer[1].(*dns.A)
		if cn.Target != ip.Hdr.Name || cn.Hdr.Ttl != ip.Hdr.Ttl {
			t.Fatal("torn generation")
		}
	}
	wg.Wait()
	select {
	case e := <-errs:
		t.Fatal(e)
	default:
	}
	if e = cleanup(); e != nil {
		t.Fatal(e)
	}
	for _, resolver := range []*Authoritative{a, {Store: name, CompleteCNAME: true}} {
		reply, e := resolver.Resolve(query("alias.invalid.", dns.TypeA), 16)
		if e != nil || reply.Rcode != dns.RcodeServerFailure || len(reply.Answer) != 0 {
			t.Fatal("closed store did not fail locally")
		}
	}
}
func TestVersionedViewExpiryAndTXT(t *testing.T) {
	v, e := recordstore.NewVersionedMemory(recordstore.Enrollment{RulesetID: "r", LineageID: "l"})
	if e != nil {
		t.Fatal(e)
	}
	defer v.Close()
	_, e = v.Replace(recordstore.Expected{RulesetID: "r", LineageID: "l", Revision: 1}, "op", []recordset.Record{{Name: "x.invalid.", Type: "TXT", Values: []string{"", "chunk", "chunk"}, TTLSeconds: 0}, {Name: "expired.invalid.", Type: "A", Values: []string{"192.0.2.1"}, ExpiresAt: "2000-01-01T00:00:00Z"}})
	if e != nil {
		t.Fatal(e)
	}
	view, e := v.Acquire()
	if e != nil {
		t.Fatal(e)
	}
	reader := viewReader{view}
	if reader.HasName("expired.invalid.") {
		t.Fatal("expired visible")
	}
	r, ok := reader.Get("x.invalid.", dns.TypeTXT)
	if !ok || r.TTL != 0 || len(r.Values) != 3 {
		t.Fatal(r)
	}
	_ = v.Close()
	if !reader.HasName("x.invalid.") {
		t.Fatal("held view invalidated")
	}
}

func TestHeldVersionedChainUsesCapturedExpiry(t *testing.T) {
	v, e := recordstore.NewVersionedMemory(recordstore.Enrollment{RulesetID: "r", LineageID: "l"})
	if e != nil {
		t.Fatal(e)
	}
	defer v.Close()
	deadline := time.Now().Add(time.Second)
	_, e = v.Replace(recordstore.Expected{RulesetID: "r", LineageID: "l", Revision: 1}, "op", []recordset.Record{{Name: "alias.invalid.", Type: "CNAME", Values: []string{"target.invalid."}, ExpiresAt: deadline.Format(time.RFC3339Nano)}, {Name: "target.invalid.", Type: "A", Values: []string{"192.0.2.1"}, ExpiresAt: deadline.Format(time.RFC3339Nano)}})
	if e != nil {
		t.Fatal(e)
	}
	held, e := v.Acquire()
	if e != nil {
		t.Fatal(e)
	}
	if !held.CapturedAt().Before(deadline) {
		t.Fatal("test admission missed expiry deadline")
	}
	time.Sleep(time.Until(deadline) + time.Millisecond)
	a := &Authoritative{NegativeTTL: 60}
	reply := a.resolveChain(query("alias.invalid.", dns.TypeA), 16, viewReader{held})
	if len(reply.Answer) != 2 {
		t.Fatal("held chain changed at wall-clock expiry", reply)
	}
	fresh, e := v.Acquire()
	if e != nil {
		t.Fatal(e)
	}
	reply = a.resolveChain(query("alias.invalid.", dns.TypeA), 16, viewReader{fresh})
	if reply.Rcode != dns.RcodeNameError || len(reply.Answer) != 0 {
		t.Fatal("fresh view retained expired chain", reply)
	}
}
