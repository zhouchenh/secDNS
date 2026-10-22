package dns64

import (
	"errors"
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type functionResolver struct {
	fn func(*dns.Msg, int) (*dns.Msg, error)
}

func (f *functionResolver) Type() descriptor.Type {
	return descriptor.TypeOfNew(new(*functionResolver))
}
func (f *functionResolver) TypeName() string                            { return "function" }
func (f *functionResolver) Resolve(q *dns.Msg, d int) (*dns.Msg, error) { return f.fn(q, d) }
func wait(t *testing.T, c <-chan struct{}) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(time.Second):
		t.Fatal("blocked")
	}
}
func waitReleased(t *testing.T, d *DNS64) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for len(d.speculativeSlots) > 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(d.speculativeSlots) != 0 {
		t.Fatal("slot leaked")
	}
}
func TestSpeculativeNativePrecedence(t *testing.T) {
	for _, kind := range []string{"AAAA", "NXDOMAIN", "SERVFAIL", "REFUSED", "error", "nil"} {
		t.Run(kind, func(t *testing.T) {
			started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			original := newAAAAResponse("test.")
			sentinel := errors.New("native failure")
			switch kind {
			case "AAAA":
				original.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: "test.", Rrtype: dns.TypeAAAA, Class: 1}, AAAA: net.ParseIP("2001:db8::1")}}
			case "NXDOMAIN":
				original.Rcode = dns.RcodeNameError
			case "SERVFAIL":
				original.Rcode = dns.RcodeServerFailure
			case "REFUSED":
				original.Rcode = dns.RcodeRefused
			}
			d := &DNS64{SpeculativeA: true, Prefix: net.ParseIP("64:ff9b::")}
			d.Resolver = &functionResolver{func(q *dns.Msg, depth int) (*dns.Msg, error) {
				if depth != 3 {
					t.Error("depth changed")
				}
				if q.Question[0].Qtype == dns.TypeA {
					close(started)
					<-release
					return nil, errors.New("unused A")
				}
				<-started
				if kind == "error" {
					return nil, sentinel
				}
				if kind == "nil" {
					return nil, nil
				}
				return original, nil
			}}
			q := new(dns.Msg)
			q.SetQuestion("test.", dns.TypeAAAA)
			go func() {
				defer close(done)
				reply, err := d.Resolve(q, 4)
				if kind == "error" {
					if err != sentinel {
						t.Error("native error lost")
					}
				} else if kind == "nil" {
					if reply != nil || err != nil {
						t.Error("nil changed")
					}
				} else if reply != original || err != nil {
					t.Error("native response changed")
				}
			}()
			wait(t, done)
			if len(d.speculativeSlots) != 1 {
				t.Error("slot released before worker completion")
			}
			close(release)
			waitReleased(t, d)
			if q.Question[0].Qtype != dns.TypeAAAA {
				t.Fatal("query mutated")
			}
		})
	}
}
func TestSpeculativeSynthesisConcurrentAndCopied(t *testing.T) {
	started := make(chan struct{})
	var aCalls atomic.Int32
	a := newAResponse("test.", &dns.A{Hdr: dns.RR_Header{Name: "test.", Rrtype: dns.TypeA, Class: 1, Ttl: 60}, A: net.IPv4(1, 1, 1, 1)}, &dns.RRSIG{Hdr: dns.RR_Header{Name: "test.", Rrtype: dns.TypeRRSIG, Class: 1}})
	a.AuthenticatedData = true
	d := &DNS64{SpeculativeA: true, Prefix: net.ParseIP("64:ff9b::")}
	d.Resolver = &functionResolver{func(q *dns.Msg, _ int) (*dns.Msg, error) {
		if q.Question[0].Qtype == dns.TypeA {
			aCalls.Add(1)
			q.Question[0].Name = "changed."
			close(started)
			return a, nil
		}
		<-started
		return newAAAAResponse("test."), nil
	}}
	q := new(dns.Msg)
	q.SetQuestion("test.", dns.TypeAAAA)
	r, e := d.Resolve(q, 4)
	if e != nil || aCalls.Load() != 1 || len(r.Answer) != 1 || r.AuthenticatedData || r.Answer[0].(*dns.AAAA).AAAA.String() != "64:ff9b::101:101" {
		t.Fatal("bad synthesis", r, e)
	}
	if q.Question[0].Name != "test." || q.Question[0].Qtype != dns.TypeAAAA || len(a.Answer) != 2 || !a.AuthenticatedData || a.Question[0].Qtype != dns.TypeA {
		t.Fatal("input modified")
	}
	waitReleased(t, d)
}
func TestSpeculativeCapacityFallback(t *testing.T) {
	for _, global := range []bool{false, true} {
		d := &DNS64{SpeculativeA: true, Prefix: net.ParseIP("64:ff9b::")}
		d.speculativeOnce.Do(func() { d.speculativeSlots = make(chan struct{}, 32) })
		slots := d.speculativeSlots
		if global {
			slots = speculativeGlobalSlots
		}
		for i := 0; i < cap(slots); i++ {
			slots <- struct{}{}
		}
		calls := []uint16{}
		d.Resolver = &functionResolver{func(q *dns.Msg, _ int) (*dns.Msg, error) {
			calls = append(calls, q.Question[0].Qtype)
			return newAAAAResponse("test."), nil
		}}
		q := new(dns.Msg)
		q.SetQuestion("test.", dns.TypeAAAA)
		_, err := d.Resolve(q, 4)
		for i := 0; i < cap(slots); i++ {
			<-slots
		}
		if err != nil || len(calls) != 2 || calls[0] != dns.TypeAAAA || calls[1] != dns.TypeA {
			t.Fatal("not serial fallback", calls, err)
		}
		if len(d.speculativeSlots) != 0 {
			t.Fatal("local slot leak")
		}
	}
}
func TestSpeculativeAError(t *testing.T) {
	sentinel := errors.New("A failed")
	d := &DNS64{SpeculativeA: true}
	d.Resolver = &functionResolver{func(q *dns.Msg, _ int) (*dns.Msg, error) {
		if q.Question[0].Qtype == dns.TypeA {
			return nil, sentinel
		}
		return newAAAAResponse("test."), nil
	}}
	q := new(dns.Msg)
	q.SetQuestion("test.", dns.TypeAAAA)
	if _, err := d.Resolve(q, 4); err != sentinel {
		t.Fatal(err)
	}
	waitReleased(t, d)
}
