// Package diagnostics provides a bounded, opt-in resolver phase trace. It never
// records names, URLs, addresses, headers, reply data or error strings.
package diagnostics

import (
	"encoding/json"
	"github.com/miekg/dns"
	"os"
	"strconv"
	"sync/atomic"
	"time"
)

type event struct {
	Token    string `json:"correlation,omitempty"`
	ID       uint64 `json:"id"`
	Phase    string `json:"phase"`
	State    string `json:"state"`
	At       int64  `json:"unix_ms"`
	Duration int64  `json:"duration_ms,omitempty"`
	DNSID    uint16 `json:"dns_id"`
	Qtype    uint16 `json:"qtype"`
	Outcome  string `json:"outcome,omitempty"`
}
type Span struct {
	token        string
	id           uint64
	phase        string
	start        time.Time
	dnsid, qtype uint16
}

var deadline time.Time
var serial atomic.Uint64
var emitted atomic.Uint64
var dropped atomic.Uint64
var written atomic.Uint64
var writeErrors atomic.Uint64
var active atomic.Int64

type aggregate struct {
	Count atomic.Uint64
	MaxMS atomic.Int64
}

var aggregates = map[string]*aggregate{}
var events chan event

func init() {
	for _, phase := range []string{"doh.resolve", "doh.slot_wait", "doh.http", "doh.failed_refresh", "dns64.resolve", "dns64.aaaa", "dns64.speculative_a", "cache.slot_wait", "sequence.attempt", "listener.handler", "listener.write"} {
		aggregates[phase] = &aggregate{}
	}
	seconds, e := strconv.Atoi(os.Getenv("SECDNS_RESOLVER_TRACE_SECONDS"))
	if e != nil || seconds < 1 || seconds > 180 {
		return
	}
	deadline = time.Now().Add(time.Duration(seconds) * time.Second)
	events = make(chan event, 512)
	go func() {
		encoder := json.NewEncoder(os.Stderr)
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		for {
			select {
			case e := <-events:
				if encoder.Encode(struct {
					Kind  string `json:"kind"`
					Event event  `json:"event"`
				}{"secdns-resolver-trace", e}) != nil {
					writeErrors.Add(1)
				} else {
					written.Add(1)
				}
			case <-timer.C:
				totals := map[string]map[string]int64{}
				for phase, stat := range aggregates {
					totals[phase] = map[string]int64{"completed": int64(stat.Count.Load()), "max_ms": stat.MaxMS.Load()}
				}
				_ = encoder.Encode(map[string]interface{}{"kind": "secdns-resolver-trace-summary", "attempted": emitted.Load(), "dropped": dropped.Load(), "written": written.Load(), "write_errors": writeErrors.Load(), "active": active.Load(), "queued": len(events), "phases": totals})
			}
		}
	}()
}
func send(e event) {
	if events == nil || time.Now().After(deadline) {
		return
	}
	if emitted.Add(1) > 32768 {
		dropped.Add(1)
		return
	}
	select {
	case events <- e:
	default:
		dropped.Add(1)
	}
}
func Begin(q *dns.Msg, phase string) Span {
	if events == nil || time.Now().After(deadline) {
		return Span{}
	}
	token := CorrelationToken(q)
	if os.Getenv("SECDNS_QUERY_TRACE_ONLY") == "1" {
		if token == "" {
			return Span{}
		}
		switch phase {
		case "listener.handler", "listener.write", "dns64.resolve", "doh.resolve", "cache.slot_wait", "sequence.attempt":
		default:
			return Span{}
		}
	}
	active.Add(1)
	s := Span{id: serial.Add(1), phase: phase, start: time.Now(), token: token}
	if q != nil {
		s.dnsid = q.Id
		if len(q.Question) > 0 {
			s.qtype = q.Question[0].Qtype
		}
	}
	return s
}
func (s Span) End(outcome string) {
	if s.id == 0 {
		return
	}
	active.Add(-1)
	duration := time.Since(s.start).Milliseconds()
	if stat := aggregates[s.phase]; stat != nil && !time.Now().After(deadline) {
		stat.Count.Add(1)
		for old := stat.MaxMS.Load(); duration > old && !stat.MaxMS.CompareAndSwap(old, duration); old = stat.MaxMS.Load() {
		}
	}
	send(event{Token: s.token, ID: s.id, Phase: s.phase, State: "end", At: time.Now().UnixMilli(), Duration: time.Since(s.start).Milliseconds(), DNSID: s.dnsid, Qtype: s.qtype, Outcome: outcome})
}
