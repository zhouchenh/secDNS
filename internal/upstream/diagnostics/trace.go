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
var events chan event

func init() {
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
				_ = encoder.Encode(struct {
					Kind                                     string `json:"kind"`
					Attempted, Dropped, Written, WriteErrors uint64
					Active                                   int64
					Queued                                   int
				}{"secdns-resolver-trace-summary", emitted.Load(), dropped.Load(), written.Load(), writeErrors.Load(), active.Load(), len(events)})
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
	active.Add(1)
	s := Span{id: serial.Add(1), phase: phase, start: time.Now()}
	if q != nil {
		s.dnsid = q.Id
		if len(q.Question) > 0 {
			s.qtype = q.Question[0].Qtype
		}
	}
	send(event{ID: s.id, Phase: phase, State: "begin", At: s.start.UnixMilli(), DNSID: s.dnsid, Qtype: s.qtype})
	return s
}
func (s Span) End(outcome string) {
	if s.id == 0 {
		return
	}
	active.Add(-1)
	send(event{ID: s.id, Phase: s.phase, State: "end", At: time.Now().UnixMilli(), Duration: time.Since(s.start).Milliseconds(), DNSID: s.dnsid, Qtype: s.qtype, Outcome: outcome})
}
