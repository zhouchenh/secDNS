package diagnostics

import (
	"encoding/json"
	"github.com/miekg/dns"
	"strings"
	"testing"
	"time"
)

func TestTraceBoundedAndRedacted(t *testing.T) {
	events = make(chan event, 2)
	deadline = time.Now().Add(time.Second)
	emitted.Store(0)
	defer func() { events = nil; deadline = time.Time{}; emitted.Store(0) }()
	q := new(dns.Msg)
	q.SetQuestion("private-name.invalid.", dns.TypeAAAA)
	s := Begin(q, "test")
	s.End("complete")
	s.End("dropped")
	if len(events) != 2 {
		t.Fatal("bounded queue")
	}
	for len(events) > 0 {
		b, _ := json.Marshal(<-events)
		if strings.Contains(string(b), "private-name") {
			t.Fatal("name leaked")
		}
	}
	emitted.Store(32768)
	s.End("capped")
	if len(events) != 0 {
		t.Fatal("event cap")
	}
	emitted.Store(0)
	deadline = time.Now().Add(-time.Second)
	s.End("expired")
	if Begin(q, "expired").id != 0 || len(events) != 0 {
		t.Fatal("duration cap")
	}
}
