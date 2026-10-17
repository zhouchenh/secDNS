package recordstore

import (
	"github.com/miekg/dns"
	"testing"
	"time"
)

func TestValuesAreIsolated(t *testing.T) {
	s := New()
	values := []string{"192.0.2.1"}
	s.Set(Record{Name: "host.example.", Type: dns.TypeA, TTL: 300, Values: values})
	values[0] = "bad"
	r, _ := s.Get("host.example.", dns.TypeA)
	if r.Values[0] != "192.0.2.1" {
		t.Fatal("Set input alias")
	}
	r.Values[0] = "bad"
	list := s.List()
	list[0].Values[0] = "bad"
	snap := s.RecordsForName("HOST.EXAMPLE.")
	snap[dns.TypeA].Values[0] = "bad"
	delete(snap, dns.TypeA)
	r, _ = s.Get("host.example.", dns.TypeA)
	if r.Values[0] != "192.0.2.1" || r.TTL != 300 {
		t.Fatal("read output aliases store")
	}
	s.Set(Record{Name: "host.example.", Type: dns.TypeTXT, Values: []string{"old"}, ExpiresAt: time.Now().Add(-time.Second)})
	if len(s.RecordsForName("host.example.")) != 1 {
		t.Fatal("snapshot retained expired data")
	}
}
