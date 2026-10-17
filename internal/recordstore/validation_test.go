package recordstore

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"sync"
	"testing"
	"time"
)

func validationStore(t *testing.T, durable bool) *Store {
	t.Helper()
	if durable {
		return openDB(t, dbPath(t))
	}
	s := New()
	t.Cleanup(func() { s.Close() })
	return s
}
func TestValidatedMutationBothBackends(t *testing.T) {
	for _, durable := range []bool{false, true} {
		t.Run(fmt.Sprint(durable), func(t *testing.T) {
			s := validationStore(t, durable)
			now := time.Date(2040, 1, 1, 0, 0, 0, 123456789, time.UTC)
			s.now = func() time.Time { return now }
			good := Record{Name: "Host.Example.", Type: dns.TypeA, Values: []string{"192.0.2.1"}, TTL: 300}
			if e := s.SetValidated(good); e != nil {
				t.Fatal(e)
			}
			for _, bad := range []Record{{Name: "", Type: dns.TypeA, Values: []string{"192.0.2.1"}}, {Name: "bad name.example.", Type: dns.TypeA, Values: []string{"192.0.2.1"}}, {Name: "host.example.", Type: dns.TypeA, Values: []string{"2001:db8::1"}}, {Name: "host.example.", Type: dns.TypeTXT}, {Name: "host.example.", Type: dns.TypeCNAME, Values: []string{"a.example.", "b.example."}}, {Name: "host.example.", Type: dns.TypeCNAME, Values: []string{"bad..example."}}} {
				if e := s.SetValidated(bad); !errors.Is(e, ErrInvalidRecord) {
					t.Fatal("invalid accepted", e)
				}
			}
			past := good
			past.ExpiresAt = now
			if e := s.SetValidated(past); !errors.Is(e, ErrExpiredRecord) {
				t.Fatal("equal-now expiry accepted")
			}
			past.ExpiresAt = now.Add(-time.Nanosecond)
			if e := s.SetValidated(past); !errors.Is(e, ErrExpiredRecord) {
				t.Fatal("past expiry accepted")
			}
			alias := Record{Name: "host.example.", Type: dns.TypeCNAME, Values: []string{"target.example."}, TTL: 86400}
			if e := s.SetValidated(alias); !errors.Is(e, ErrRecordConflict) {
				t.Fatal("conflicting CNAME accepted")
			}
			got, _ := s.Get("host.example.", dns.TypeA)
			if got.Values[0] != "192.0.2.1" || got.TTL != 300 {
				t.Fatal("failed mutation changed state")
			}
			expired := Record{Name: "expired.example.", Type: dns.TypeA, Values: []string{"192.0.2.1"}, ExpiresAt: now.Add(-time.Second)}
			if e := s.Set(expired); e != nil {
				t.Fatal(e)
			}
			alias.Name = expired.Name
			if e := s.SetValidated(alias); e != nil {
				t.Fatal("expired conflict not ignored", e)
			}
			if e := s.Set(expired); e != nil {
				t.Fatal("expired direct write conflicts with live alias", e)
			}
		})
	}
}
func TestValidatedConcurrentCNAMEConflict(t *testing.T) {
	for _, durable := range []bool{false, true} {
		t.Run(fmt.Sprint(durable), func(t *testing.T) {
			s := validationStore(t, durable)
			for n := 0; n < 12; n++ {
				name := fmt.Sprintf("n%d.example.", n)
				start := make(chan struct{})
				results := make(chan error, 2)
				var wg sync.WaitGroup
				for _, r := range []Record{{Name: name, Type: dns.TypeCNAME, Values: []string{"target.example."}, TTL: 300}, {Name: name, Type: dns.TypeA, Values: []string{"192.0.2.1"}, TTL: 300}} {
					wg.Add(1)
					go func(r Record) { defer wg.Done(); <-start; results <- s.SetValidated(r) }(r)
				}
				close(start)
				wg.Wait()
				close(results)
				success, conflict := 0, 0
				for e := range results {
					if e == nil {
						success++
					} else if errors.Is(e, ErrRecordConflict) {
						conflict++
					} else {
						t.Fatal(e)
					}
				}
				if success != 1 || conflict != 1 || len(s.RecordsForName(name)) != 1 {
					t.Fatal("mixed owner admitted")
				}
			}
		})
	}
}
func TestLegacyMemorySetRemainsPermissive(t *testing.T) {
	s := New()
	if e := s.Set(Record{Name: "bad name", Type: dns.TypeCNAME, Values: []string{"a", "b"}}); e != nil {
		t.Fatal("legacy Set changed")
	}
	if e := s.SetValidated(Record{Name: "bad name", Type: dns.TypeCNAME, Values: []string{"a", "b"}}); !errors.Is(e, ErrInvalidRecord) {
		t.Fatal("admin bypass")
	}
}

func TestSharedValidatedNormalization(t *testing.T) {
	for _, durable := range []bool{false, true} {
		t.Run(fmt.Sprint(durable), func(t *testing.T) {
			s := validationStore(t, durable)
			input := Record{Name: " Alias.Example ", Type: dns.TypeCNAME, Values: []string{" Target.Example "}, TTL: 300}
			if e := s.SetValidated(input); e != nil {
				t.Fatal(e)
			}
			r, _ := s.Get("alias.example.", dns.TypeCNAME)
			if r.Name != "alias.example." || r.Values[0] != "target.example." || input.Values[0] != " Target.Example " {
				t.Fatal("normalization ownership")
			}
			invalid := Record{Name: "bad.example.", Type: dns.TypeTXT, Values: []string{"ok"}, ExpiresAt: time.Date(9999, 12, 31, 23, 59, 59, 0, time.FixedZone("west", -23*3600))}
			if e := s.SetValidated(invalid); !errors.Is(e, ErrInvalidRecord) {
				t.Fatal("UTC year overflow accepted")
			}
		})
	}
}
