package recordstore

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestStoreSetGetReplaceDelete(t *testing.T) {
	s := New()
	s.Set(Record{Name: "Foo.Example.COM", Type: dns.TypeTXT, Values: []string{"a"}, TTL: 60})

	// Lookup is case- and trailing-dot-insensitive.
	rec, ok := s.Get("foo.example.com.", dns.TypeTXT)
	if !ok {
		t.Fatalf("record not found after Set")
	}
	if rec.Name != "foo.example.com." || rec.Values[0] != "a" {
		t.Fatalf("unexpected record: %+v", rec)
	}

	// Set replaces by {name, type}.
	s.Set(Record{Name: "foo.example.com", Type: dns.TypeTXT, Values: []string{"b"}, TTL: 30})
	rec, _ = s.Get("foo.example.com", dns.TypeTXT)
	if len(rec.Values) != 1 || rec.Values[0] != "b" || rec.TTL != 30 {
		t.Fatalf("Set did not replace: %+v", rec)
	}

	// A different type for the same name is independent.
	if _, ok := s.Get("foo.example.com", dns.TypeA); ok {
		t.Fatalf("unexpected A record")
	}

	if !s.Delete("FOO.example.com.", dns.TypeTXT) {
		t.Fatalf("Delete should report the record was present")
	}
	if _, ok := s.Get("foo.example.com", dns.TypeTXT); ok {
		t.Fatalf("record still present after Delete")
	}
	if s.Delete("foo.example.com", dns.TypeTXT) {
		t.Fatalf("Delete of an absent record should report false")
	}
}

func TestStoreExpiry(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	s := New()
	s.now = func() time.Time { return now }

	s.Set(Record{Name: "live.example.", Type: dns.TypeA, Values: []string{"1.2.3.4"}, TTL: 60, ExpiresAt: now.Add(time.Minute)})
	s.Set(Record{Name: "perm.example.", Type: dns.TypeA, Values: []string{"5.6.7.8"}, TTL: 60}) // zero ExpiresAt = no expiry

	if _, ok := s.Get("live.example.", dns.TypeA); !ok {
		t.Fatalf("unexpired record should be live")
	}

	// Advance past the expiry: the record is no longer returned, and HasName/List drop it.
	now = now.Add(2 * time.Minute)
	if _, ok := s.Get("live.example.", dns.TypeA); ok {
		t.Fatalf("expired record must not be returned")
	}
	if s.HasName("live.example.") {
		t.Fatalf("HasName must ignore expired records")
	}
	if _, ok := s.Get("perm.example.", dns.TypeA); !ok {
		t.Fatalf("a zero-expiry record must never expire")
	}

	// sweep reclaims the expired entry; the permanent one stays.
	s.sweep()
	if got := len(s.List()); got != 1 {
		t.Fatalf("after sweep, want 1 live record, got %d", got)
	}
}

func TestStoreHasNameDistinguishesNodataFromNxdomain(t *testing.T) {
	s := New()
	s.Set(Record{Name: "exists.example.", Type: dns.TypeA, Values: []string{"1.2.3.4"}, TTL: 60})

	if !s.HasName("exists.example.") {
		t.Fatalf("HasName should be true for a name with a record")
	}
	if _, ok := s.Get("exists.example.", dns.TypeTXT); ok {
		t.Fatalf("a different type should miss (NODATA), got a hit")
	}
	if s.HasName("absent.example.") {
		t.Fatalf("HasName should be false for an unknown name (NXDOMAIN)")
	}
}

func TestGetOrCreateSharesByName(t *testing.T) {
	a := GetOrCreate("shared-test")
	b := GetOrCreate("shared-test")
	if a != b {
		t.Fatalf("GetOrCreate must return the same store for the same name")
	}
	if GetOrCreate("") != GetOrCreate(DefaultName) {
		t.Fatalf("an empty name must map to DefaultName")
	}
	c := GetOrCreate("other-test")
	if c == a {
		t.Fatalf("distinct names must map to distinct stores")
	}
}
