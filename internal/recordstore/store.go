// Package recordstore holds the in-memory authoritative records served by the
// authoritative resolver and mutated by the admin API. A store is shared by name (see
// registry.go) so a resolver and an admin listener configured with the same store name
// operate on one set of records.
package recordstore

import (
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Record is a single authoritative RRset for a {name, type} pair.
type Record struct {
	Name      string    // canonical FQDN, lowercase
	Type      uint16    // dns.TypeTXT / TypeA / TypeAAAA / TypeCNAME
	Values    []string  // presentation-form values (IP strings, CNAME target, TXT strings)
	TTL       uint32    // DNS TTL served in answers
	ExpiresAt time.Time // store auto-removal time; the zero time means no expiry
}

func (rec Record) expired(now time.Time) bool {
	return !rec.ExpiresAt.IsZero() && !now.Before(rec.ExpiresAt)
}

type key struct {
	name   string
	rrtype uint16
}

// Store is an in-memory, TTL-aware, concurrency-safe set of authoritative records keyed
// by {canonical name, type}. Expired records are never returned and are reclaimed by a
// background sweep.
type Store struct {
	mu      sync.RWMutex
	records map[key]Record
	now     func() time.Time
}

// New returns an empty store. Use GetOrCreate for the shared, registry-backed instance
// that a resolver and an admin listener join by name.
func New() *Store {
	return &Store{records: make(map[key]Record), now: time.Now}
}

// canonicalName lowercases and fqdn-normalizes a name for keying and lookup.
func canonicalName(name string) string {
	return strings.ToLower(dns.Fqdn(name))
}

// Set inserts or replaces the record for its {name, type}. The name is canonicalized.
func (s *Store) Set(rec Record) {
	rec.Name = canonicalName(rec.Name)
	s.mu.Lock()
	s.records[key{rec.Name, rec.Type}] = rec
	s.mu.Unlock()
}

// Get returns the live record for {name, type}, or false if it is absent or expired.
func (s *Store) Get(name string, rrtype uint16) (Record, bool) {
	k := key{canonicalName(name), rrtype}
	s.mu.RLock()
	rec, ok := s.records[k]
	s.mu.RUnlock()
	if !ok || rec.expired(s.now()) {
		return Record{}, false
	}
	return rec, true
}

// Delete removes the record for {name, type}; it reports whether one was present
// (regardless of expiry).
func (s *Store) Delete(name string, rrtype uint16) bool {
	k := key{canonicalName(name), rrtype}
	s.mu.Lock()
	_, ok := s.records[k]
	delete(s.records, k)
	s.mu.Unlock()
	return ok
}

// List returns all live (non-expired) records.
func (s *Store) List() []Record {
	now := s.now()
	s.mu.RLock()
	out := make([]Record, 0, len(s.records))
	for _, rec := range s.records {
		if !rec.expired(now) {
			out = append(out, rec)
		}
	}
	s.mu.RUnlock()
	return out
}

// HasName reports whether any live record exists for the canonical name, of any type.
// The authoritative resolver uses it to answer NODATA (the name exists but not the
// queried type) versus NXDOMAIN (the name does not exist at all).
func (s *Store) HasName(name string) bool {
	cn := canonicalName(name)
	now := s.now()
	s.mu.RLock()
	defer s.mu.RUnlock()
	for k, rec := range s.records {
		if k.name == cn && !rec.expired(now) {
			return true
		}
	}
	return false
}

// sweep removes every expired record. It is called periodically by the GC loop and is
// safe to call concurrently with reads and writes.
func (s *Store) sweep() {
	now := s.now()
	s.mu.Lock()
	for k, rec := range s.records {
		if rec.expired(now) {
			delete(s.records, k)
		}
	}
	s.mu.Unlock()
}
