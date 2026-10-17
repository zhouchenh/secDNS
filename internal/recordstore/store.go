// Package recordstore holds the in-memory authoritative records served by the
// authoritative resolver and mutated by the admin API. A store is shared by name (see
// registry.go) so a resolver and an admin listener configured with the same store name
// operate on one set of records.
package recordstore

import (
	"database/sql"
	"errors"
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
	db      *sql.DB
	closed  bool
	stop    chan struct{}
	done    chan struct{}
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
func (s *Store) Set(rec Record) error { return s.set(rec, false) }

// SetValidated is the admin mutation path for both backends. Validation, expiry
// and CNAME conflict checks share the same lock as durable commit and publication.
// Direct Set retains permissive in-memory behavior for existing internal callers.
func (s *Store) SetValidated(rec Record) error { return s.set(rec, true) }

var ErrRecordConflict = errors.New("record conflicts with a live CNAME or other RRset")
var ErrExpiredRecord = errors.New("record expiry must be in the future")

func (s *Store) set(rec Record, validated bool) error {
	if validated {
		rec.Name = strings.TrimSpace(rec.Name)
	}
	invalidName := rec.Name == ""
	rec.Name = canonicalName(rec.Name)
	rec.Values = append([]string(nil), rec.Values...)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if validated {
		var err error
		rec, err = normalizeValidated(rec)
		if err != nil {
			return err
		}
	}
	if validated || s.db != nil {
		if invalidName {
			return ErrInvalidRecord
		}
		if err := validateRecord(rec); err != nil {
			return err
		}
		now := s.now()
		if validated && !rec.ExpiresAt.IsZero() && !rec.ExpiresAt.After(now) {
			return ErrExpiredRecord
		}
		// Already expired direct writes cannot conflict with live data. Admin writes
		// must instead pass the future-expiry check above.
		if !rec.expired(now) {
			for k, other := range s.records {
				if k.name == rec.Name && k.rrtype != rec.Type && (k.rrtype == 5 || rec.Type == 5) && !other.expired(now) {
					return ErrRecordConflict
				}
			}
		}
	}
	if s.db != nil {
		if err := s.persistSet(rec); err != nil {
			return err
		}
	}
	s.records[key{rec.Name, rec.Type}] = rec
	return nil
}

// Get returns the live record for {name, type}, or false if it is absent or expired.
func (s *Store) Get(name string, rrtype uint16) (Record, bool) {
	k := key{canonicalName(name), rrtype}
	s.mu.RLock()
	rec, ok := s.records[k]
	rec.Values = append([]string(nil), rec.Values...)
	s.mu.RUnlock()
	if !ok || rec.expired(s.now()) {
		return Record{}, false
	}
	return rec, true
}

// Delete removes the record for {name, type}; it reports whether one was present
// (regardless of expiry).
func (s *Store) Delete(name string, rrtype uint16) (bool, error) {
	k := key{canonicalName(name), rrtype}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false, ErrClosed
	}
	_, ok := s.records[k]
	if s.db != nil {
		if err := s.persistDelete(k); err != nil {
			return false, err
		}
	}
	delete(s.records, k)
	return ok, nil
}

// List returns all live (non-expired) records.
func (s *Store) List() []Record {
	now := s.now()
	s.mu.RLock()
	out := make([]Record, 0, len(s.records))
	for _, rec := range s.records {
		if !rec.expired(now) {
			rec.Values = append([]string(nil), rec.Values...)
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
func (s *Store) sweep() error {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	var expired []key
	for k, rec := range s.records {
		if rec.expired(now) {
			expired = append(expired, k)
		}
	}
	if s.db != nil && len(expired) > 0 {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()
		for _, k := range expired {
			if _, err = tx.Exec("DELETE FROM records WHERE name=? AND type=?", k.name, k.rrtype); err != nil {
				return err
			}
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	for _, k := range expired {
		delete(s.records, k)
	}
	return nil
}

// RecordsForName returns an isolated, per-owner snapshot of live RRsets. It does
// not promise a transaction spanning different names or multiple calls.
func (s *Store) RecordsForName(name string) map[uint16]Record {
	cn := canonicalName(name)
	now := s.now()
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[uint16]Record)
	for k, rec := range s.records {
		if k.name == cn && !rec.expired(now) {
			rec.Values = append([]string(nil), rec.Values...)
			out[k.rrtype] = rec
		}
	}
	return out
}

var ErrClosed = errors.New("record store is closed")

// Close serializes with mutations; none can publish after it returns.
func (s *Store) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	if s.stop != nil {
		close(s.stop)
	}
	done := s.done
	var err error
	if s.db != nil {
		err = s.db.Close()
	}
	s.mu.Unlock()
	if done != nil {
		<-done
	}
	return err
}
