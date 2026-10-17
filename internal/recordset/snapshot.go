// Package recordset defines an immutable, exact-record replication payload.
// It performs no I/O, store mutation, replication, or authority election.
package recordset

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/miekg/dns"
)

const Schema = "secdns.exact-record-set.v1"
const MaxBytes = 4 << 20
const MaxRecords = 10000
const MaxValues = 64
const MaxTotalValues = 100000

var ErrInvalid = errors.New("invalid exact record snapshot")
var ErrLimit = errors.New("exact record snapshot limit exceeded")
var ErrDigest = errors.New("exact record snapshot digest mismatch")

// Record is one exact RRset. TTL zero is meaningful and is never defaulted.
// ExpiresAt is an absolute RFC3339Nano timestamp; empty means permanent.
type Record struct {
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	Values     []string `json:"values"`
	TTLSeconds uint32   `json:"ttl_seconds"`
	ExpiresAt  string   `json:"expires_at,omitempty"`
}

type Metadata struct {
	Schema        string `json:"schema"`
	RulesetID     string `json:"ruleset_id"`
	LineageID     string `json:"lineage_id"`
	Revision      uint64 `json:"revision,string"`
	ContentSHA256 string `json:"content_sha256"`
}

type envelope struct {
	Metadata
	Records []Record `json:"records"`
}
type content struct {
	Schema    string   `json:"schema"`
	RulesetID string   `json:"ruleset_id"`
	Records   []Record `json:"records"`
}
type key struct{ name, typ string }

// Snapshot owns all slices and maps. Accessors return copies; a resolver can pin
// one Snapshot for its complete query, including multi-owner CNAME traversal.
type Snapshot struct {
	metadata  Metadata
	records   []Record
	expires   []time.Time
	index     map[key]int
	canonical []byte
	wire      []byte
}

func validID(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func canonicalName(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 255 {
		return "", ErrInvalid
	}
	// v1 uses unescaped ASCII presentation names. IDNs must arrive as A-labels.
	// Reject alternate escaped representations instead of hashing aliases as distinct names.
	for _, c := range s {
		if c <= 32 || c >= 127 || c == '\\' {
			return "", ErrInvalid
		}
	}
	s = strings.ToLower(dns.Fqdn(s))
	if len(s) > 255 {
		return "", ErrInvalid
	}
	if _, ok := dns.IsDomainName(s); !ok {
		return "", ErrInvalid
	}
	return s, nil
}

func cloneRecord(r Record) Record { r.Values = append([]string(nil), r.Values...); return r }

// New validates and seals a proposed exact-record snapshot. It never consults
// the clock. Expired entries are retained; conflicting types must be removed by
// the authority in the same proposal, even when one entry has already expired.
func New(rulesetID, lineageID string, revision uint64, records []Record) (*Snapshot, error) {
	if !validID(rulesetID) || !validID(lineageID) || revision == 0 {
		return nil, ErrInvalid
	}
	if len(records) > MaxRecords {
		return nil, ErrLimit
	}
	s := &Snapshot{metadata: Metadata{Schema: Schema, RulesetID: rulesetID, LineageID: lineageID, Revision: revision}, records: make([]Record, 0, len(records)), index: make(map[key]int)}
	total, size := 0, 0
	for _, input := range records {
		if len(input.Values) == 0 {
			return nil, ErrInvalid
		}
		if len(input.Values) > MaxValues {
			return nil, ErrLimit
		}
		total += len(input.Values)
		if total > MaxTotalValues {
			return nil, ErrLimit
		}
		size += len(input.Name) + len(input.Type) + len(input.ExpiresAt)
		for _, v := range input.Values {
			if !utf8.ValidString(v) {
				return nil, ErrInvalid
			}
			if len(v) > 255 {
				return nil, ErrLimit
			}
			size += len(v)
		}
		if size > MaxBytes {
			return nil, ErrLimit
		}
		r := cloneRecord(input)
		var err error
		if r.Name, err = canonicalName(r.Name); err != nil {
			return nil, err
		}
		r.Type = strings.ToUpper(strings.TrimSpace(r.Type))
		switch r.Type {
		case "A", "AAAA":
			for i, v := range r.Values {
				ip := net.ParseIP(strings.TrimSpace(v))
				if ip == nil || (r.Type == "A") != (ip.To4() != nil) {
					return nil, ErrInvalid
				}
				r.Values[i] = ip.String()
			}
		case "CNAME":
			if len(r.Values) != 1 {
				return nil, ErrInvalid
			}
			r.Values[0], err = canonicalName(r.Values[0])
			if err != nil {
				return nil, err
			}
		case "TXT":
		default:
			return nil, ErrInvalid
		}
		seen := map[string]bool{}
		for _, v := range r.Values {
			if r.Type != "TXT" && seen[v] {
				return nil, ErrInvalid
			}
			seen[v] = true
		}
		if r.ExpiresAt != "" {
			t, e := time.Parse(time.RFC3339Nano, r.ExpiresAt)
			if e != nil || t.IsZero() || t.UTC().Year() < 1 || t.UTC().Year() > 9999 {
				return nil, ErrInvalid
			}
			r.ExpiresAt = t.UTC().Format(time.RFC3339Nano)
		}
		s.records = append(s.records, r)
	}
	sort.Slice(s.records, func(i, j int) bool {
		a, b := s.records[i], s.records[j]
		if a.Name == b.Name {
			return a.Type < b.Type
		}
		return a.Name < b.Name
	})
	for i, r := range s.records {
		k := key{r.Name, r.Type}
		if _, ok := s.index[k]; ok {
			return nil, ErrInvalid
		}
		if i > 0 && s.records[i-1].Name == r.Name && (s.records[i-1].Type == "CNAME" || r.Type == "CNAME") {
			return nil, ErrInvalid
		}
		s.index[k] = i
		var expiry time.Time
		if r.ExpiresAt != "" {
			expiry, _ = time.Parse(time.RFC3339Nano, r.ExpiresAt)
		}
		s.expires = append(s.expires, expiry)
	}
	s.canonical, _ = json.Marshal(content{Schema: Schema, RulesetID: rulesetID, Records: s.records})
	sum := sha256.Sum256(s.canonical)
	s.metadata.ContentSHA256 = hex.EncodeToString(sum[:])
	s.wire, _ = json.Marshal(envelope{Metadata: s.metadata, Records: s.records})
	if len(s.wire) > MaxBytes {
		return nil, ErrLimit
	}
	return s, nil
}

func (s *Snapshot) Metadata() Metadata           { return s.metadata }
func (s *Snapshot) ContentJSON() []byte          { return append([]byte(nil), s.canonical...) }
func (s *Snapshot) MarshalJSON() ([]byte, error) { return append([]byte(nil), s.wire...), nil }

// Records returns the full canonical payload, including expired records.
func (s *Snapshot) Records() []Record {
	out := make([]Record, len(s.records))
	for i, r := range s.records {
		out[i] = cloneRecord(r)
	}
	return out
}

// RecordsAt filters without changing the canonical payload or its digest.
func (s *Snapshot) RecordsAt(now time.Time) []Record {
	out := make([]Record, 0, len(s.records))
	for i, r := range s.records {
		if s.live(i, now) {
			out = append(out, cloneRecord(r))
		}
	}
	return out
}
func (s *Snapshot) live(i int, now time.Time) bool {
	return s.expires[i].IsZero() || now.Before(s.expires[i])
}
func (s *Snapshot) Lookup(name, typ string, now time.Time) (Record, bool) {
	n, e := canonicalName(name)
	if e != nil {
		return Record{}, false
	}
	i, ok := s.index[key{n, strings.ToUpper(strings.TrimSpace(typ))}]
	if !ok || !s.live(i, now) {
		return Record{}, false
	}
	return cloneRecord(s.records[i]), true
}
