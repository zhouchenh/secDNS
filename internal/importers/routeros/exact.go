package routeros

import (
	"errors"
	"io"
	"sort"
	"strings"

	"github.com/zhouchenh/secDNS/internal/recordset"
)

const ExactProfile = "secdns.routeros-exact-explicit.v1"
const MaxCompileBlockers = 2*MaxEntries + 1
const validationLineage = "compiler-validation" // Private scratch identity, never published.

var ErrExactConfig = errors.New("invalid exact compiler configuration")
var ErrNotExact = errors.New("source is not fully representable by the exact profile")
var ErrExactLimit = errors.New("exact compiler target limit exceeded")
var ErrExactValidation = errors.New("exact compiler validation failed")

type CompileBlocker struct {
	Ordinal        int
	Line           int
	Code           string
	RelatedOrdinal int
}

type ExactBinding struct {
	Ordinal int
	Name    string
	Type    string
}

// ExactCompilation owns a complete source report and, only on success, a sealed
// exact candidate. No accessor exposes scratch lineage/revision or a wire envelope.
type ExactCompilation struct {
	source   *Preview
	blockers []CompileBlocker
	sealed   *recordset.Snapshot
	bindings []ExactBinding
}

func (*ExactCompilation) Profile() string  { return ExactProfile }
func (*ExactCompilation) CanApply() bool   { return false }
func (c *ExactCompilation) Compiled() bool { return c != nil && c.sealed != nil }
func (c *ExactCompilation) Preview() *Preview {
	if c == nil || c.source == nil {
		return nil
	}
	p := *c.source
	p.Diagnostics = append([]Diagnostic(nil), p.Diagnostics...)
	p.Entries = make([]Entry, len(c.source.Entries))
	for i, entry := range c.source.Entries {
		e := entry
		e.Fields = make(map[string]string, len(entry.Fields))
		for k, v := range entry.Fields {
			e.Fields[k] = v
		}
		e.Diagnostics = append([]Diagnostic(nil), entry.Diagnostics...)
		p.Entries[i] = e
	}
	return &p
}
func (c *ExactCompilation) Blockers() []CompileBlocker {
	if c == nil {
		return nil
	}
	return append([]CompileBlocker(nil), c.blockers...)
}
func (c *ExactCompilation) Records() []recordset.Record {
	if !c.Compiled() {
		return nil
	}
	return c.sealed.Records()
}
func (c *ExactCompilation) ContentJSON() []byte {
	if !c.Compiled() {
		return nil
	}
	return c.sealed.ContentJSON()
}
func (c *ExactCompilation) ContentSHA256() string {
	if !c.Compiled() {
		return ""
	}
	return c.sealed.Metadata().ContentSHA256
}
func (c *ExactCompilation) Bindings() []ExactBinding {
	if !c.Compiled() {
		return nil
	}
	return append([]ExactBinding(nil), c.bindings...)
}

type exactRow struct {
	entry  Entry
	record recordset.Record
}
type exactKey struct{ name, typ string }

// exactRecord returns one primary blocker, following the profile's fixed priority.
func exactRecord(e Entry, rulesetID string) (recordset.Record, string, bool) {
	f := e.Fields
	for _, k := range []string{"type", "ttl", "disabled", "match-subdomain"} {
		if _, ok := f[k]; !ok {
			return recordset.Record{}, "defaults_missing", false
		}
	}
	typ := f["type"]
	if typ != "A" && typ != "AAAA" && typ != "CNAME" {
		return recordset.Record{}, "unsupported_type", false
	}
	if f["disabled"] != "no" {
		return recordset.Record{}, "disabled_not_enabled", false
	}
	_, regexp := f["regexp"]
	if regexp || f["match-subdomain"] != "no" {
		return recordset.Record{}, "matching_policy_not_exact", false
	}
	valueKey := "address"
	if typ == "CNAME" {
		valueKey = "cname"
	}
	for k := range f {
		if k != "name" && k != "type" && k != "ttl" && k != "disabled" && k != "match-subdomain" && k != "comment" && k != valueKey {
			return recordset.Record{}, "fields_not_exact", false
		}
	}
	ttl, err := TTLSeconds(f["ttl"])
	if err != nil {
		return recordset.Record{}, "ttl_not_exact", false
	}
	name, value := f["name"], f[valueKey]
	if strings.TrimSpace(name) != name || strings.TrimSpace(value) != value || strings.Contains(name, "*") || typ == "CNAME" && strings.Contains(value, "*") {
		return recordset.Record{}, "record_invalid", false
	}
	s, err := recordset.New(rulesetID, validationLineage, 1, []recordset.Record{{Name: name, Type: typ, Values: []string{value}, TTLSeconds: ttl}})
	if err != nil {
		return recordset.Record{}, "record_invalid", errors.Is(err, recordset.ErrLimit)
	}
	if len(e.Diagnostics) != 0 || e.Classification != "exact_record_candidate" {
		return recordset.Record{}, "parser_semantics_not_exact", false
	}
	return s.Records()[0], "", false
}

// CompileExact never applies records or returns an eligible subset. Source input
// and all ambiguity remain in the report; only a complete success exposes records.
func CompileExact(reader io.Reader, rulesetID string) (*ExactCompilation, error) {
	if _, err := recordset.New(rulesetID, validationLineage, 1, nil); err != nil {
		return nil, ErrExactConfig
	}
	if reader == nil {
		return nil, &ParseError{Diagnostic{1, 1, "input_read_failed"}}
	}
	p, err := Parse(reader)
	if err != nil {
		return nil, err
	}
	c := &ExactCompilation{source: p}
	if len(p.Entries) == 0 {
		c.blockers = []CompileBlocker{{Code: "empty_source"}}
		return c, ErrNotExact
	}
	rows := make([]exactRow, 0, len(p.Entries))
	limited := false
	for _, e := range p.Entries {
		r, code, limit := exactRecord(e, rulesetID)
		limited = limited || limit
		if code != "" {
			c.blockers = append(c.blockers, CompileBlocker{Ordinal: e.Ordinal, Line: e.Line, Code: code})
		} else {
			rows = append(rows, exactRow{e, r})
		}
	}
	// One fixed-priority conflict per eligible entry; never emit every pair.
	conflicts := make(map[int]CompileBlocker)
	first := make(map[exactKey]int)
	owners := make(map[string][]int)
	for i, row := range rows {
		k := exactKey{row.record.Name, row.record.Type}
		if prior, ok := first[k]; ok {
			conflicts[i] = CompileBlocker{row.entry.Ordinal, row.entry.Line, "duplicate_owner_type", rows[prior].entry.Ordinal}
		} else {
			first[k] = i
		}
		owners[k.name] = append(owners[k.name], i)
	}
	nodes := make(map[string]int)
	for name, members := range owners {
		cname, other := -1, -1
		for _, i := range members {
			if rows[i].record.Type == "CNAME" {
				if cname < 0 {
					cname = i
				}
			} else if other < 0 {
				other = i
			}
		}
		if cname >= 0 && other >= 0 {
			for _, i := range members {
				if _, exists := conflicts[i]; exists {
					continue
				}
				related := cname
				if rows[i].record.Type == "CNAME" {
					related = other
				}
				conflicts[i] = CompileBlocker{rows[i].entry.Ordinal, rows[i].entry.Line, "cname_owner_conflict", rows[related].entry.Ordinal}
			}
		} else if cname >= 0 && len(members) == 1 {
			nodes[name] = cname
		}
	}
	// Each node is visited once; no recursion and no repeated full-chain walks.
	done := make(map[string]bool)
	for _, row := range rows {
		name := row.record.Name
		if _, ok := nodes[name]; !ok || done[name] {
			continue
		}
		path, positions := []string{}, map[string]int{}
		for {
			i, exists := nodes[name]
			if !exists || done[name] {
				break
			}
			if start, active := positions[name]; active {
				for _, member := range path[start:] {
					j := nodes[member]
					related := nodes[rows[j].record.Values[0]]
					conflicts[j] = CompileBlocker{rows[j].entry.Ordinal, rows[j].entry.Line, "cname_cycle", rows[related].entry.Ordinal}
				}
				break
			}
			positions[name] = len(path)
			path = append(path, name)
			name = rows[i].record.Values[0]
		}
		for _, member := range path {
			done[member] = true
		}
	}
	for _, blocker := range conflicts {
		c.blockers = append(c.blockers, blocker)
	}
	if limited {
		c.blockers = append(c.blockers, CompileBlocker{Code: "target_limit"})
	}
	sort.Slice(c.blockers, func(i, j int) bool {
		if c.blockers[i].Ordinal == c.blockers[j].Ordinal {
			return c.blockers[i].Code < c.blockers[j].Code
		}
		return c.blockers[i].Ordinal < c.blockers[j].Ordinal
	})
	if limited {
		return c, ErrExactLimit
	}
	if len(c.blockers) != 0 {
		return c, ErrNotExact
	}
	records := make([]recordset.Record, len(rows))
	ordinals := make(map[exactKey]int, len(rows))
	for i, row := range rows {
		records[i] = row.record
		ordinals[exactKey{row.record.Name, row.record.Type}] = row.entry.Ordinal
	}
	sealed, err := recordset.New(rulesetID, validationLineage, 1, records)
	if err != nil {
		if errors.Is(err, recordset.ErrLimit) {
			c.blockers = []CompileBlocker{{Code: "target_limit"}}
			return c, ErrExactLimit
		}
		return c, ErrExactValidation
	}
	c.sealed = sealed
	for _, r := range sealed.Records() {
		c.bindings = append(c.bindings, ExactBinding{ordinals[exactKey{r.Name, r.Type}], r.Name, r.Type})
	}
	return c, nil
}
