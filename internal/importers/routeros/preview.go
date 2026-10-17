// Package routeros previews a deliberately restricted DNS-static export grammar.
// It never executes input and has no store, network, or mutation dependency.
package routeros

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	MaxInputBytes       = 1 << 20
	MaxEntries          = 4096
	MaxValueBytes       = 16 << 10
	MaxLogicalLineBytes = 64 << 10
)

// Diagnostic intentionally reports fixed categories, never arbitrary input text.
type Diagnostic struct {
	Line   int    `json:"line"`
	Column int    `json:"column"`
	Code   string `json:"code"`
}

type Entry struct {
	Ordinal int `json:"ordinal"`
	Line    int `json:"line"`
	// Fields retains decoded literal values, including unsupported and disabled entries.
	Fields         map[string]string `json:"fields"`
	Classification string            `json:"classification"`
	Diagnostics    []Diagnostic      `json:"diagnostics,omitempty"`
}

type Preview struct {
	SourceSHA256 string       `json:"source_sha256"`
	Entries      []Entry      `json:"entries"`
	Diagnostics  []Diagnostic `json:"diagnostics,omitempty"`
	// CanApply is always false: this package neither compiles a complete ruleset nor applies it.
	CanApply bool `json:"can_apply"`
}

type ParseError struct{ Diagnostic }

func (e *ParseError) Error() string {
	return fmt.Sprintf("RouterOS export line %d column %d: %s", e.Line, e.Column, e.Code)
}

// Parse returns no preview on a syntax failure, avoiding accidental partial imports.
// Semantic limitations are retained as diagnostics on a complete data-only preview.
func Parse(reader io.Reader) (*Preview, error) {
	data, err := io.ReadAll(io.LimitReader(reader, MaxInputBytes+1))
	if err != nil {
		return nil, &ParseError{Diagnostic{1, 1, "input_read_failed"}}
	}
	if len(data) > MaxInputBytes {
		return nil, &ParseError{Diagnostic{1, 1, "input_limit"}}
	}
	if !utf8.Valid(data) || strings.IndexByte(string(data), 0) >= 0 {
		return nil, &ParseError{Diagnostic{1, 1, "invalid_text"}}
	}
	hash := sha256.Sum256(data)
	p := &Preview{SourceSHA256: hex.EncodeToString(hash[:]), Entries: []Entry{}}
	l := lexer{data: strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\r", "\n"), line: 1, column: 1}
	section := false
	for {
		tokens, line, err := l.command()
		if err != nil {
			return nil, err
		}
		if tokens == nil {
			break
		}
		if len(tokens) == 0 {
			continue
		}
		if strings.Join(tokens, " ") == "/ip dns static" || (len(tokens) == 1 && tokens[0] == "/ip/dns/static") {
			section = true
			continue
		}
		if !section {
			return nil, &ParseError{Diagnostic{line, 1, "dns_static_section_required"}}
		}
		if tokens[0] != "add" {
			return nil, &ParseError{Diagnostic{line, 1, "unsupported_command"}}
		}
		if len(p.Entries) >= MaxEntries {
			return nil, &ParseError{Diagnostic{line, 1, "entry_limit"}}
		}
		e := Entry{Ordinal: len(p.Entries) + 1, Line: line, Fields: map[string]string{}, Classification: "unsupported"}
		for _, token := range tokens[1:] {
			key, value, ok := strings.Cut(token, "=")
			if !ok || !validKey(key) {
				return nil, &ParseError{Diagnostic{line, 1, "invalid_property"}}
			}
			if _, exists := e.Fields[key]; exists {
				return nil, &ParseError{Diagnostic{line, 1, "duplicate_property"}}
			}
			if !allowedProperty(key) {
				return nil, &ParseError{Diagnostic{line, 1, "unknown_property"}}
			}
			if !utf8.ValidString(value) || strings.IndexByte(value, 0) >= 0 {
				return nil, &ParseError{Diagnostic{line, 1, "invalid_decoded_text"}}
			}
			e.Fields[key] = value
		}
		classify(&e)
		p.Entries = append(p.Entries, e)
	}
	if !section {
		return nil, &ParseError{Diagnostic{1, 1, "dns_static_section_required"}}
	}
	p.Diagnostics = append(p.Diagnostics, Diagnostic{0, 0, "preview_only_no_apply"})
	return p, nil
}

func validKey(key string) bool {
	if key == "" {
		return false
	}
	for _, c := range key {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func classify(e *Entry) {
	add := func(code string) { e.Diagnostics = append(e.Diagnostics, Diagnostic{e.Line, 1, code}) }
	known := map[string]bool{"name": true, "address": true, "cname": true, "type": true, "ttl": true, "disabled": true, "comment": true, "regexp": true, "match-subdomain": true, "forward-to": true}
	keys := make([]string, 0, len(e.Fields))
	for key := range e.Fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if !known[key] {
			add("unsupported_property")
		}
	}
	for _, key := range []string{"disabled", "match-subdomain"} {
		if v, ok := e.Fields[key]; ok && v != "yes" && v != "no" {
			add("invalid_boolean")
		}
	}
	if value, ok := e.Fields["ttl"]; ok {
		if _, err := TTLSeconds(value); err != nil {
			add("unsupported_ttl")
		}
	} else {
		add("omitted_ttl_requires_source_defaults")
	}
	if e.Fields["regexp"] != "" {
		add("regexp_semantics_not_compiled")
	}
	if e.Fields["match-subdomain"] == "yes" {
		add("subdomain_semantics_not_compiled")
	}
	for _, key := range []string{"disabled", "match-subdomain"} {
		if _, ok := e.Fields[key]; !ok {
			add("omitted_" + strings.ReplaceAll(key, "-", "_") + "_requires_source_defaults")
		}
	}
	typ, explicit := e.Fields["type"]
	if !explicit {
		add("omitted_type_requires_source_defaults")
	}
	allowedForType := map[string]map[string]bool{
		"A": {"address": true}, "AAAA": {"address": true}, "CNAME": {"cname": true},
	}
	if dataFields, ok := allowedForType[typ]; ok {
		for _, key := range []string{"address", "cname", "forward-to", "text", "mx-exchange", "mx-preference", "ns", "srv-port", "srv-target", "srv-priority", "srv-weight"} {
			if _, exists := e.Fields[key]; exists && !dataFields[key] {
				add("conflicting_record_fields")
			}
		}
	}
	switch typ {
	case "A", "AAAA":
		ip := net.ParseIP(e.Fields["address"])
		if ip == nil || (typ == "A") != (ip.To4() != nil) {
			add("invalid_address_family")
		}
		if e.Fields["name"] == "" && e.Fields["regexp"] == "" {
			add("missing_match")
		}
		if len(e.Diagnostics) == 0 {
			e.Classification = "exact_record_candidate"
		}
	case "CNAME":
		if e.Fields["name"] == "" || e.Fields["cname"] == "" {
			add("missing_cname_fields")
		}
		if len(e.Diagnostics) == 0 {
			e.Classification = "exact_record_candidate"
		}
	case "FWD":
		add("forward_semantics_not_compiled")
	case "NXDOMAIN":
		add("negative_semantics_not_compiled")
	default:
		add("unsupported_record_type")
	}
	if e.Fields["disabled"] == "yes" {
		add("disabled_entry_retained")
	}
}

// TTLSeconds accepts integer s/m/h/d/w components or an integer seconds literal.
// Other formats are retained but diagnosed, never rounded or silently defaulted.
func TTLSeconds(value string) (uint32, error) {
	if value == "" {
		return 0, fmt.Errorf("empty TTL")
	}
	var total uint64
	units := map[byte]uint64{'s': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 604800}
	last := uint64(^uint64(0))
	for i := 0; i < len(value); {
		start := i
		for i < len(value) && value[i] >= '0' && value[i] <= '9' {
			i++
		}
		if i == start {
			return 0, fmt.Errorf("invalid TTL")
		}
		n, err := strconv.ParseUint(value[start:i], 10, 32)
		if err != nil {
			return 0, fmt.Errorf("TTL overflow")
		}
		mult := uint64(1)
		if i < len(value) {
			var ok bool
			mult, ok = units[value[i]]
			if !ok {
				return 0, fmt.Errorf("unsupported TTL unit")
			}
			i++
		} else if start != 0 {
			return 0, fmt.Errorf("missing TTL unit")
		}
		if mult >= last {
			return 0, fmt.Errorf("unordered TTL units")
		}
		last = mult
		if n > (uint64(^uint32(0))-total)/mult {
			return 0, fmt.Errorf("TTL overflow")
		}
		total += n * mult
	}
	return uint32(total), nil
}

func allowedProperty(key string) bool {
	switch key {
	case "name", "address", "cname", "type", "ttl", "disabled", "comment", "regexp", "match-subdomain", "forward-to", "address-list", "mx-exchange", "mx-preference", "ns", "srv-port", "srv-priority", "srv-target", "srv-weight", "text":
		return true
	}
	return false
}
