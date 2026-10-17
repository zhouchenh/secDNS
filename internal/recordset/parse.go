package recordset

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// object accepts exact field spellings only and rejects duplicates, unknowns,
// null required fields and trailing values. No last-key-wins interpretation.
func object(raw []byte, required, optional []string) (map[string]json.RawMessage, error) {
	allowed := map[string]bool{}
	for _, k := range append(append([]string{}, required...), optional...) {
		allowed[k] = true
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return nil, ErrInvalid
	}
	out := map[string]json.RawMessage{}
	for d.More() {
		t, e = d.Token()
		if e != nil {
			return nil, ErrInvalid
		}
		k, ok := t.(string)
		if !ok || !allowed[k] {
			return nil, ErrInvalid
		}
		if _, ok = out[k]; ok {
			return nil, ErrInvalid
		}
		var v json.RawMessage
		if d.Decode(&v) != nil || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return nil, ErrInvalid
		}
		out[k] = v
	}
	if _, e = d.Token(); e != nil {
		return nil, ErrInvalid
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, ErrInvalid
	}
	for _, k := range required {
		if _, ok := out[k]; !ok {
			return nil, ErrInvalid
		}
	}
	return out, nil
}

// Parse validates a complete envelope and verifies its canonical content hash.
// A digest detects content changes; it is not a signature or an authority proof.
func Parse(raw []byte) (*Snapshot, error) {
	if len(raw) > MaxBytes {
		return nil, ErrLimit
	}
	if !utf8.Valid(raw) {
		return nil, ErrInvalid
	}
	if !validUnicodeEscapes(raw) {
		return nil, ErrInvalid
	}
	f, e := object(raw, []string{"schema", "ruleset_id", "lineage_id", "revision", "content_sha256", "records"}, nil)
	if e != nil {
		return nil, e
	}
	var schema, ruleset, lineage, revision, digest string
	for k, p := range map[string]*string{"schema": &schema, "ruleset_id": &ruleset, "lineage_id": &lineage, "revision": &revision, "content_sha256": &digest} {
		if json.Unmarshal(f[k], p) != nil {
			return nil, ErrInvalid
		}
	}
	if schema != Schema || len(revision) == 0 || revision[0] == '0' {
		return nil, ErrInvalid
	}
	rev, e := strconv.ParseUint(revision, 10, 64)
	if e != nil || strconv.FormatUint(rev, 10) != revision {
		return nil, ErrInvalid
	}
	if len(digest) != 64 || strings.ToLower(digest) != digest {
		return nil, ErrDigest
	}
	records, e := parseRecords(f["records"])
	if e != nil {
		return nil, e
	}
	s, e := New(ruleset, lineage, rev, records)
	if e != nil {
		return nil, e
	}
	if s.metadata.ContentSHA256 != digest {
		return nil, ErrDigest
	}
	return s, nil
}

// encoding/json replaces isolated UTF-16 surrogate escapes with U+FFFD. Reject
// those lossy inputs before decoding; valid pairs and literal U+FFFD remain valid.
func validUnicodeEscapes(raw []byte) bool {
	quoted := false
	hex4 := func(b []byte) (uint16, bool) {
		var n uint16
		for _, c := range b {
			n <<= 4
			switch {
			case c >= '0' && c <= '9':
				n += uint16(c - '0')
			case c >= 'a' && c <= 'f':
				n += uint16(c - 'a' + 10)
			case c >= 'A' && c <= 'F':
				n += uint16(c - 'A' + 10)
			default:
				return 0, false
			}
		}
		return n, true
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			quoted = !quoted
			continue
		}
		if !quoted || raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		n, ok := hex4(raw[i+1 : i+5])
		if !ok {
			return false
		}
		i += 4
		if n >= 0xDC00 && n <= 0xDFFF {
			return false
		}
		if n >= 0xD800 && n <= 0xDBFF {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low, ok := hex4(raw[i+3 : i+7])
			if !ok || low < 0xDC00 || low > 0xDFFF {
				return false
			}
			i += 6
		}
	}
	return true
}

func parseRecords(raw []byte) ([]Record, error) {
	var entries []json.RawMessage
	if json.Unmarshal(raw, &entries) != nil {
		return nil, ErrInvalid
	}
	if len(entries) > MaxRecords {
		return nil, ErrLimit
	}
	records := make([]Record, 0, len(entries))
	for _, rawRecord := range entries {
		fields, e := object(rawRecord, []string{"name", "type", "values", "ttl_seconds"}, []string{"expires_at"})
		if e != nil {
			return nil, e
		}
		var values []json.RawMessage
		if json.Unmarshal(fields["values"], &values) != nil {
			return nil, ErrInvalid
		}
		if len(values) > MaxValues {
			return nil, ErrLimit
		}
		for _, v := range values {
			var text string
			if bytes.Equal(bytes.TrimSpace(v), []byte("null")) || json.Unmarshal(v, &text) != nil {
				return nil, ErrInvalid
			}
		}
		var r Record
		if json.Unmarshal(rawRecord, &r) != nil {
			return nil, ErrInvalid
		}
		records = append(records, r)
	}

	return records, nil
}
