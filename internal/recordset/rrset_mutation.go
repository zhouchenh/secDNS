package recordset

import (
	"encoding/json"
	"strconv"
	"strings"
	"unicode/utf8"
)

// RecordKey identifies an exact RRset without inventing record values.
type RecordKey struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// CanonicalKey uses the same owner/type rules as full snapshots.
func CanonicalKey(name, typ string) (string, string, error) {
	name, err := canonicalName(name)
	if err != nil {
		return "", "", err
	}
	typ = strings.ToUpper(strings.TrimSpace(typ))
	switch typ {
	case "A", "AAAA", "CNAME", "TXT":
	default:
		return "", "", ErrInvalid
	}
	return name, typ, nil
}

// RRsetMutation nominates one conditional edit, not a resulting snapshot.
type RRsetMutation struct {
	RulesetID, LineageID, OperationID string
	Revision                          uint64
	Action                            string
	Record                            *Record
	Key                               *RecordKey
}

// Canonical validates a request independently of the current store contents.
func (r RRsetMutation) Canonical() (RRsetMutation, error) {
	if _, err := New(r.RulesetID, r.LineageID, r.Revision, nil); err != nil {
		return RRsetMutation{}, err
	}
	if len(r.OperationID) == 0 || len(r.OperationID) > 128 {
		return RRsetMutation{}, ErrInvalid
	}
	for _, c := range r.OperationID {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return RRsetMutation{}, ErrInvalid
		}
	}
	switch r.Action {
	case "upsert":
		if r.Record == nil || r.Key != nil {
			return RRsetMutation{}, ErrInvalid
		}
		snapshot, err := New(r.RulesetID, r.LineageID, r.Revision, []Record{*r.Record})
		if err != nil {
			return RRsetMutation{}, err
		}
		record := snapshot.Records()[0]
		r.Record = &record
	case "delete":
		if r.Key == nil || r.Record != nil {
			return RRsetMutation{}, ErrInvalid
		}
		name, typ, err := CanonicalKey(r.Key.Name, r.Key.Type)
		if err != nil {
			return RRsetMutation{}, err
		}
		r.Key = &RecordKey{name, typ}
	default:
		return RRsetMutation{}, ErrInvalid
	}
	return r, nil
}

// ParseRRsetMutation rejects ambiguous JSON and cross-action fields.
func ParseRRsetMutation(raw []byte) (RRsetMutation, error) {
	var r RRsetMutation
	if len(raw) > MaxBytes {
		return r, ErrLimit
	}
	if !utf8.Valid(raw) || !validUnicodeEscapes(raw) {
		return r, ErrInvalid
	}
	f, err := object(raw, []string{"expected", "operation_id", "action"}, []string{"record", "key"})
	if err != nil {
		return r, err
	}
	e, err := object(f["expected"], []string{"ruleset_id", "lineage_id", "revision"}, nil)
	if err != nil {
		return r, err
	}
	var rev string
	for k, p := range map[string]*string{"ruleset_id": &r.RulesetID, "lineage_id": &r.LineageID, "revision": &rev} {
		if json.Unmarshal(e[k], p) != nil {
			return r, ErrInvalid
		}
	}
	if json.Unmarshal(f["operation_id"], &r.OperationID) != nil || json.Unmarshal(f["action"], &r.Action) != nil {
		return r, ErrInvalid
	}
	r.Revision, err = strconv.ParseUint(rev, 10, 64)
	if err != nil || strconv.FormatUint(r.Revision, 10) != rev {
		return r, ErrInvalid
	}
	switch r.Action {
	case "upsert":
		if _, ok := f["key"]; ok {
			return r, ErrInvalid
		}
		v, ok := f["record"]
		if !ok {
			return r, ErrInvalid
		}
		records, err := parseRecords(append(append([]byte{'['}, v...), ']'))
		if err != nil || len(records) != 1 {
			return r, ErrInvalid
		}
		r.Record = &records[0]
	case "delete":
		if _, ok := f["record"]; ok {
			return r, ErrInvalid
		}
		v, ok := f["key"]
		if !ok {
			return r, ErrInvalid
		}
		key, err := object(v, []string{"name", "type"}, nil)
		if err != nil {
			return r, err
		}
		r.Key = &RecordKey{}
		if json.Unmarshal(key["name"], &r.Key.Name) != nil || json.Unmarshal(key["type"], &r.Key.Type) != nil {
			return r, ErrInvalid
		}
	default:
		return r, ErrInvalid
	}
	return r.Canonical()
}

// MaxRRsetRequestBytes bounds canonical persisted metadata, not HTTP whitespace.
const MaxRRsetRequestBytes = 128 << 10

// CanonicalJSON retains the complete request needed to verify durable retries.
func (r RRsetMutation) CanonicalJSON() ([]byte, error) {
	r, err := r.Canonical()
	if err != nil {
		return nil, err
	}
	type expected struct {
		RulesetID string `json:"ruleset_id"`
		LineageID string `json:"lineage_id"`
		Revision  uint64 `json:"revision,string"`
	}
	wire, err := json.Marshal(struct {
		Expected    expected   `json:"expected"`
		OperationID string     `json:"operation_id"`
		Action      string     `json:"action"`
		Record      *Record    `json:"record,omitempty"`
		Key         *RecordKey `json:"key,omitempty"`
	}{expected{r.RulesetID, r.LineageID, r.Revision}, r.OperationID, r.Action, r.Record, r.Key})
	if len(wire) > MaxRRsetRequestBytes {
		return nil, ErrLimit
	}
	return wire, err
}
