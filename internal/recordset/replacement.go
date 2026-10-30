package recordset

import (
	"encoding/json"
	"strconv"
	"unicode/utf8"
)

// Replacement is a strict batch request; it nominates an expected generation,
// never the resulting revision. It contains no relative expiry or implicit defaults.
type Replacement struct {
	RulesetID, LineageID, OperationID string
	Revision                          uint64
	Records                           []Record
	operatorSuppliedProvenance        OperatorSuppliedProvenance
	hasOperatorSuppliedProvenance     bool
	confirmRemovals                   int
	hasConfirmRemovals                bool
}

// MaxConfirmRemovals bounds the confirm_removals field; a replacement never removes more
// records than a snapshot may hold.
const MaxConfirmRemovals = 1 << 20

// ConfirmRemovals is the number of records the operator confirmed this replacement removes
// from the expected base (optional field confirm_removals).
func (r Replacement) ConfirmRemovals() (int, bool) { return r.confirmRemovals, r.hasConfirmRemovals }

func (r Replacement) OperatorSuppliedProvenance() (OperatorSuppliedProvenance, bool) {
	return r.operatorSuppliedProvenance, r.hasOperatorSuppliedProvenance
}

func ParseReplacement(raw []byte) (Replacement, error) {
	fail := Replacement{}
	if len(raw) > MaxBytes {
		return fail, ErrLimit
	}
	if !utf8.Valid(raw) || !validUnicodeEscapes(raw) {
		return fail, ErrInvalid
	}
	fields, e := object(raw, []string{"expected", "operation_id", "records"}, []string{"operator_supplied_provenance", "confirm_removals"})
	if e != nil {
		return fail, e
	}
	expected, e := object(fields["expected"], []string{"ruleset_id", "lineage_id", "revision"}, nil)
	if e != nil {
		return fail, e
	}
	var r Replacement
	var revision string
	for k, v := range map[string]*string{"ruleset_id": &r.RulesetID, "lineage_id": &r.LineageID, "revision": &revision} {
		if json.Unmarshal(expected[k], v) != nil {
			return fail, ErrInvalid
		}
	}
	if json.Unmarshal(fields["operation_id"], &r.OperationID) != nil {
		return fail, ErrInvalid
	}
	if len(r.OperationID) == 0 || len(r.OperationID) > 128 {
		return fail, ErrInvalid
	}
	for _, c := range r.OperationID {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return fail, ErrInvalid
		}
	}
	r.Revision, e = strconv.ParseUint(revision, 10, 64)
	if e != nil || r.Revision == 0 || strconv.FormatUint(r.Revision, 10) != revision {
		return fail, ErrInvalid
	}
	r.Records, e = parseRecords(fields["records"])
	if e != nil {
		return fail, e
	}
	snapshot, e := New(r.RulesetID, r.LineageID, r.Revision, r.Records)
	if e != nil {
		return fail, e
	}
	r.Records = snapshot.Records()
	if rawProvenance, ok := fields["operator_supplied_provenance"]; ok {
		r.operatorSuppliedProvenance, e = ParseOperatorSuppliedProvenance(rawProvenance)
		if e != nil || r.operatorSuppliedProvenance.ContentSHA256() != snapshot.Metadata().ContentSHA256 {
			return fail, ErrInvalid
		}
		r.hasOperatorSuppliedProvenance = true
	}
	if rawConfirm, ok := fields["confirm_removals"]; ok {
		// a plain non-negative JSON integer: no sign, fraction, exponent or leading zero
		text := string(rawConfirm)
		if len(text) == 0 || len(text) > 7 || text[0] == '0' && len(text) > 1 {
			return fail, ErrInvalid
		}
		for _, c := range text {
			if c < '0' || c > '9' {
				return fail, ErrInvalid
			}
		}
		n, e := strconv.Atoi(text)
		if e != nil || n > MaxConfirmRemovals {
			return fail, ErrInvalid
		}
		r.confirmRemovals, r.hasConfirmRemovals = n, true
	}
	return r, nil
}
