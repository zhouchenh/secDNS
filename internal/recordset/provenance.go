package recordset

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"unicode/utf8"
)

const RouterOSExactExplicitProfile = "secdns.routeros-exact-explicit.v1"
const MaxOperatorSuppliedProvenanceBytes = 512

// OperatorSuppliedProvenance is an operator assertion about a submitted exact
// candidate. ContentSHA256 can be checked against the candidate; Profile and
// SourceSHA256 are not source authenticity proofs.
type OperatorSuppliedProvenance struct {
	profile, sourceSHA256, contentSHA256 string
}

type operatorSuppliedProvenanceWire struct {
	Profile       string `json:"profile"`
	SourceSHA256  string `json:"source_sha256"`
	ContentSHA256 string `json:"content_sha256"`
}

func validSHA256(s string) bool {
	if len(s) != 64 || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func NewOperatorSuppliedProvenance(profile, sourceSHA256, contentSHA256 string) (OperatorSuppliedProvenance, error) {
	p := OperatorSuppliedProvenance{profile, sourceSHA256, contentSHA256}
	if !p.Valid() {
		return OperatorSuppliedProvenance{}, ErrInvalid
	}
	return p, nil
}

func (p OperatorSuppliedProvenance) Valid() bool {
	return p.profile == RouterOSExactExplicitProfile && validSHA256(p.sourceSHA256) && validSHA256(p.contentSHA256)
}

func (p OperatorSuppliedProvenance) Profile() string       { return p.profile }
func (p OperatorSuppliedProvenance) SourceSHA256() string  { return p.sourceSHA256 }
func (p OperatorSuppliedProvenance) ContentSHA256() string { return p.contentSHA256 }

func (p OperatorSuppliedProvenance) MarshalJSON() ([]byte, error) {
	if !p.Valid() {
		return nil, ErrInvalid
	}
	return json.Marshal(operatorSuppliedProvenanceWire{p.profile, p.sourceSHA256, p.contentSHA256})
}

func ParseOperatorSuppliedProvenance(raw []byte) (OperatorSuppliedProvenance, error) {
	if len(raw) == 0 || len(raw) > MaxOperatorSuppliedProvenanceBytes || !utf8.Valid(raw) || !validUnicodeEscapes(raw) {
		return OperatorSuppliedProvenance{}, ErrInvalid
	}
	fields, err := object(raw, []string{"profile", "source_sha256", "content_sha256"}, nil)
	if err != nil {
		return OperatorSuppliedProvenance{}, err
	}
	var wire operatorSuppliedProvenanceWire
	if json.Unmarshal(raw, &wire) != nil {
		return OperatorSuppliedProvenance{}, ErrInvalid
	}
	p, err := NewOperatorSuppliedProvenance(wire.Profile, wire.SourceSHA256, wire.ContentSHA256)
	if err != nil {
		return OperatorSuppliedProvenance{}, err
	}
	canonical, _ := p.MarshalJSON()
	if len(canonical) > MaxOperatorSuppliedProvenanceBytes || len(fields) != 3 {
		return OperatorSuppliedProvenance{}, ErrInvalid
	}
	return p, nil
}
