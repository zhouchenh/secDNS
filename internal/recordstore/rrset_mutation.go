package recordstore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/zhouchenh/secDNS/internal/recordset"
)

func rrsetRequestDigest(r recordset.RRsetMutation) string {
	payload, _ := json.Marshal(struct {
		Kind, RulesetID, LineageID string
		Revision                   uint64               `json:",string"`
		Record                     *recordset.Record    `json:",omitempty"`
		Key                        *recordset.RecordKey `json:",omitempty"`
	}{r.Action + "-exact-rrset-v1", r.RulesetID, r.LineageID, r.Revision, r.Record, r.Key})
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// MutateRRset applies one canonical edit under the same CAS and durability
// boundary as Replace. Replays never derive a new candidate or emit a hint.
func (s *VersionedStore) MutateRRset(input recordset.RRsetMutation) (Receipt, error) {
	r, err := input.Canonical()
	if err != nil {
		return Receipt{}, ErrVersionedInput
	}
	request := rrsetRequestDigest(r)
	canonical, err := r.CanonicalJSON()
	if err != nil {
		return Receipt{}, ErrVersionedInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.current.Load()
	if current == nil {
		return Receipt{}, ErrClosed
	}
	if s.db != nil && s.schemaVersion < 4 {
		return Receipt{}, ErrRRsetSchemaRequired
	}
	meta := current.snapshot.Metadata()
	if r.RulesetID != meta.RulesetID || r.LineageID != meta.LineageID {
		return Receipt{}, ErrIdentity
	}
	if receipt, ok := s.receipts[r.OperationID]; ok {
		if receipt.RequestSHA256 != request {
			return Receipt{}, ErrOperationConflict
		}
		return receipt, nil
	}
	if r.Revision != meta.Revision {
		return Receipt{}, ErrRevisionConflict
	}
	var key recordset.RecordKey
	if r.Action == "upsert" {
		key = recordset.RecordKey{Name: r.Record.Name, Type: r.Record.Type}
	} else {
		key = *r.Key
	}
	records := current.snapshot.Records()
	kept := make([]recordset.Record, 0, len(records)+1)
	for _, record := range records {
		if record.Name != key.Name || record.Type != key.Type {
			kept = append(kept, record)
		}
	}
	if r.Action == "upsert" {
		kept = append(kept, *r.Record)
	}
	return s.commitLocked(meta, r.OperationID, request, kept, nil, string(canonical))
}

type rrsetReceiptMetadata struct {
	Request       json.RawMessage `json:"request"`
	OutcomeSHA256 string          `json:"outcome_sha256"`
}

const maxRRsetReceiptMetadataBytes = recordset.MaxRRsetRequestBytes + 256

func rrsetOutcomeDigest(request []byte, content string) string {
	wire, _ := json.Marshal(struct {
		Kind          string
		Request       json.RawMessage
		ContentSHA256 string
	}{"exact-rrset-outcome-v1", request, content})
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:])
}
func encodeRRsetReceiptMetadata(request []byte, content string) string {
	wire, _ := json.Marshal(rrsetReceiptMetadata{request, rrsetOutcomeDigest(request, content)})
	return string(wire)
}
func decodeRRsetReceiptMetadata(raw []byte, content string) (recordset.RRsetMutation, error) {
	var stored rrsetReceiptMetadata
	if len(raw) > maxRRsetReceiptMetadataBytes || json.Unmarshal(raw, &stored) != nil {
		return recordset.RRsetMutation{}, ErrVersionedSchema
	}
	mutation, err := recordset.ParseRRsetMutation(stored.Request)
	if err != nil {
		return mutation, ErrVersionedSchema
	}
	canonical, err := mutation.CanonicalJSON()
	if err != nil || string(raw) != encodeRRsetReceiptMetadata(canonical, content) {
		return mutation, ErrVersionedSchema
	}
	return mutation, nil
}

// SupportsRRsetMutations reports only local writer capability, not authorization.
func (s *VersionedStore) SupportsRRsetMutations() bool {
	// db and schemaVersion are immutable after initialization. Do not block a
	// snapshot read behind a writer's durable commit I/O.
	return s.current.Load() != nil && (s.db == nil || s.schemaVersion >= 4)
}
