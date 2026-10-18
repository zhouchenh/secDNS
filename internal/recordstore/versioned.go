package recordstore

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zhouchenh/secDNS/internal/recordset"
)

const MaxOperationReceipts = 10000

var ErrRevisionConflict = errors.New("exact store revision conflict")
var ErrIdentity = errors.New("exact store identity mismatch")
var ErrOperationConflict = errors.New("exact store operation conflict")
var ErrReceiptCapacity = errors.New("exact store receipt capacity reached")
var ErrRevisionOverflow = errors.New("exact store revision exhausted")
var ErrVersionedSchema = errors.New("unsupported or inconsistent exact store schema")
var ErrMigrationRequired = errors.New("explicit exact store migration required")
var ErrOperatorProvenanceUnavailable = errors.New("operator-supplied provenance is unavailable for this exact store schema")
var ErrVersionedStorage = errors.New("exact store storage failure")
var ErrVersionedInput = errors.New("invalid exact store input")

type Enrollment struct {
	RulesetID, LineageID                         string
	AllowSchema1Migration, AllowSchema2Migration bool
}
type Expected struct {
	RulesetID, LineageID string
	Revision             uint64
}
type Receipt struct {
	OperationID, RequestSHA256    string
	Revision                      uint64
	ContentSHA256                 string
	CommittedAt                   time.Time
	operatorSuppliedProvenance    recordset.OperatorSuppliedProvenance
	hasOperatorSuppliedProvenance bool
}

func (r Receipt) OperatorSuppliedProvenance() (recordset.OperatorSuppliedProvenance, bool) {
	return r.operatorSuppliedProvenance, r.hasOperatorSuppliedProvenance
}

type versionedGeneration struct {
	snapshot                      *recordset.Snapshot
	operatorSuppliedProvenance    recordset.OperatorSuppliedProvenance
	hasOperatorSuppliedProvenance bool
}

// View pins one immutable generation and one expiry instant. It remains usable
// after publication of another generation or Close. No resolver is wired here.
type View struct {
	generation *versionedGeneration
	at         time.Time
}

func (v View) Metadata() recordset.Metadata    { return v.generation.snapshot.Metadata() }
func (v View) CapturedAt() time.Time           { return v.at }
func (v View) Records() []recordset.Record     { return v.generation.snapshot.Records() }
func (v View) LiveRecords() []recordset.Record { return v.generation.snapshot.RecordsAt(v.at) }
func (v View) Lookup(name, typ string) (recordset.Record, bool) {
	return v.generation.snapshot.Lookup(name, typ, v.at)
}
func (v View) MarshalJSON() ([]byte, error) { return v.generation.snapshot.MarshalJSON() }
func (v View) OperatorSuppliedProvenance() (recordset.OperatorSuppliedProvenance, bool) {
	return v.generation.operatorSuppliedProvenance, v.generation.hasOperatorSuppliedProvenance
}

type versionedHooks struct {
	beforeCommit func(*sql.Tx) error
	afterCommit  func()
}

// VersionedStore is an opt-in exact snapshot substrate. Legacy Store and its
// configuration/API are unchanged. One process exclusively owns a SQLite file.
type VersionedStore struct {
	mu                     sync.Mutex
	revisionMu             sync.Mutex
	current                atomic.Pointer[versionedGeneration]
	receipts               map[string]Receipt
	revisionSubscribers    map[uint64]*revisionSubscriber
	nextRevisionSubscriber uint64
	db                     *sql.DB
	schemaVersion          int
	now                    func() time.Time
	hooks                  versionedHooks
}

func validOperationID(s string) bool {
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
func NewVersionedMemory(e Enrollment) (*VersionedStore, error) {
	initial, err := recordset.New(e.RulesetID, e.LineageID, 1, nil)
	if err != nil {
		return nil, ErrVersionedInput
	}
	s := &VersionedStore{receipts: map[string]Receipt{}, schemaVersion: 3, now: time.Now}
	s.current.Store(&versionedGeneration{snapshot: initial})
	return s, nil
}

// Acquire linearizes at its atomic pointer load. Close replaces that pointer
// with nil, so calls after Close returns cannot acquire a new view. Calls already
// holding a generation never wait on writer disk I/O and remain valid.
func (s *VersionedStore) Acquire() (View, error) {
	p := s.current.Load()
	if p == nil {
		return View{}, ErrClosed
	}
	return View{p, s.now()}, nil
}
func requestDigest(e Expected, content string) string {
	payload, _ := json.Marshal(struct {
		Kind, RulesetID, LineageID string
		Revision                   uint64 `json:",string"`
		ContentSHA256              string
	}{"replace-exact-v1", e.RulesetID, e.LineageID, e.Revision, content})
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func requestDigestWithOperatorSuppliedProvenance(e Expected, content string, provenance recordset.OperatorSuppliedProvenance) string {
	payload, _ := json.Marshal(struct {
		Kind, RulesetID, LineageID string
		Revision                   uint64 `json:",string"`
		ContentSHA256              string
		OperatorSuppliedProvenance recordset.OperatorSuppliedProvenance
	}{"replace-exact-with-operator-supplied-provenance-v1", e.RulesetID, e.LineageID, e.Revision, content, provenance})
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func (s *VersionedStore) Replace(expected Expected, operationID string, records []recordset.Record) (Receipt, error) {
	return s.replace(expected, operationID, records, nil)
}

func (s *VersionedStore) ReplaceWithOperatorSuppliedProvenance(expected Expected, operationID string, records []recordset.Record, provenance recordset.OperatorSuppliedProvenance) (Receipt, error) {
	return s.replace(expected, operationID, records, &provenance)
}

func (s *VersionedStore) replace(expected Expected, operationID string, records []recordset.Record, provenance *recordset.OperatorSuppliedProvenance) (Receipt, error) {
	initial := s.current.Load()
	if initial == nil {
		return Receipt{}, ErrClosed
	}
	identity := initial.snapshot.Metadata()
	if expected.RulesetID != identity.RulesetID || expected.LineageID != identity.LineageID {
		return Receipt{}, ErrIdentity
	}
	if !validOperationID(operationID) || expected.Revision == 0 {
		return Receipt{}, ErrVersionedInput
	}
	// New copies every input slice and compiles without consulting the clock.
	candidate, err := recordset.New(expected.RulesetID, expected.LineageID, 1, records)
	if err != nil {
		return Receipt{}, ErrVersionedInput
	}
	request := requestDigest(expected, candidate.Metadata().ContentSHA256)
	if provenance != nil {
		if !provenance.Valid() || provenance.ContentSHA256() != candidate.Metadata().ContentSHA256 {
			return Receipt{}, ErrVersionedInput
		}
		request = requestDigestWithOperatorSuppliedProvenance(expected, candidate.Metadata().ContentSHA256, *provenance)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.current.Load()
	if current == nil {
		return Receipt{}, ErrClosed
	}
	meta := current.snapshot.Metadata()
	if expected.RulesetID != meta.RulesetID || expected.LineageID != meta.LineageID {
		return Receipt{}, ErrIdentity
	}
	if provenance != nil && s.db != nil && s.schemaVersion < 3 {
		return Receipt{}, ErrOperatorProvenanceUnavailable
	}
	if receipt, ok := s.receipts[operationID]; ok {
		if receipt.RequestSHA256 != request {
			return Receipt{}, ErrOperationConflict
		}
		return receipt, nil
	}
	if expected.Revision != meta.Revision {
		return Receipt{}, ErrRevisionConflict
	}
	if meta.Revision == math.MaxUint64 {
		return Receipt{}, ErrRevisionOverflow
	}
	if len(s.receipts) >= MaxOperationReceipts {
		return Receipt{}, ErrReceiptCapacity
	}
	next, err := recordset.New(meta.RulesetID, meta.LineageID, meta.Revision+1, candidate.Records())
	if err != nil {
		return Receipt{}, ErrVersionedInput
	}
	at := s.now().UTC()
	if at.Year() < 1 || at.Year() > 9999 || at.IsZero() {
		return Receipt{}, ErrVersionedInput
	}
	receipt := Receipt{OperationID: operationID, RequestSHA256: request, Revision: next.Metadata().Revision, ContentSHA256: next.Metadata().ContentSHA256, CommittedAt: at}
	generation := &versionedGeneration{snapshot: next}
	if provenance != nil {
		receipt.operatorSuppliedProvenance = *provenance
		receipt.hasOperatorSuppliedProvenance = true
		generation.operatorSuppliedProvenance = *provenance
		generation.hasOperatorSuppliedProvenance = true
	}
	if s.db != nil {
		if err := s.persistReplacement(generation, receipt); err != nil {
			return Receipt{}, ErrVersionedStorage
		}
	} else if s.hooks.beforeCommit != nil {
		if err := s.hooks.beforeCommit(nil); err != nil {
			return Receipt{}, ErrVersionedStorage
		}
	}
	if s.hooks.afterCommit != nil {
		s.hooks.afterCommit()
	}
	s.receipts[operationID] = receipt
	s.revisionMu.Lock()
	s.current.Store(generation)
	s.publishRevisionLocked(generation)
	s.revisionMu.Unlock()
	return receipt, nil
}
func (s *VersionedStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revisionMu.Lock()
	if s.current.Swap(nil) == nil {
		s.revisionMu.Unlock()
		return nil
	}
	for id, subscriber := range s.revisionSubscribers {
		delete(s.revisionSubscribers, id)
		close(subscriber.events)
	}
	s.revisionMu.Unlock()
	if s.db != nil {
		if err := s.db.Close(); err != nil {
			return ErrVersionedStorage
		}
	}
	return nil
}
