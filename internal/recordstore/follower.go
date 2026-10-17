package recordstore

import (
	"database/sql"
	"errors"
	"github.com/zhouchenh/secDNS/internal/recordset"
	"sync"
	"sync/atomic"
	"time"
)

const FollowerExactRecords = "exact-records"

var (
	ErrFollowerInput        = errors.New("invalid follower input")
	ErrFollowerLimit        = errors.New("follower envelope limit exceeded")
	ErrFollowerIdentity     = errors.New("follower enrollment mismatch")
	ErrFollowerRollback     = errors.New("follower revision rollback")
	ErrFollowerEquivocation = errors.New("follower revision equivocation")
	ErrFollowerNotReady     = errors.New("follower snapshot not ready")
	ErrFollowerStorage      = errors.New("follower storage failure")
	ErrFollowerSchema       = errors.New("unsupported or inconsistent follower schema")
	ErrFollowerExists       = errors.New("follower database already exists")
	ErrFollowerFaulted      = errors.New("follower storage state uncertain")
)

// FollowerEnrollment pins storage identity. Assertions passed to Accept are not
// authenticated principals; an external trust adapter must authorize the sender.
type FollowerEnrollment struct{ ClusterID, Kind, RulesetID, LineageID, AuthorityEpoch string }
type FollowerState struct {
	Enrollment FollowerEnrollment
	Snapshot   recordset.Metadata
}
type FollowerAcceptance struct {
	Outcome string
	State   FollowerState
}

const (
	followerEmpty = iota
	followerReady
	followerFaulted
	followerClosed
)

type followerPublication struct {
	status   int
	snapshot *recordset.Snapshot
	envelope []byte
}
type followerHooks struct {
	beforeCommit func(*sql.Tx) error
	afterCommit  func()
}

// FollowerStore retains a single authority generation. It is not registered,
// network-accessible, a writer, or an authenticated replication protocol.
type FollowerStore struct {
	mu         sync.Mutex
	enrollment FollowerEnrollment
	current    atomic.Pointer[followerPublication]
	db         *sql.DB
	now        func() time.Time
	hooks      followerHooks
	closeErr   error
}

// FollowerView owns a reference to one immutable generation and expiry instant.
// All returned content is copied; a held view survives replacement and Close.
type FollowerView struct {
	enrollment  FollowerEnrollment
	publication *followerPublication
	at          time.Time
}

func (v FollowerView) State() FollowerState {
	return FollowerState{v.enrollment, v.publication.snapshot.Metadata()}
}
func (v FollowerView) CapturedAt() time.Time           { return v.at }
func (v FollowerView) Records() []recordset.Record     { return v.publication.snapshot.Records() }
func (v FollowerView) LiveRecords() []recordset.Record { return v.publication.snapshot.RecordsAt(v.at) }
func (v FollowerView) Lookup(name, typ string) (recordset.Record, bool) {
	return v.publication.snapshot.Lookup(name, typ, v.at)
}

// EnvelopeJSON returns the unsigned canonical envelope, not an identity manifest.
func (v FollowerView) EnvelopeJSON() []byte { return append([]byte(nil), v.publication.envelope...) }
func validFollowerEnrollment(e FollowerEnrollment) bool {
	return e.Kind == FollowerExactRecords && validOperationID(e.ClusterID) && validOperationID(e.RulesetID) && validOperationID(e.LineageID) && validOperationID(e.AuthorityEpoch)
}
func NewFollowerMemory(e FollowerEnrollment) (*FollowerStore, error) {
	if !validFollowerEnrollment(e) {
		return nil, ErrFollowerInput
	}
	s := &FollowerStore{enrollment: e, now: time.Now}
	s.current.Store(&followerPublication{status: followerEmpty})
	return s, nil
}
func (s *FollowerStore) Acquire() (FollowerView, error) {
	p := s.current.Load()
	switch p.status {
	case followerClosed:
		return FollowerView{}, ErrClosed
	case followerFaulted:
		return FollowerView{}, ErrFollowerFaulted
	case followerEmpty:
		return FollowerView{}, ErrFollowerNotReady
	}
	return FollowerView{s.enrollment, p, s.now()}, nil
}
func (s *FollowerStore) Accept(asserted FollowerEnrollment, raw []byte) (FollowerAcceptance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.current.Load()
	if current.status == followerClosed {
		return FollowerAcceptance{}, ErrClosed
	}
	if current.status == followerFaulted {
		return FollowerAcceptance{}, ErrFollowerFaulted
	}
	if !validFollowerEnrollment(asserted) {
		return FollowerAcceptance{}, ErrFollowerInput
	}
	if len(raw) > recordset.MaxBytes {
		return FollowerAcceptance{}, ErrFollowerLimit
	}
	if asserted != s.enrollment {
		return FollowerAcceptance{}, ErrFollowerIdentity
	}
	owned := append([]byte(nil), raw...)
	snapshot, e := recordset.Parse(owned)
	if e != nil {
		if errors.Is(e, recordset.ErrLimit) {
			return FollowerAcceptance{}, ErrFollowerLimit
		}
		return FollowerAcceptance{}, ErrFollowerInput
	}
	meta := snapshot.Metadata()
	if meta.RulesetID != asserted.RulesetID || meta.LineageID != asserted.LineageID {
		return FollowerAcceptance{}, ErrFollowerIdentity
	}
	wire, e := snapshot.MarshalJSON()
	if e != nil {
		return FollowerAcceptance{}, ErrFollowerInput
	}
	if len(wire) > recordset.MaxBytes {
		return FollowerAcceptance{}, ErrFollowerLimit
	}
	outcome := "initial"
	if current.status == followerReady {
		old := current.snapshot.Metadata()
		if meta.Revision < old.Revision {
			return FollowerAcceptance{}, ErrFollowerRollback
		}
		if meta.Revision == old.Revision {
			if meta.ContentSHA256 != old.ContentSHA256 {
				return FollowerAcceptance{}, ErrFollowerEquivocation
			}
			return FollowerAcceptance{"unchanged", FollowerState{s.enrollment, old}}, nil
		}
		outcome = "advanced"
	}
	next := &followerPublication{status: followerReady, snapshot: snapshot, envelope: wire}
	if s.db != nil {
		if e = s.persistFollower(current, next); e != nil {
			return FollowerAcceptance{}, e
		}
	}
	if s.hooks.afterCommit != nil {
		s.hooks.afterCommit()
	}
	s.current.Store(next)
	return FollowerAcceptance{outcome, FollowerState{s.enrollment, meta}}, nil
}
func (s *FollowerStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current.Load().status == followerClosed {
		return s.closeErr
	}
	s.current.Store(&followerPublication{status: followerClosed})
	if s.db != nil {
		if e := s.db.Close(); e != nil {
			s.closeErr = ErrFollowerStorage
		}
	}
	return s.closeErr
}
