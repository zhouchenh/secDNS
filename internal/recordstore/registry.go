package recordstore

import (
	"errors"
	"sync"
	"time"

	"github.com/zhouchenh/secDNS/internal/recordset"
)

// DefaultName is the store joined when a resolver or admin listener omits a store name,
// so the common single-store config needs no naming.
const DefaultName = "default"

// gcInterval is how often a store's background sweep reclaims expired records. Reads
// already skip expired records, so this only bounds memory; it is a var so tests can
// shorten it.
var gcInterval = 10 * time.Second

var (
	ErrExactReadBinding = errors.New("exact read store binding unavailable")

	registryMu        sync.Mutex
	registry          = map[string]*Store{}
	versionedRegistry = map[string]*VersionedStore{}
	followerRegistry  = map[string]*FollowerStore{}
)

// ExactView is the immutable read surface shared by writer-versioned and
// enrolled-follower generations. Implementations pin both content and the
// expiry instant used by Lookup.
type ExactView interface {
	CapturedAt() time.Time
	Lookup(name, typ string) (recordset.Record, bool)
}

// GetOrCreate returns the shared store for name, creating it (and starting its
// background GC sweep) on first use. An empty name maps to DefaultName, so a resolver
// and an admin listener that both omit the store name share one store regardless of
// which is configured first. It returns nil for explicitly versioned names;
// production callers use Binding to distinguish modes without a fallback.
func GetOrCreate(name string) *Store {
	if name == "" {
		name = DefaultName
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, reserved := versionedRegistry[name]; reserved {
		return nil
	}
	if _, reserved := followerRegistry[name]; reserved {
		return nil
	}
	if s, ok := registry[name]; ok {
		return s
	}
	s := New()
	registry[name] = s
	s.startGC()
	return s
}

func (s *Store) gcLoop() {
	t := time.NewTicker(gcInterval)
	defer t.Stop()
	defer close(s.done)
	for {
		select {
		case <-t.C:
			s.sweep()
		case <-s.stop:
			return
		}
	}
}

func (s *Store) startGC() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.stop != nil {
		return
	}
	s.stop, s.done = make(chan struct{}), make(chan struct{})
	go s.gcLoop()
}

// Binding resolves a logical name atomically. Closed versioned handles remain
// reserved for process lifetime, so shutdown cannot recreate a legacy store.
func Binding(name string) (*Store, *VersionedStore) {
	if name == "" {
		name = DefaultName
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	if v, ok := versionedRegistry[name]; ok {
		return nil, v
	}
	if _, ok := followerRegistry[name]; ok {
		return nil, nil
	}
	if s := registry[name]; s != nil {
		return s, nil
	}
	s := New()
	registry[name] = s
	s.startGC()
	return s, nil
}

// FollowerBinding resolves a logical name only when startup reserved it as a
// follower store. Closed follower handles remain reserved for process lifetime,
// preventing a shutdown race from silently creating a mutable legacy store.
func FollowerBinding(name string) *FollowerStore {
	if name == "" {
		name = DefaultName
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	return followerRegistry[name]
}

// AcquireExactView resolves only an explicitly prepared writer-versioned or
// enrolled-follower name. It never creates or falls back to a mutable legacy
// store; closed tombstones remain terminal for the process lifetime.
func AcquireExactView(name string) (ExactView, error) {
	if name == "" {
		name = DefaultName
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	if registry[name] != nil {
		return nil, ErrExactReadBinding
	}
	if versioned := versionedRegistry[name]; versioned != nil {
		return versioned.Acquire()
	}
	if follower := followerRegistry[name]; follower != nil {
		return follower.Acquire()
	}
	return nil, ErrExactReadBinding
}
