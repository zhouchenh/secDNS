package recordstore

import (
	"sync"
	"time"
)

// DefaultName is the store joined when a resolver or admin listener omits a store name,
// so the common single-store config needs no naming.
const DefaultName = "default"

// gcInterval is how often a store's background sweep reclaims expired records. Reads
// already skip expired records, so this only bounds memory; it is a var so tests can
// shorten it.
var gcInterval = 10 * time.Second

var (
	registryMu        sync.Mutex
	registry          = map[string]*Store{}
	versionedRegistry = map[string]*VersionedStore{}
	followerRegistry  = map[string]*FollowerStore{}
)

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
