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
	registryMu sync.Mutex
	registry   = map[string]*Store{}
)

// GetOrCreate returns the shared store for name, creating it (and starting its
// background GC sweep) on first use. An empty name maps to DefaultName, so a resolver
// and an admin listener that both omit the store name share one store regardless of
// which is configured first.
func GetOrCreate(name string) *Store {
	if name == "" {
		name = DefaultName
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	if s, ok := registry[name]; ok {
		return s
	}
	s := New()
	registry[name] = s
	go s.gcLoop()
	return s
}

func (s *Store) gcLoop() {
	t := time.NewTicker(gcInterval)
	defer t.Stop()
	for range t.C {
		s.sweep()
	}
}
