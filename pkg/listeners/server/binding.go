package server

import (
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
	"net/netip"
	"time"
)

// PeerResolver selects one already constructed resolver for a direct socket
// peer. Implementations must not perform I/O or consult mutable request data.
type PeerResolver interface {
	ResolverFor(peer netip.Addr, now time.Time) (resolver.Resolver, error)
	ResolverDependencies() []resolver.Resolver
}

// Binding selects a resolver while retaining the server's normal transport handler.
// Configuration construction validates the selection before any listener starts.
type Binding struct {
	Server
	Resolver     resolver.Resolver
	PeerResolver PeerResolver
}
