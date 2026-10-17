package server

import "github.com/zhouchenh/secDNS/pkg/upstream/resolver"

// Binding selects a resolver while retaining the server's normal transport handler.
// Configuration construction validates the selection before any listener starts.
type Binding struct {
	Server
	Resolver resolver.Resolver
}
