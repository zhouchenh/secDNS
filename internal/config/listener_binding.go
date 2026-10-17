package config

import (
	"errors"
	named "github.com/zhouchenh/secDNS/internal/config/named/resolver"
	"reflect"

	"github.com/zhouchenh/secDNS/internal/upstream/resolvers/address"
	"github.com/zhouchenh/secDNS/internal/upstream/resolvers/authoritative"
	"github.com/zhouchenh/secDNS/internal/upstream/resolvers/nameserver"
	noanswer "github.com/zhouchenh/secDNS/internal/upstream/resolvers/no/answer/resolver"
	notexist "github.com/zhouchenh/secDNS/internal/upstream/resolvers/not/exist/resolver"
	"github.com/zhouchenh/secDNS/internal/upstream/resolvers/policy"
	"github.com/zhouchenh/secDNS/internal/upstream/resolvers/recursive"
	"github.com/zhouchenh/secDNS/pkg/listeners/server"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
)

var ErrListenerBinding = errors.New("config: invalid listener resolver selection")
var ErrResolverCycle = errors.New("config: cyclic resolver graph is unsupported for listener selection or policy (including recursive aliases)")
var ErrOpaqueResolver = errors.New("config: unsupported resolver dependency shape")
var ErrResolverGraphLimit = errors.New("config: resolver dependency graph limit exceeded")

// Called inside the loader transaction; restores the registry callback cleared
// by Config.Descriptor for the duration of selector construction,
// but before named references are initialized. It never starts a server.
func bindListeners(raw interface{}, config *Config) (bool, error) {
	named.SetNameRegistryAssignmentFunction(func(interface{}) (interface{}, bool) { return config.Resolvers, true })
	defer named.SetNameRegistryAssignmentFunction(nil)
	root, ok := raw.(map[string]interface{})
	if !ok {
		return false, ErrListenerBinding
	}
	enabled := false
	if groups, ok := root["resolvers"].(map[string]interface{}); ok {
		if rawPolicies, present := groups["policy"]; present {
			policies, ok := rawPolicies.(map[string]interface{})
			if !ok {
				return false, ErrListenerBinding
			}
			for name := range policies {
				r, ok := config.Resolvers.Lookup(name)
				if !ok {
					return false, ErrListenerBinding
				}
				if _, ok := r.(*policy.Policy); !ok {
					return false, ErrListenerBinding
				}
			}
			enabled = true
		}
	}
	entries, array := root["listeners"].([]interface{})
	selectionPresent := false
	for _, entry := range entries {
		if m, ok := entry.(map[string]interface{}); ok {
			if _, present := m["resolver"]; present {
				selectionPresent = true
			}
		}
	}
	// Legacy descriptors retain their own permissive behavior when the new
	// listener binding feature is absent. Policy graph validation happens later.
	if !selectionPresent {
		return enabled, nil
	}
	if !array || len(entries) != len(config.Listeners) {
		return false, ErrListenerBinding
	}
	for index, entry := range entries {
		m, ok := entry.(map[string]interface{})
		if !ok {
			return false, ErrListenerBinding
		}
		selection, present := m["resolver"]
		if !present {
			continue
		}
		enabled = true
		kind, _ := m["type"].(string)
		if kind != "dnsServer" && kind != "httpAPIServer" {
			return false, ErrListenerBinding
		}
		value, s, f := resolver.Descriptor().Describe(selection)
		if s < 1 || f > 0 {
			return false, ErrListenerBinding
		}
		r, ok := value.(resolver.Resolver)
		if !ok || r == nil {
			return false, ErrListenerBinding
		}
		config.Listeners[index] = &server.Binding{Server: config.Listeners[index], Resolver: r}
	}
	return enabled, nil
}

// Detection is iterative and visits each constructed pointer once. A bounded
// validation walk follows if a policy exists; exhaustion must never hide one.
func containsPolicyGraph(roots []resolver.Resolver) bool {
	seen := map[resolver.Resolver]bool{}
	pending := append([]resolver.Resolver(nil), roots...)
	for len(pending) > 0 {
		r := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if r == nil {
			continue
		}
		v := reflect.ValueOf(r)
		if v.Kind() != reflect.Ptr || v.IsNil() || seen[r] {
			continue
		}
		seen[r] = true
		if _, ok := r.(*policy.Policy); ok {
			return true
		}
		if d, ok := r.(resolver.DependencyProvider); ok {
			pending = append(pending, d.ResolverDependencies()...)
		}
	}
	return false
}

func validateResolverGraph(roots []resolver.Resolver) error {
	state := map[resolver.Resolver]uint8{}
	var visit func(resolver.Resolver, int) error
	visit = func(r resolver.Resolver, depth int) error {
		if r == nil {
			return ErrOpaqueResolver
		}
		value := reflect.ValueOf(r)
		if value.Kind() != reflect.Ptr || value.IsNil() {
			return ErrOpaqueResolver
		}
		if depth > 256 {
			return ErrResolverGraphLimit
		}
		if state[r] == 1 {
			return ErrResolverCycle
		}
		if state[r] == 2 {
			return nil
		}
		if len(state) >= 4096 {
			return ErrResolverGraphLimit
		}
		state[r] = 1
		if node, ok := r.(resolver.DependencyProvider); ok {
			for _, child := range node.ResolverDependencies() {
				if err := visit(child, depth+1); err != nil {
					return err
				}
			}
		} else {
			switch r.(type) {
			case *address.Address, *authoritative.Authoritative, *nameserver.NameServer, *noanswer.NoAnswerResolver, *notexist.NotExistResolver, *recursive.Recursive:
			default:
				return ErrOpaqueResolver
			}
		}
		state[r] = 2
		return nil
	}
	for _, r := range roots {
		if err := visit(r, 0); err != nil {
			return err
		}
	}
	return nil
}
