package resolver

import "github.com/zhouchenh/secDNS/pkg/upstream/resolver"

type NameRegistry struct {
	registry map[string]resolver.Resolver
}

func (nr *NameRegistry) NameResolver(name string, r resolver.Resolver) error {
	if nr == nil {
		return ErrNilNameRegistry
	}
	if nr.registry == nil {
		nr.registry = make(map[string]resolver.Resolver)
	}
	if _, hasKey := nr.registry[name]; hasKey {
		return AlreadyExistedError(name)
	}
	nr.registry[name] = r
	return nil
}

// Names returns the list of registered resolver names.
func (nr *NameRegistry) Names() []string {
	if nr == nil || nr.registry == nil {
		return nil
	}
	names := make([]string, 0, len(nr.registry))
	for name := range nr.registry {
		if name == "" {
			continue
		}
		names = append(names, name)
	}
	return names
}
