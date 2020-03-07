package resolver

import "upstream/resolver"

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
