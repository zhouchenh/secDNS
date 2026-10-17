package core

import "github.com/zhouchenh/secDNS/pkg/upstream/resolver"

func (i *instance) ResolverDependencies() []resolver.Resolver {
	i.mapMutex.RLock()
	defer i.mapMutex.RUnlock()
	out := make([]resolver.Resolver, 0, len(i.nameResolverMap)+1)
	out = append(out, i.defaultResolver)
	for _, r := range i.nameResolverMap {
		out = append(out, r)
	}
	return out
}
