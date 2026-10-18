package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"sort"
	"time"

	named "github.com/zhouchenh/secDNS/internal/config/named/resolver"
	"github.com/zhouchenh/secDNS/internal/sourcepolicy"
	"github.com/zhouchenh/secDNS/internal/upstream/resolvers/cache"
	"github.com/zhouchenh/secDNS/pkg/listeners/server"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
)

var (
	ErrSourcePolicyConfig      = errors.New("config: invalid source policy")
	ErrSharedSourcePolicyCache = errors.New("config: cache resolver shared by distinct source policies")
)

type sourcePolicyConfig struct {
	SourceSets []sourceSetConfig     `json:"sourceSets"`
	Rules      []sourceRuleConfig    `json:"rules"`
	Defaults   []sourceDefaultConfig `json:"defaults"`
}

type sourceSetConfig struct {
	ID      string               `json:"id"`
	Members []sourceMemberConfig `json:"members"`
}

type sourceMemberConfig struct {
	Prefix    string          `json:"prefix"`
	ExpiresAt json.RawMessage `json:"expiresAt,omitempty"`
}

type sourceRuleConfig struct {
	ListenerRole string `json:"listenerRole"`
	SourceSet    string `json:"sourceSet"`
	Resolver     string `json:"resolver"`
}

type sourceDefaultConfig struct {
	ListenerRole string `json:"listenerRole"`
	Resolver     string `json:"resolver"`
}

type parsedSourcePolicy struct {
	selector    *sourcepolicy.Selector
	resolvers   map[string]resolver.Resolver
	resolverIDs []string
	roles       map[string]struct{}
}

type sourcePeerResolver struct {
	policy *parsedSourcePolicy
	role   string
}

func (s *sourcePeerResolver) ResolverFor(peer netip.Addr, now time.Time) (resolver.Resolver, error) {
	if s == nil || s.policy == nil || !peer.IsValid() || peer.Zone() != "" {
		return nil, server.ErrPeerUnavailable
	}
	decision, err := s.policy.selector.Select(s.role, peer.Unmap(), now)
	if err != nil {
		return nil, err
	}
	selected, ok := s.policy.resolvers[decision.ResolverPolicyID]
	if !ok || selected == nil {
		return nil, server.ErrResolverSelection
	}
	return selected, nil
}

func (s *sourcePeerResolver) ResolverDependencies() []resolver.Resolver {
	if s == nil || s.policy == nil {
		return nil
	}
	out := make([]resolver.Resolver, 0, len(s.policy.resolverIDs))
	for _, id := range s.policy.resolverIDs {
		out = append(out, s.policy.resolvers[id])
	}
	return out
}

func parseSourcePolicy(raw interface{}, registry *named.NameRegistry) (*parsedSourcePolicy, error) {
	if registry == nil {
		return nil, ErrSourcePolicyConfig
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil, ErrSourcePolicyConfig
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var input sourcePolicyConfig
	if err := decoder.Decode(&input); err != nil {
		return nil, ErrSourcePolicyConfig
	}
	if err := decoder.Decode(new(interface{})); err != io.EOF {
		return nil, ErrSourcePolicyConfig
	}

	definition := sourcepolicy.Definition{
		SourceSets: make([]sourcepolicy.SourceSet, 0, len(input.SourceSets)),
		Rules:      make([]sourcepolicy.Rule, 0, len(input.Rules)),
		Defaults:   make([]sourcepolicy.RoleDefault, 0, len(input.Defaults)),
	}
	for _, sourceSet := range input.SourceSets {
		converted := sourcepolicy.SourceSet{ID: sourceSet.ID, Members: make([]sourcepolicy.Member, 0, len(sourceSet.Members))}
		for _, member := range sourceSet.Members {
			prefix, err := netip.ParsePrefix(member.Prefix)
			if err != nil {
				return nil, ErrSourcePolicyConfig
			}
			var expiry time.Time
			if len(member.ExpiresAt) != 0 {
				var expiryText string
				if err := json.Unmarshal(member.ExpiresAt, &expiryText); err != nil || expiryText == "" {
					return nil, ErrSourcePolicyConfig
				}
				expiry, err = time.Parse(time.RFC3339Nano, expiryText)
				if err != nil {
					return nil, ErrSourcePolicyConfig
				}
			}
			converted.Members = append(converted.Members, sourcepolicy.Member{Prefix: prefix, ExpiresAt: expiry})
		}
		definition.SourceSets = append(definition.SourceSets, converted)
	}

	resolverNames := make(map[string]struct{})
	roles := make(map[string]struct{}, len(input.Defaults))
	for _, rule := range input.Rules {
		definition.Rules = append(definition.Rules, sourcepolicy.Rule{
			ListenerRole: rule.ListenerRole, SourceSetID: rule.SourceSet, ResolverPolicyID: rule.Resolver,
		})
		resolverNames[rule.Resolver] = struct{}{}
	}
	for _, fallback := range input.Defaults {
		definition.Defaults = append(definition.Defaults, sourcepolicy.RoleDefault{
			ListenerRole: fallback.ListenerRole, ResolverPolicyID: fallback.Resolver,
		})
		resolverNames[fallback.Resolver] = struct{}{}
		roles[fallback.ListenerRole] = struct{}{}
	}

	resolverIDs := make([]string, 0, len(resolverNames))
	for name := range resolverNames {
		resolverIDs = append(resolverIDs, name)
	}
	sort.Strings(resolverIDs)
	definition.ResolverPolicyIDs = append([]string(nil), resolverIDs...)
	selector, err := sourcepolicy.Compile(definition)
	if err != nil {
		return nil, errors.Join(ErrSourcePolicyConfig, err)
	}
	resolvers := make(map[string]resolver.Resolver, len(resolverIDs))
	for _, name := range resolverIDs {
		resolved, ok := registry.Lookup(name)
		if !ok || resolved == nil {
			return nil, ErrSourcePolicyConfig
		}
		resolvers[name] = resolved
	}
	return &parsedSourcePolicy{selector: selector, resolvers: resolvers, resolverIDs: resolverIDs, roles: roles}, nil
}

func validateSourcePolicyCacheIsolation(policy *parsedSourcePolicy) error {
	if policy == nil {
		return nil
	}
	owners := make(map[*cache.Cache]string)
	for _, policyID := range policy.resolverIDs {
		seen := make(map[resolver.Resolver]struct{})
		pending := []resolver.Resolver{policy.resolvers[policyID]}
		for len(pending) > 0 {
			current := pending[len(pending)-1]
			pending = pending[:len(pending)-1]
			if current == nil {
				return ErrSourcePolicyConfig
			}
			if _, ok := seen[current]; ok {
				continue
			}
			seen[current] = struct{}{}
			if value, ok := current.(*cache.Cache); ok {
				if owner, exists := owners[value]; exists && owner != policyID {
					return ErrSharedSourcePolicyCache
				}
				owners[value] = policyID
			}
			if provider, ok := current.(resolver.DependencyProvider); ok {
				pending = append(pending, provider.ResolverDependencies()...)
			}
		}
	}
	return nil
}
