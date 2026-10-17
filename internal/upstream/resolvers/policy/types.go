// Package policy reuses the core rule selector as an in-process resolver.
package policy

import (
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/core"
	"github.com/zhouchenh/secDNS/internal/rules/providers/collection"
	"github.com/zhouchenh/secDNS/internal/rules/providers/collection/rule"
	"github.com/zhouchenh/secDNS/pkg/rules/provider"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
)

type Policy struct{ Graph resolver.Resolver }

var policyType = descriptor.TypeOfNew(new(*Policy))

func (p *Policy) Type() descriptor.Type                     { return policyType }
func (p *Policy) TypeName() string                          { return "policy" }
func (p *Policy) ResolverDependencies() []resolver.Resolver { return []resolver.Resolver{p.Graph} }
func (p *Policy) Resolve(q *dns.Msg, depth int) (*dns.Msg, error) {
	if depth < 0 {
		return nil, resolver.ErrLoopDetected
	}
	return p.Graph.Resolve(q, depth-1)
}

func build(raw interface{}) (interface{}, bool) {
	m, ok := raw.(map[string]interface{})
	if !ok {
		return nil, false
	}
	for k := range m {
		if k != "rules" && k != "defaultResolver" {
			return nil, false
		}
	}
	def, s, f := resolver.Descriptor().Describe(m["defaultResolver"])
	if s < 1 || f > 0 {
		return nil, false
	}
	d, ok := def.(resolver.Resolver)
	if !ok || d == nil {
		return nil, false
	}
	entries, ok := m["rules"].([]interface{})
	if !ok {
		return nil, false
	}
	i := core.NewInstance()
	i.SetDefaultResolver(d)
	for _, rawEntry := range entries {
		entry, ok := rawEntry.(map[string]interface{})
		if !ok {
			return nil, false
		}
		kind, ok := entry["type"].(string)
		if !ok {
			return nil, false
		}
		// The legacy collection descriptor skips malformed entries. New policy
		// definitions must reject those before the provider can partially load.
		var direct provider.Provider
		if kind == "collection" || kind == "typedCollection" {
			rows, ok := entry["config"].([]interface{})
			if !ok {
				return nil, false
			}
			c := &collection.Collection{}
			for _, row := range rows {
				value, s, f := rule.NameResolutionRuleDescriptor().Describe(row)
				if s < 1 || f > 0 {
					return nil, false
				}
				r, ok := value.(*rule.NameResolutionRule)
				if !ok {
					return nil, false
				}
				c.Rules = append(c.Rules, r)
			}
			direct = c
		}
		value, s, f := interface{}(direct), 1, 0
		if direct == nil {
			value, s, f = provider.Descriptor().Describe(rawEntry)
		}
		if s < 1 || f > 0 {
			return nil, false
		}
		p, ok := value.(provider.Provider)
		if !ok || p == nil {
			return nil, false
		}
		failed := false
		i.AcceptProvider(p, func(error) { failed = true })
		if failed {
			return nil, false
		}
	}
	r, ok := i.GetResolver()
	return r, ok
}

func init() {
	if err := resolver.RegisterResolver(&descriptor.Descriptor{Type: policyType, Filler: descriptor.ObjectFiller{ObjectPath: descriptor.Path{"Graph"}, ValueSource: descriptor.ObjectAtPath{ObjectPath: descriptor.Root, AssignableKind: descriptor.AssignmentFunction(build)}}}); err != nil {
		panic(err)
	}
}
