// Package sourcepolicy compiles immutable, ordered client-source selection.
//
// The package is intentionally transport independent. A future listener
// integration must pass the validated UDP/TCP peer address, the configured
// listener role, and one query-pinned instant to Selector.Select before any
// cache lookup. ECS and untrusted forwarded headers are not peer identity.
// SelectionCachePartition is only the source-policy portion of a cache key;
// callers must also retain any resolver-graph and DNS64 semantic partitions.
//
// This package does not activate source policy in a listener, resolve names,
// perform I/O, or select network egress.
package sourcepolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"time"
)

const (
	MaxSourceSets       = 1024
	MaxMembers          = 100000
	MaxRules            = 4096
	MaxRoles            = 256
	MaxResolverPolicies = 4096
	MaxIDBytes          = 128
)

var (
	ErrInvalid     = errors.New("invalid source policy")
	ErrLimit       = errors.New("source policy limit exceeded")
	ErrReference   = errors.New("invalid source policy reference")
	ErrUnknownRole = errors.New("unknown source policy listener role")
	ErrInvalidTime = errors.New("invalid source policy query time")
)

// Member is one CIDR contribution to a source set. A zero ExpiresAt is
// permanent. A member is inactive at and after its expiry instant.
type Member struct {
	Prefix    netip.Prefix
	ExpiresAt time.Time
}

type SourceSet struct {
	ID      string
	Members []Member
}

// Rule order is significant. For a role, the first matching source set wins;
// a more-specific prefix in a later rule never overrides an earlier rule.
type Rule struct {
	ListenerRole     string
	SourceSetID      string
	ResolverPolicyID string
}

// RoleDefault is the required fallback for one listener role.
type RoleDefault struct {
	ListenerRole     string
	ResolverPolicyID string
}

// Definition is the complete input to one compiled selector. ResolverPolicyIDs
// names the resolver policies which the future integration has already built.
type Definition struct {
	SourceSets        []SourceSet
	Rules             []Rule
	Defaults          []RoleDefault
	ResolverPolicyIDs []string
}

// SelectionCachePartition is comparable and contains no client address. It is
// the source-policy component a future runtime must include before sharing a
// cached answer across selections.
type SelectionCachePartition struct {
	PolicyFingerprint [sha256.Size]byte
	ListenerRole      string
	ResolverPolicyID  string
}

// Decision describes one deterministic selection. RuleIndex is the original
// Definition.Rules index, or -1 when UsedDefault is true.
type Decision struct {
	ResolverPolicyID string
	SourceSetID      string
	RuleIndex        int
	UsedDefault      bool
	CachePartition   SelectionCachePartition
}

// Explainer is the read-only selection surface used by management previews.
// It cannot resolve a DNS query or access policy resolver instances.
type Explainer interface {
	Select(listenerRole string, peer netip.Addr, now time.Time) (Decision, error)
}

type compiledMember struct {
	expiresAt time.Time
}

type compiledSet struct {
	members map[netip.Prefix][]compiledMember
}

type compiledRule struct {
	setID            string
	resolverPolicyID string
	ruleIndex        int
}

// Selector owns its compiled state and is safe for concurrent use.
type Selector struct {
	fingerprint [sha256.Size]byte
	sets        map[string]compiledSet
	rules       map[string][]compiledRule
	defaults    map[string]string
}

type canonicalMember struct {
	Prefix    string `json:"prefix"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

type canonicalSet struct {
	ID      string            `json:"id"`
	Members []canonicalMember `json:"members"`
}

type canonicalRule struct {
	ListenerRole     string `json:"listener_role"`
	SourceSetID      string `json:"source_set_id"`
	ResolverPolicyID string `json:"resolver_policy_id"`
}

type canonicalDefault struct {
	ListenerRole     string `json:"listener_role"`
	ResolverPolicyID string `json:"resolver_policy_id"`
}

type canonicalDefinition struct {
	Schema            string             `json:"schema"`
	SourceSets        []canonicalSet     `json:"source_sets"`
	Rules             []canonicalRule    `json:"rules"`
	Defaults          []canonicalDefault `json:"defaults"`
	ResolverPolicyIDs []string           `json:"resolver_policy_ids"`
}

const fingerprintSchema = "secdns.source-policy-selection.v1"

// Compile validates and copies a complete source-policy definition. Prefixes
// are normalized to network addresses. IPv4 ranges are deliberately outside
// this slice; a future connector may convert them to a separately bounded CIDR
// cover before calling Compile.
func Compile(input Definition) (*Selector, error) {
	if len(input.SourceSets) > MaxSourceSets || len(input.Rules) > MaxRules || len(input.Defaults) > MaxRoles || len(input.ResolverPolicyIDs) > MaxResolverPolicies {
		return nil, ErrLimit
	}
	if len(input.Defaults) == 0 || len(input.ResolverPolicyIDs) == 0 {
		return nil, ErrInvalid
	}

	knownResolvers := make(map[string]struct{}, len(input.ResolverPolicyIDs))
	canonicalResolvers := make([]string, 0, len(input.ResolverPolicyIDs))
	for _, id := range input.ResolverPolicyIDs {
		if !validID(id) {
			return nil, ErrInvalid
		}
		if _, exists := knownResolvers[id]; exists {
			return nil, ErrInvalid
		}
		knownResolvers[id] = struct{}{}
		canonicalResolvers = append(canonicalResolvers, id)
	}
	sort.Strings(canonicalResolvers)

	selector := &Selector{
		sets:     make(map[string]compiledSet, len(input.SourceSets)),
		rules:    make(map[string][]compiledRule, len(input.Defaults)),
		defaults: make(map[string]string, len(input.Defaults)),
	}
	canonicalSets := make([]canonicalSet, 0, len(input.SourceSets))
	totalMembers := 0
	for _, sourceSet := range input.SourceSets {
		if !validID(sourceSet.ID) {
			return nil, ErrInvalid
		}
		if _, exists := selector.sets[sourceSet.ID]; exists {
			return nil, ErrInvalid
		}
		totalMembers += len(sourceSet.Members)
		if totalMembers > MaxMembers {
			return nil, ErrLimit
		}
		compiled := compiledSet{members: make(map[netip.Prefix][]compiledMember, len(sourceSet.Members))}
		canonical := canonicalSet{ID: sourceSet.ID, Members: make([]canonicalMember, 0, len(sourceSet.Members))}
		for _, member := range sourceSet.Members {
			if !member.Prefix.IsValid() || member.Prefix.Addr().Zone() != "" || member.Prefix.Addr().Is4In6() {
				return nil, ErrInvalid
			}
			prefix := member.Prefix.Masked()
			expiresAt, expiryText, ok := canonicalTime(member.ExpiresAt)
			if !ok {
				return nil, ErrInvalid
			}
			insert(&compiled, prefix, compiledMember{expiresAt: expiresAt})
			canonical.Members = append(canonical.Members, canonicalMember{Prefix: prefix.String(), ExpiresAt: expiryText})
		}
		sort.Slice(canonical.Members, func(i, j int) bool {
			if canonical.Members[i].Prefix == canonical.Members[j].Prefix {
				return canonical.Members[i].ExpiresAt < canonical.Members[j].ExpiresAt
			}
			return canonical.Members[i].Prefix < canonical.Members[j].Prefix
		})
		selector.sets[sourceSet.ID] = compiled
		canonicalSets = append(canonicalSets, canonical)
	}
	sort.Slice(canonicalSets, func(i, j int) bool { return canonicalSets[i].ID < canonicalSets[j].ID })

	canonicalDefaults := make([]canonicalDefault, 0, len(input.Defaults))
	for _, fallback := range input.Defaults {
		if !validID(fallback.ListenerRole) || !validID(fallback.ResolverPolicyID) {
			return nil, ErrInvalid
		}
		if _, ok := knownResolvers[fallback.ResolverPolicyID]; !ok {
			return nil, ErrReference
		}
		if _, exists := selector.defaults[fallback.ListenerRole]; exists {
			return nil, ErrInvalid
		}
		selector.defaults[fallback.ListenerRole] = fallback.ResolverPolicyID
		canonicalDefaults = append(canonicalDefaults, canonicalDefault(fallback))
	}
	sort.Slice(canonicalDefaults, func(i, j int) bool { return canonicalDefaults[i].ListenerRole < canonicalDefaults[j].ListenerRole })

	canonicalRules := make([]canonicalRule, 0, len(input.Rules))
	for index, rule := range input.Rules {
		if !validID(rule.ListenerRole) || !validID(rule.SourceSetID) || !validID(rule.ResolverPolicyID) {
			return nil, ErrInvalid
		}
		if _, ok := selector.defaults[rule.ListenerRole]; !ok {
			return nil, ErrReference
		}
		if _, ok := selector.sets[rule.SourceSetID]; !ok {
			return nil, ErrReference
		}
		if _, ok := knownResolvers[rule.ResolverPolicyID]; !ok {
			return nil, ErrReference
		}
		selector.rules[rule.ListenerRole] = append(selector.rules[rule.ListenerRole], compiledRule{
			setID: rule.SourceSetID, resolverPolicyID: rule.ResolverPolicyID, ruleIndex: index,
		})
		canonicalRules = append(canonicalRules, canonicalRule(rule))
	}

	canonical := canonicalDefinition{
		Schema: fingerprintSchema, SourceSets: canonicalSets, Rules: canonicalRules,
		Defaults: canonicalDefaults, ResolverPolicyIDs: canonicalResolvers,
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return nil, ErrInvalid
	}
	selector.fingerprint = sha256.Sum256(encoded)
	return selector, nil
}

// Fingerprint returns the content-derived selector fingerprint. It detects
// policy changes for cache separation and diagnostics; it is not an authority
// signature or security boundary.
func (s *Selector) Fingerprint() [sha256.Size]byte { return s.fingerprint }

func (s *Selector) FingerprintHex() string { return hex.EncodeToString(s.fingerprint[:]) }

// Select applies one role's ordered rules. An invalid, missing, or zone-qualified
// peer address is treated as unavailable identity and uses the explicit default.
func (s *Selector) Select(listenerRole string, peer netip.Addr, now time.Time) (Decision, error) {
	if s == nil {
		return Decision{}, ErrInvalid
	}
	defaultResolver, ok := s.defaults[listenerRole]
	if !ok {
		return Decision{}, ErrUnknownRole
	}
	if now.IsZero() {
		return Decision{}, ErrInvalidTime
	}
	now = now.UTC().Round(0)
	if now.Year() < 1 || now.Year() > 9999 {
		return Decision{}, ErrInvalidTime
	}
	if peer.IsValid() && peer.Zone() == "" {
		peer = peer.Unmap()
		for _, rule := range s.rules[listenerRole] {
			if s.sets[rule.setID].contains(peer, now) {
				return s.decision(listenerRole, rule.resolverPolicyID, rule.setID, rule.ruleIndex, false), nil
			}
		}
	}
	return s.decision(listenerRole, defaultResolver, "", -1, true), nil
}

func (s *Selector) decision(role, resolverPolicyID, sourceSetID string, ruleIndex int, usedDefault bool) Decision {
	return Decision{
		ResolverPolicyID: resolverPolicyID,
		SourceSetID:      sourceSetID,
		RuleIndex:        ruleIndex,
		UsedDefault:      usedDefault,
		CachePartition: SelectionCachePartition{
			PolicyFingerprint: s.fingerprint,
			ListenerRole:      role, ResolverPolicyID: resolverPolicyID,
		},
	}
}

func validID(value string) bool {
	if len(value) == 0 || len(value) > MaxIDBytes {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func canonicalTime(value time.Time) (time.Time, string, bool) {
	if value.IsZero() {
		return time.Time{}, "", true
	}
	value = value.UTC().Round(0)
	if value.Year() < 1 || value.Year() > 9999 {
		return time.Time{}, "", false
	}
	return value, value.Format(time.RFC3339Nano), true
}

func insert(set *compiledSet, prefix netip.Prefix, member compiledMember) {
	set.members[prefix] = append(set.members[prefix], member)
}

func (set compiledSet) contains(address netip.Addr, now time.Time) bool {
	if !address.Is4() && !address.Is6() {
		return false
	}
	for bits := address.BitLen(); bits >= 0; bits-- {
		prefix := netip.PrefixFrom(address, bits).Masked()
		for _, member := range set.members[prefix] {
			if member.expiresAt.IsZero() || now.Before(member.expiresAt) {
				return true
			}
		}
	}
	return false
}
