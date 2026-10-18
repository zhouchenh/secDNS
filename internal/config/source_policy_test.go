package config

import (
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/zhouchenh/secDNS/internal/sourcepolicy"
	"github.com/zhouchenh/secDNS/internal/upstream/resolvers/address"
	"github.com/zhouchenh/secDNS/internal/upstream/resolvers/cache"
	"github.com/zhouchenh/secDNS/internal/upstream/resolvers/dns64"
	"github.com/zhouchenh/secDNS/pkg/listeners/server"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
)

const sourceSelectedConfig = `{
  "listeners":[{"type":"dnsServer","sourcePolicyRole":"normal","config":{"listen":"127.0.0.1","port":11553,"protocol":"udp"}}],
  "resolvers":{"cache":{
    "ordinary-cache":{"resolver":{"type":"address","config":"192.0.2.10"},"maxEntries":32},
    "special-cache":{"resolver":{"type":"address","config":"192.0.2.20"},"maxEntries":32}
  }},
  "sourcePolicy":{
    "sourceSets":[{"id":"special-clients","members":[{"prefix":"127.0.0.2/32","expiresAt":"2099-01-01T00:00:00Z"}]}],
    "rules":[{"listenerRole":"normal","sourceSet":"special-clients","resolver":"special-cache"}],
    "defaults":[{"listenerRole":"normal","resolver":"ordinary-cache"}]
  },
  "rules":[],
  "defaultResolver":"ordinary-cache"
}`

const sourceExplainOnlyConfig = `{
  "listeners":[{"type":"httpAdminServer","config":{"listen":"127.0.0.1","port":19053,"token":"synthetic-token","sourcePolicyExplain":true}}],
  "resolvers":{"address":{
    "ordinary":{"addresses":"192.0.2.10"},
    "regional":{"addresses":"192.0.2.20"}
  }},
  "sourcePolicy":{
    "sourceSets":[{"id":"regional-clients","members":[{"prefix":"192.0.2.0/24","expiresAt":"2099-01-01T00:00:00Z"}]}],
    "rules":[{"listenerRole":"normal","sourceSet":"regional-clients","resolver":"regional"}],
    "defaults":[{"listenerRole":"normal","resolver":"ordinary"}]
  },
  "rules":[],
  "defaultResolver":"ordinary"
}`

func TestSourcePolicyExplainOnlyConfigBindsWithoutDNSActivation(t *testing.T) {
	configured, err := LoadConfig(strings.NewReader(sourceExplainOnlyConfig))
	if err != nil || configured == nil {
		t.Fatal(err)
	}
	if err := ValidateConfig(strings.NewReader(sourceExplainOnlyConfig)); err != nil {
		t.Fatal(err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(sourceExplainOnlyConfig), &raw); err != nil {
		t.Fatal(err)
	}
	delete(raw, "sourcePolicy")
	withoutPolicy, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if configured, err := LoadConfig(strings.NewReader(string(withoutPolicy))); !errors.Is(err, ErrSourcePolicyConfig) || configured != nil {
		t.Fatalf("enabled explain without policy admitted: %v", err)
	}

	listeners := raw["listeners"].([]interface{})
	listener := listeners[0].(map[string]interface{})
	listener["config"].(map[string]interface{})["sourcePolicyExplain"] = false
	disabled, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if configured, err := LoadConfig(strings.NewReader(string(disabled))); err != nil || configured == nil {
		t.Fatalf("disabled explain changed legacy config: %v", err)
	}

	invalidType := strings.Replace(sourceExplainOnlyConfig, `"sourcePolicyExplain":true`, `"sourcePolicyExplain":"true"`, 1)
	if configured, err := LoadConfig(strings.NewReader(invalidType)); err == nil || configured != nil {
		t.Fatal("non-boolean sourcePolicyExplain admitted")
	}
}

func TestSourcePolicyConfigOptInAndLegacyOmission(t *testing.T) {
	configured, err := LoadConfig(strings.NewReader(sourceSelectedConfig))
	if err != nil || configured == nil {
		t.Fatal(err)
	}
	if err := ValidateConfig(strings.NewReader(sourceSelectedConfig)); err != nil {
		t.Fatal(err)
	}
	legacy := `{
      "listeners":[{"type":"dnsServer","config":{"listen":"127.0.0.1","port":11553,"protocol":"udp"}}],
      "resolvers":{"cache":{"ordinary-cache":{"resolver":{"type":"address","config":"192.0.2.10"},"maxEntries":32}}},
      "rules":[],"defaultResolver":"ordinary-cache"
    }`
	if configured, err := LoadConfig(strings.NewReader(legacy)); err != nil || configured == nil {
		t.Fatal("legacy omission changed", err)
	}
}

func TestSourcePolicyConfigRejectsPartialOrAmbiguousOptIn(t *testing.T) {
	cases := []string{
		strings.Replace(sourceSelectedConfig, `"sourcePolicyRole":"normal",`, "", 1),
		strings.Replace(sourceSelectedConfig, `"sourcePolicy":{`, `"unusedSourcePolicy":{`, 1),
		strings.Replace(sourceSelectedConfig, `"sourcePolicyRole":"normal"`, `"sourcePolicyRole":"normal","resolver":"ordinary-cache"`, 1),
		strings.Replace(sourceSelectedConfig, `"sourcePolicyRole":"normal"`, `"sourcePolicyRole":42`, 1),
		strings.Replace(sourceSelectedConfig, `"type":"dnsServer"`, `"type":"httpAPIServer"`, 1),
		strings.Replace(sourceSelectedConfig, `"sourcePolicyRole":"normal"`, `"sourcePolicyRole":"missing"`, 1),
		strings.Replace(sourceSelectedConfig, `"resolver":"special-cache"`, `"resolver":"missing-cache"`, 1),
		strings.Replace(sourceSelectedConfig, `"prefix":"127.0.0.2/32"`, `"prefix":"not-a-prefix"`, 1),
		strings.Replace(sourceSelectedConfig, `"sourceSets":[`, `"unknown":true,"sourceSets":[`, 1),
		strings.Replace(sourceSelectedConfig, `"expiresAt":"2099-01-01T00:00:00Z"`, `"expiresAt":""`, 1),
		strings.Replace(sourceSelectedConfig, `"expiresAt":"2099-01-01T00:00:00Z"`, `"expiresAt":null`, 1),
	}
	for index, raw := range cases {
		if configured, err := LoadConfig(strings.NewReader(raw)); err == nil || configured != nil {
			t.Fatalf("case %d admitted", index)
		}
	}
}

func TestSourcePeerResolverMappingAndUnavailablePeer(t *testing.T) {
	one := &address.Address{Addresses: [2][]net.IP{{net.ParseIP("192.0.2.1").To4()}}}
	two := &address.Address{Addresses: [2][]net.IP{{net.ParseIP("192.0.2.2").To4()}}}
	selector, err := sourcepolicy.Compile(sourcepolicy.Definition{
		SourceSets:        []sourcepolicy.SourceSet{{ID: "special", Members: []sourcepolicy.Member{{Prefix: netip.MustParsePrefix("127.0.0.2/32")}}}},
		Rules:             []sourcepolicy.Rule{{ListenerRole: "normal", SourceSetID: "special", ResolverPolicyID: "two"}},
		Defaults:          []sourcepolicy.RoleDefault{{ListenerRole: "normal", ResolverPolicyID: "one"}},
		ResolverPolicyIDs: []string{"one", "two"},
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed := &parsedSourcePolicy{selector: selector, resolverIDs: []string{"one", "two"}, resolvers: map[string]resolver.Resolver{"one": one, "two": two}}
	binding := &sourcePeerResolver{policy: parsed, role: "normal"}
	for peer, want := range map[netip.Addr]resolver.Resolver{
		netip.MustParseAddr("127.0.0.1"): one,
		netip.MustParseAddr("127.0.0.2"): two,
	} {
		got, err := binding.ResolverFor(peer, time.Now())
		if err != nil || got != want {
			t.Fatalf("peer %v: got %T %v", peer, got, err)
		}
	}
	if got, err := binding.ResolverFor(netip.Addr{}, time.Now()); !errors.Is(err, server.ErrPeerUnavailable) || got != nil {
		t.Fatalf("unavailable peer admitted: %T %v", got, err)
	}
	unknownRole := &sourcePeerResolver{policy: parsed, role: "missing"}
	if got, err := unknownRole.ResolverFor(netip.MustParseAddr("127.0.0.1"), time.Now()); !errors.Is(err, sourcepolicy.ErrUnknownRole) || got != nil {
		t.Fatalf("unknown role admitted: %T %v", got, err)
	}
}

func TestSourcePolicyRejectsSharedCacheAcrossDivergentGraphs(t *testing.T) {
	upstream := &address.Address{Addresses: [2][]net.IP{{net.ParseIP("192.0.2.10").To4()}}}
	shared := &cache.Cache{Resolver: upstream, MaxEntries: 16}
	t.Cleanup(shared.Stop)
	translated := &dns64.DNS64{Resolver: shared, Prefix: net.ParseIP("64:ff9b::")}
	policy := &parsedSourcePolicy{
		resolverIDs: []string{"normal", "translated"},
		resolvers: map[string]resolver.Resolver{
			"normal": shared, "translated": translated,
		},
	}
	if err := validateResolverGraph([]resolver.Resolver{shared, translated}); err != nil {
		t.Fatal(err)
	}
	if err := validateSourcePolicyCacheIsolation(policy); !errors.Is(err, ErrSharedSourcePolicyCache) {
		t.Fatalf("shared cache admitted: %v", err)
	}

	// The roots really do produce different final answers to the same question,
	// so a common downstream object is not accepted merely because it is named.
	query := new(dns.Msg)
	query.SetQuestion("same.invalid.", dns.TypeAAAA)
	ordinary, err := shared.Resolve(query.Copy(), 16)
	if err != nil || len(ordinary.Answer) != 0 {
		t.Fatal("ordinary graph fixture", err, ordinary)
	}
	synthesized, err := translated.Resolve(query.Copy(), 16)
	if err != nil || len(synthesized.Answer) != 1 {
		t.Fatal("translated graph fixture", err, synthesized)
	}

	separate := &cache.Cache{Resolver: upstream, MaxEntries: 16}
	policy.resolvers["translated"] = &dns64.DNS64{Resolver: separate, Prefix: net.ParseIP("64:ff9b::")}
	if err := validateSourcePolicyCacheIsolation(policy); err != nil {
		t.Fatal("separate caches rejected", err)
	}
}

func TestSourcePolicySharedNamedCacheConfigRejected(t *testing.T) {
	raw := `{
      "listeners":[{"type":"dnsServer","sourcePolicyRole":"normal","config":{"listen":"127.0.0.1","port":11553,"protocol":"udp"}}],
      "resolvers":{
        "cache":{"shared-cache":{"resolver":{"type":"address","config":"192.0.2.10"},"maxEntries":32}},
        "dns64":{"translated":{"resolver":"shared-cache","prefix":"64:ff9b::","ignoreExistingAAAA":false}}
      },
      "sourcePolicy":{
        "sourceSets":[{"id":"special","members":[{"prefix":"127.0.0.2/32"}]}],
        "rules":[{"listenerRole":"normal","sourceSet":"special","resolver":"translated"}],
        "defaults":[{"listenerRole":"normal","resolver":"shared-cache"}]
      },
      "rules":[],"defaultResolver":"shared-cache"
    }`
	if configured, err := LoadConfig(strings.NewReader(raw)); !errors.Is(err, ErrSharedSourcePolicyCache) || configured != nil {
		t.Fatalf("shared named cache admitted: %v", err)
	}
}
