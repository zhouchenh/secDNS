package config

import (
	"encoding/json"
	"errors"
	named "github.com/zhouchenh/secDNS/internal/config/named/resolver"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/upstream/resolvers/policy"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
)

const selectedConfig = `{
 "listeners":[{"type":"dnsServer","resolver":"dns64-policy","config":{"listen":"::1","port":11653,"protocol":"udp"}}],
 "resolvers":{
  "cache":{"normal-cache":{"resolver":{"type":"address","config":"192.0.2.10"},"maxEntries":32,"negativeTTL":30},"dns64-cache":{"resolver":"dns64-base","maxEntries":32}},
  "dns64":{"dns64-base":{"resolver":"","prefix":"64:ff9b::","ignoreExistingAAAA":false}},
  "policy":{"dns64-policy":{"rules":[{"type":"collection","config":[{"name":"\"exclude.invalid.\"","resolver":""}]}],"defaultResolver":"dns64-cache"}}
 },
 "rules":[{"type":"collection","config":[{"name":"\"native.invalid.\"","resolver":{"type":"address","config":"2001:db8::10"}}]}],
 "defaultResolver":"normal-cache"
}`

func TestSelectedPolicyConfigAndGlobalUnchanged(t *testing.T) {
	i, err := LoadConfig(strings.NewReader(selectedConfig))
	if err != nil {
		t.Fatal(err)
	}
	r, ok := i.GetResolver()
	if !ok {
		t.Fatal("global missing")
	}
	q := new(dns.Msg)
	q.SetQuestion("ordinary.invalid.", dns.TypeAAAA)
	answer, err := r.Resolve(q, 32)
	if err != nil || len(answer.Answer) != 0 {
		t.Fatal("global became DNS64", err)
	}
	if err := ValidateConfig(strings.NewReader(selectedConfig)); err != nil {
		t.Fatal(err)
	}
}

func TestBindingRejectsInvalidGraphsAndPreservesLegacy(t *testing.T) {
	for _, bad := range []string{
		strings.Replace(selectedConfig, `"resolver":"dns64-policy"`, `"resolver":"missing"`, 1),
		strings.Replace(selectedConfig, `"resolver":"dns64-policy"`, `"resolver":null`, 1),
		strings.Replace(selectedConfig, `"resolver":""`, `"resolver":"dns64-policy"`, 1),
		strings.Replace(selectedConfig, `"type":"dnsServer"`, `"type":"httpAdminServer"`, 1),
		strings.Replace(selectedConfig, `"defaultResolver":"dns64-cache"`, `"defaultResolver":"dns64-policy"`, 1),
		strings.Replace(selectedConfig, `"name":"\"exclude.invalid.\""`, `"name":null`, 1),
	} {
		if i, err := LoadConfig(strings.NewReader(bad)); err == nil || i != nil {
			t.Fatal("invalid graph admitted")
		}
	}
	// Recursive aliases can make name progress at runtime, but opt-in graph
	// eligibility deliberately rejects them. Legacy omission retains its behavior.
	legacy := `{"listeners":[{"type":"dnsServer","config":{"listen":"127.0.0.1","port":11553,"protocol":"udp"}}],"rules":[{"type":"collection","config":[{"name":"alias.invalid","resolver":{"type":"alias","config":"target.invalid."}}]}],"defaultResolver":{"type":"address","config":"192.0.2.1"}}`
	if _, err := LoadConfig(strings.NewReader(legacy)); err != nil {
		t.Fatal(err)
	}
	selected := strings.Replace(legacy, `"type":"dnsServer"`, `"type":"dnsServer","resolver":""`, 1)
	if _, err := LoadConfig(strings.NewReader(selected)); !errors.Is(err, ErrResolverCycle) {
		t.Fatalf("wanted conservative cycle rejection, got %v", err)
	}
}

type opaqueResolver struct{}

func (*opaqueResolver) Type() descriptor.Type { return nil }
func (*opaqueResolver) TypeName() string      { return "opaque" }
func (*opaqueResolver) Resolve(*dns.Msg, int) (*dns.Msg, error) {
	panic("must not resolve during validation")
}
func TestGraphRejectsOpaqueAndTypedNil(t *testing.T) {
	for _, r := range []resolver.Resolver{&opaqueResolver{}, (*opaqueResolver)(nil)} {
		if !errors.Is(validateResolverGraph([]resolver.Resolver{r}), ErrOpaqueResolver) {
			t.Fatal("opaque admitted")
		}
	}
}

func TestUnusedPolicyRejectedAndLegacyMetadataIgnored(t *testing.T) {
	for _, body := range []string{
		`{"rules":[{"type":"collection","config":[{"name":null,"resolver":""}]}],"defaultResolver":""}`,
		`{"rules":[],"defaultResolver":"missing"}`,
		`{"rules":[],"defaultResolver":"unused"}`,
	} {
		raw := strings.Replace(minimalConfig, `"resolvers": {`, `"resolvers": {"policy":{"unused":`+body+`},`, 1)
		if i, err := LoadConfig(strings.NewReader(raw)); err == nil || i != nil {
			t.Fatal("invalid unused policy admitted")
		}
		if _, err := LoadConfig(strings.NewReader(selectedConfig)); err != nil {
			t.Fatal("failed config contaminated registry", err)
		}
	}
	legacy := `{"listeners":[{"type":"dnsServer","config":{"listen":"127.0.0.1","port":11553,"protocol":"udp"}}],"rules":[{"type":"collection","config":[{"name":"alias.invalid","resolver":{"type":"alias","config":"target.invalid."}}]}],"defaultResolver":{"type":"address","config":"192.0.2.1"},"unrelated":{"type":"policy"}}`
	if _, err := LoadConfig(strings.NewReader(legacy)); err != nil {
		t.Fatal("unrelated metadata opted into graph restrictions", err)
	}
}

type graphResolver struct{ children []resolver.Resolver }

func (*graphResolver) Type() descriptor.Type                       { return nil }
func (*graphResolver) TypeName() string                            { return "graph-test" }
func (*graphResolver) Resolve(*dns.Msg, int) (*dns.Msg, error)     { panic("validation must not resolve") }
func (g *graphResolver) ResolverDependencies() []resolver.Resolver { return g.children }
func TestGraphDAGCycleAndBounds(t *testing.T) {
	leaf := &graphResolver{}
	root := &graphResolver{[]resolver.Resolver{leaf, leaf}}
	if err := validateResolverGraph([]resolver.Resolver{root}); err != nil {
		t.Fatal(err)
	}
	leaf.children = []resolver.Resolver{root}
	if !errors.Is(validateResolverGraph([]resolver.Resolver{root}), ErrResolverCycle) {
		t.Fatal("cycle admitted")
	}
	leaf.children = nil
	chain := &graphResolver{}
	for n := 0; n < 257; n++ {
		chain = &graphResolver{[]resolver.Resolver{chain}}
	}
	if !errors.Is(validateResolverGraph([]resolver.Resolver{chain}), ErrResolverGraphLimit) {
		t.Fatal("depth limit ignored")
	}
	wide := &graphResolver{}
	for n := 0; n < 4096; n++ {
		wide.children = append(wide.children, &graphResolver{})
	}
	if !errors.Is(validateResolverGraph([]resolver.Resolver{wide}), ErrResolverGraphLimit) {
		t.Fatal("node limit ignored")
	}
}

func TestLegacyListenerOmissionRetainsDescriptorBehavior(t *testing.T) {
	raw := strings.Replace(minimalConfig, `"listeners": [`, `"listeners": [{"type":"unknown-server","config":{}},`, 1)
	// Compare the existing descriptor directly: the binding layer must add no new
	// rejection for legacy omission, whether this descriptor accepts or rejects it.
	var data interface{}
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		t.Fatal(err)
	}
	loadMu.Lock()
	named.ResetKnownNamedResolvers()
	value, s, f := Descriptor().Describe(data)
	named.SetNameRegistryAssignmentFunction(nil)
	named.ResetKnownNamedResolvers()
	loadMu.Unlock()
	if s > 0 && f == 0 {
		if _, err := bindListeners(data, value.(*Config)); err != nil {
			t.Fatal("legacy binding regression", err)
		}
	}
}

func TestConcurrentSelectedLoaderIsolation(t *testing.T) {
	var group sync.WaitGroup
	for n := 0; n < 12; n++ {
		group.Add(1)
		go func(n int) {
			defer group.Done()
			for j := 0; j < 6; j++ {
				if n%3 == 0 {
					if err := ValidateConfig(strings.NewReader(selectedConfig)); err != nil {
						t.Error(err)
					}
				} else if n%3 == 1 {
					if _, err := LoadConfig(strings.NewReader(selectedConfig)); err != nil {
						t.Error(err)
					}
				} else {
					bad := strings.Replace(selectedConfig, `"resolver":"dns64-policy"`, `"resolver":"missing"`, 1)
					if _, err := LoadConfig(strings.NewReader(bad)); err == nil {
						t.Error("missing accepted")
					}
				}
			}
		}(n)
	}
	group.Wait()
	if _, err := LoadConfig(strings.NewReader(selectedConfig)); err != nil {
		t.Fatal(err)
	}
}

func TestSelectedGlobalProviderFailureIsFatal(t *testing.T) {
	var data map[string]any
	if err := json.Unmarshal([]byte(selectedConfig), &data); err != nil {
		t.Fatal(err)
	}
	data["rules"] = []any{map[string]any{"type": "dnsmasqConf", "config": map[string]any{"filePath": filepath.Join(t.TempDir(), "missing.conf"), "resolver": map[string]any{"type": "address", "config": "192.0.2.1"}}}}
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	if i, err := LoadConfig(strings.NewReader(string(raw))); err == nil || i != nil {
		t.Fatal("selected partial provider admitted")
	}
}

func TestPolicyDetectionDoesNotHideBehindLargeGraph(t *testing.T) {
	root := &graphResolver{children: []resolver.Resolver{&policy.Policy{Graph: &graphResolver{}}}}
	for n := 0; n < 5000; n++ {
		root.children = append(root.children, &graphResolver{})
	}
	if !containsPolicyGraph([]resolver.Resolver{root}) {
		t.Fatal("policy hidden by unrelated nodes")
	}
	if !errors.Is(validateResolverGraph([]resolver.Resolver{root}), ErrResolverGraphLimit) {
		t.Fatal("large opt-in graph admitted")
	}
}
