package recursive

import (
	"testing"

	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
)

// describeRecursive builds a recursive resolver from a JSON-like config map via the registered
// descriptor, mirroring how the config loader instantiates named resolvers.
func describeRecursive(t *testing.T, cfg map[string]interface{}) *Recursive {
	t.Helper()
	describable, ok := resolver.GetResolverDescriptorByTypeName("recursive")
	if !ok {
		t.Fatalf("descriptor for recursive not registered")
	}
	obj, s, f := describable.Describe(cfg)
	if s < 1 || f > 0 {
		t.Fatalf("describe failed for cfg %v: success=%d failure=%d", cfg, s, f)
	}
	r, ok := obj.(*Recursive)
	if !ok || r == nil {
		t.Fatalf("describe returned %T (nil=%v), want non-nil *Recursive", obj, r == nil)
	}
	return r
}

// TestRecursiveDescriptorEmptyConfigUsesDefaults verifies that a recursive resolver can be
// constructed from an empty config, i.e. every key is optional and falls back to its default.
// Regression: validateDNSSEC/qnameMinimize/ednsSize previously had no DefaultValue fallback, so
// omitting any of them made the descriptor fail and the resolver be silently dropped (the
// documented minimal example did not load).
func TestRecursiveDescriptorEmptyConfigUsesDefaults(t *testing.T) {
	r := describeRecursive(t, map[string]interface{}{})
	if r.ValidateDNSSEC != "permissive" {
		t.Errorf("validateDNSSEC default = %q, want %q", r.ValidateDNSSEC, "permissive")
	}
	if !r.QNameMinimize {
		t.Errorf("qnameMinimize default = false, want true")
	}
	if r.EDNSSize != 1232 {
		t.Errorf("ednsSize default = %d, want 1232", r.EDNSSize)
	}
	if len(r.RootServers) == 0 {
		t.Errorf("rootServers default is empty, want built-in root hints")
	}
}

// TestRecursiveDescriptorPartialConfigUsesDefaults verifies that supplying only one key still
// constructs the resolver and defaults the rest.
func TestRecursiveDescriptorPartialConfigUsesDefaults(t *testing.T) {
	r := describeRecursive(t, map[string]interface{}{"validateDNSSEC": "strict"})
	if r.ValidateDNSSEC != "strict" {
		t.Errorf("validateDNSSEC = %q, want strict", r.ValidateDNSSEC)
	}
	if !r.QNameMinimize {
		t.Errorf("qnameMinimize default = false, want true")
	}
	if r.EDNSSize != 1232 {
		t.Errorf("ednsSize default = %d, want 1232", r.EDNSSize)
	}
}

// TestRecursiveDescriptorInstancesAreIndependent verifies that two recursive resolvers built
// from different configs do not share state. Regression: the descriptor previously seeded every
// instance from one shared *Recursive default pointer, so the last-parsed config overwrote the
// others (e.g. a strict resolver silently downgraded to permissive when a permissive resolver
// was also configured).
func TestRecursiveDescriptorInstancesAreIndependent(t *testing.T) {
	strict := describeRecursive(t, map[string]interface{}{"validateDNSSEC": "strict"})
	permissive := describeRecursive(t, map[string]interface{}{"validateDNSSEC": "permissive"})
	if strict == permissive {
		t.Fatalf("two recursive resolvers share the same *Recursive instance")
	}
	if strict.ValidateDNSSEC != "strict" {
		t.Errorf("first resolver validateDNSSEC = %q, want strict", strict.ValidateDNSSEC)
	}
	if permissive.ValidateDNSSEC != "permissive" {
		t.Errorf("second resolver validateDNSSEC = %q, want permissive", permissive.ValidateDNSSEC)
	}
	strict.ValidateDNSSEC = "off"
	if permissive.ValidateDNSSEC != "permissive" {
		t.Errorf("mutating the first resolver changed the second: got %q", permissive.ValidateDNSSEC)
	}
}
