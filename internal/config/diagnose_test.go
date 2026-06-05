package config

import (
	"strings"
	"testing"

	"github.com/zhouchenh/go-descriptor"
	_ "github.com/zhouchenh/secDNS/internal/features"
)

// TestLoadConfigLocatableErrors drives the real loader with malformed configs and
// asserts the error names the section and the offending entry, instead of the opaque
// "Bad config". Each input is one the loader rejects; the assertion is on locality.
func TestLoadConfigLocatableErrors(t *testing.T) {
	cases := []struct {
		name     string
		json     string
		contains []string
	}{
		{
			name:     "root not an object",
			json:     `[1, 2, 3]`,
			contains: []string{"config:", "(root)", "must be a JSON object", "array"},
		},
		{
			name:     "listeners not an array",
			json:     `{"listeners": {}, "defaultResolver": {"type":"noAnswer","config":{}}}`,
			contains: []string{"listeners", "must be a JSON array", "object"},
		},
		{
			name: "listener unknown type",
			json: `{
			  "listeners": [{"type": "bogusListener", "config": {}}],
			  "defaultResolver": {"type":"noAnswer","config":{}}
			}`,
			contains: []string{"listeners", "index 0", `unknown type "bogusListener"`},
		},
		{
			name: "listener missing type",
			json: `{
			  "listeners": [{"config": {}}],
			  "defaultResolver": {"type":"noAnswer","config":{}}
			}`,
			contains: []string{"listeners", "index 0", `missing the required "type"`},
		},
		{
			name: "second listener is the bad one",
			json: `{
			  "listeners": [
			    {"type": "dnsServer", "config": {"listen": "127.0.0.1", "port": 5353, "protocol": "udp"}},
			    {"type": "bogusListener", "config": {}}
			  ],
			  "defaultResolver": {"type":"noAnswer","config":{}}
			}`,
			contains: []string{"listeners", "index 1", `unknown type "bogusListener"`},
		},
		{
			name: "defaultResolver unknown type",
			json: `{
			  "listeners": [{"type": "dnsServer", "config": {"listen": "127.0.0.1", "port": 5353, "protocol": "udp"}}],
			  "defaultResolver": {"type": "bogusResolver", "config": {}}
			}`,
			contains: []string{"defaultResolver", `unknown type "bogusResolver"`},
		},
		{
			name: "defaultResolver missing",
			json: `{
			  "listeners": [{"type": "dnsServer", "config": {"listen": "127.0.0.1", "port": 5353, "protocol": "udp"}}]
			}`,
			contains: []string{"defaultResolver", "missing"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := LoadConfig(strings.NewReader(c.json))
			if err == nil {
				t.Fatalf("expected an error, got nil")
			}
			got := err.Error()
			if got == ErrBadConfig.Error() {
				t.Fatalf("error is still the opaque %q", got)
			}
			for _, want := range c.contains {
				if !strings.Contains(got, want) {
					t.Fatalf("error %q does not contain %q", got, want)
				}
			}
		})
	}
}

// TestLoadConfigValidStillLoads guards against false positives: a valid config that
// uses every diagnosed section must still load without error.
func TestLoadConfigValidStillLoads(t *testing.T) {
	json := `{
	  "listeners": [
	    {"type": "dnsServer", "config": {"listen": "127.0.0.1", "port": 5353, "protocol": "udp"}}
	  ],
	  "resolvers": {"noAnswer": {"noop": {}}},
	  "rules": [],
	  "defaultResolver": {"type": "noAnswer", "config": {}}
	}`
	if _, err := LoadConfig(strings.NewReader(json)); err != nil {
		t.Fatalf("valid config failed to load: %v", err)
	}
}

// TestDiagnoseConfigGivesUp asserts diagnoseConfig returns nil (loader falls back to
// ErrBadConfig) when every section it inspects is individually well-formed, so it
// never fabricates a cause.
func TestDiagnoseConfigGivesUp(t *testing.T) {
	data := map[string]interface{}{
		"listeners": []interface{}{
			map[string]interface{}{"type": "dnsServer", "config": map[string]interface{}{"listen": "127.0.0.1"}},
		},
		"defaultResolver": map[string]interface{}{"type": "noAnswer", "config": map[string]interface{}{}},
	}
	if err := diagnoseConfig(data); err != nil {
		t.Fatalf("diagnoseConfig should give up on a well-formed shape, got %v", err)
	}
}

// failingDescribable is registered (lookup succeeds) but rejects every config block,
// which the real listener/resolver descriptors are too lenient to do deterministically.
type failingDescribable struct{}

func (failingDescribable) Describe(interface{}) (interface{}, int, int) { return nil, 0, 1 }
func (failingDescribable) GetPrototype() interface{}                    { return nil }

// TestDiagnoseTypedEntryInvalidConfigBlock exercises the "known type, bad config"
// branch directly, since the shipped types accept lenient inner configs.
func TestDiagnoseTypedEntryInvalidConfigBlock(t *testing.T) {
	entry := map[string]interface{}{"type": "known", "config": map[string]interface{}{"x": float64(1)}}
	lookup := func(name string) (descriptor.Describable, bool) {
		return failingDescribable{}, name == "known" // the type is registered...
	}
	reason := diagnoseTypedEntry(entry, failingDescribable{}, lookup) // ...but its config is rejected
	if !strings.Contains(reason, `type "known"`) || !strings.Contains(reason, "invalid config block") {
		t.Fatalf("expected an invalid-config-block reason, got %q", reason)
	}
}
