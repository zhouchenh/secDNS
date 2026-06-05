package config

import (
	"errors"
	"strings"
	"testing"

	_ "github.com/zhouchenh/secDNS/internal/features"
)

const minimalConfig = `{
  "listeners": [
    {"type": "dnsServer", "config": {"listen": "127.0.0.1", "port": 5353, "protocol": "udp"}}
  ],
  "resolvers": {
    "noAnswer": {
      "default": {}
    }
  },
  "rules": [],
  "defaultResolver": {
    "type": "noAnswer",
    "config": {}
  },
  "resolutionDepth": 42
}`

func TestLoadConfigSuccess(t *testing.T) {
	instance, err := LoadConfig(strings.NewReader(minimalConfig))
	if err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}
	if instance == nil {
		t.Fatalf("expected instance, got nil")
	}
	if _, ok := instance.GetResolver(); !ok {
		t.Fatalf("expected default resolver to be configured")
	}
}

func TestLoadConfigMissingListeners(t *testing.T) {
	json := `{
  "listeners": [],
  "resolvers": {"noAnswer":{"default":{}}},
  "rules": [],
  "defaultResolver":{"type":"noAnswer","config":{}}
}`
	_, err := LoadConfig(strings.NewReader(json))
	if !errors.Is(err, ErrMissingListenersConfig) {
		t.Fatalf("expected ErrMissingListenersConfig, got %v", err)
	}
}

func TestLoadConfigInvalidJSON(t *testing.T) {
	_, err := LoadConfig(strings.NewReader("{invalid"))
	if err == nil {
		t.Fatalf("expected JSON parse error")
	}
}

func TestLoadConfigEcsDefaultsAreStrings(t *testing.T) {
	json := `{
  "listeners": [
    {"type": "dnsServer", "config": {"listen": "127.0.0.1", "port": 5353, "protocol": "udp"}}
  ],
  "resolvers": {
    "doh": {
      "dohDefault": {
        "url": "https://dns.google/dns-query",
        "urlResolver": {"type": "noAnswer", "config": {}}
      }
    },
    "nameServer": {
      "nsDefault": {"address": "1.1.1.1"}
    },
    "recursive": {
      "recDefault": {}
    },
    "ecs": {
      "ecsDefault": {"resolver": "dohDefault"}
    }
  },
  "rules": [],
  "defaultResolver": "dohDefault"
}`

	instance, err := LoadConfig(strings.NewReader(json))
	if err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}
	if instance == nil {
		t.Fatalf("expected instance, got nil")
	}
	if _, ok := instance.GetResolver(); !ok {
		t.Fatalf("expected default resolver to be configured")
	}
}

func TestLoadConfigAuthoritativeAndAdmin(t *testing.T) {
	// The authoritative resolver and the admin listener share a store by name; this
	// asserts the whole config pipeline accepts both new types. The default resolver is
	// declared inline (no named resolver) to avoid mutating the process-global resolver
	// name registry this package's other tests rely on.
	json := `{
  "listeners": [
    {"type": "dnsServer", "config": {"listen": "127.0.0.1", "port": 5353, "protocol": "udp"}},
    {"type": "httpAdminServer", "config": {"listen": "127.0.0.1", "port": 9053, "token": "secret", "store": "acme"}}
  ],
  "rules": [],
  "defaultResolver": {"type": "authoritative", "config": {"store": "acme", "negativeTTL": 30}}
}`
	instance, err := LoadConfig(strings.NewReader(json))
	if err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}
	if instance == nil {
		t.Fatalf("expected an instance")
	}
	if _, ok := instance.GetResolver(); !ok {
		t.Fatalf("expected default resolver to be configured")
	}
}

func TestLoadConfigDoesNotLeakFailedNamedResolvers(t *testing.T) {
	// A first load fails because its default resolver names one that does not exist.
	failing := `{
  "listeners": [{"type": "dnsServer", "config": {"listen": "127.0.0.1", "port": 5353, "protocol": "udp"}}],
  "resolvers": {"noAnswer": {"present": {}}},
  "rules": [],
  "defaultResolver": "missing-resolver"
}`
	if _, err := LoadConfig(strings.NewReader(failing)); err == nil {
		t.Fatalf("expected the first load to fail on the missing resolver")
	}

	// A second, independent load that references a resolver it DOES declare must succeed:
	// the failed load must not have left "missing-resolver" in the process-global pending
	// list to be re-processed (and re-failed on) here.
	valid := `{
  "listeners": [{"type": "dnsServer", "config": {"listen": "127.0.0.1", "port": 5353, "protocol": "udp"}}],
  "resolvers": {"noAnswer": {"only": {}}},
  "rules": [],
  "defaultResolver": "only"
}`
	if _, err := LoadConfig(strings.NewReader(valid)); err != nil {
		t.Fatalf("second load inherited the first load's failure: %v", err)
	}
}

func TestLoadConfigReportsKnownResolversOnNotFound(t *testing.T) {
	json := `{
  "listeners": [
    {"type": "dnsServer", "config": {"listen": "127.0.0.1", "port": 5353, "protocol": "udp"}}
  ],
  "resolvers": {
    "noAnswer": {
      "noop": {}
    }
  },
  "rules": [],
  "defaultResolver": "missing-resolver"
}`

	_, err := LoadConfig(strings.NewReader(json))
	if err == nil {
		t.Fatalf("expected error for missing resolver")
	}
	if !strings.Contains(err.Error(), "registered resolvers: [noop]") {
		t.Fatalf("expected error to list registered resolvers, got: %v", err)
	}
}
