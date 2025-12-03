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
