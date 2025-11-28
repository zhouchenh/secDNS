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
