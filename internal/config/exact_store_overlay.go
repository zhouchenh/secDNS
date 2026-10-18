package config

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/zhouchenh/secDNS/internal/recordstore"
	"github.com/zhouchenh/secDNS/internal/snapshotfollower"
)

var ErrExactStoreOverlayConfig = errors.New("config: invalid exact store overlay")

// ValidateExactStoreOverlayTopology validates declared store modes without
// opening a database, constructing a binding, or resolving a named fallback.
func ValidateExactStoreOverlayTopology(raw []byte, legacy map[string]string, versioned map[string]recordstore.VersionedConfig, followers map[string]snapshotfollower.Config) error {
	var root map[string]interface{}
	if json.Unmarshal(raw, &root) != nil {
		return ErrExactStoreOverlayConfig
	}
	validate := func(value interface{}) error {
		config, ok := value.(map[string]interface{})
		if !ok {
			return ErrExactStoreOverlayConfig
		}
		for field := range config {
			switch field {
			case "store", "completeCNAME", "negativeTTL", "fallback":
			default:
				return ErrExactStoreOverlayConfig
			}
		}
		if fallback, present := config["fallback"]; !present || fallback == nil {
			return ErrExactStoreOverlayConfig
		}
		store, ok := config["store"].(string)
		if !ok || store == "" || strings.TrimSpace(store) != store {
			return ErrExactStoreOverlayConfig
		}
		if _, wrongMode := legacy[store]; wrongMode {
			return ErrExactStoreOverlayConfig
		}
		if _, writer := versioned[store]; writer {
			return nil
		}
		if _, follower := followers[store]; follower {
			return nil
		}
		return ErrExactStoreOverlayConfig
	}
	if resolverGroups, ok := root["resolvers"].(map[string]interface{}); ok {
		if rawDefinitions, present := resolverGroups["exactStoreOverlay"]; present {
			definitions, ok := rawDefinitions.(map[string]interface{})
			if !ok {
				return ErrExactStoreOverlayConfig
			}
			for _, definition := range definitions {
				if err := validate(definition); err != nil {
					return err
				}
			}
		}
	}
	pending := make([]interface{}, 0, 4)
	for _, name := range []string{"defaultResolver", "resolvers", "rules", "listeners"} {
		if value, present := root[name]; present {
			pending = append(pending, value)
		}
	}
	for visited := 0; len(pending) > 0; visited++ {
		if visited >= 65536 {
			return ErrExactStoreOverlayConfig
		}
		value := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		switch typed := value.(type) {
		case []interface{}:
			pending = append(pending, typed...)
		case map[string]interface{}:
			if kind, _ := typed["type"].(string); kind == "exactStoreOverlay" {
				if err := validate(typed["config"]); err != nil {
					return err
				}
			}
			for _, child := range typed {
				pending = append(pending, child)
			}
		}
	}
	return nil
}
