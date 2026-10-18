package config

import (
	"encoding/json"
	"errors"

	"github.com/zhouchenh/secDNS/internal/recordstore"
	"github.com/zhouchenh/secDNS/internal/snapshotfollower"
)

var ErrFollowerConfig = errors.New("config: invalid direct follower configuration")

// ParseFollowerRecordStores performs syntax and cross-mode validation only. It
// never opens a database or makes a network request.
func ParseFollowerRecordStores(raw []byte, legacy map[string]string, versioned map[string]recordstore.VersionedConfig) (map[string]snapshotfollower.Config, error) {
	root, err := objectFields(raw, false)
	if err != nil {
		return nil, err
	}
	value, ok := root["followerRecordStores"]
	if !ok {
		return nil, nil
	}
	entries, err := objectFields(value, true)
	if err != nil {
		return nil, ErrFollowerConfig
	}
	out := make(map[string]snapshotfollower.Config, len(entries))
	bindings := make(map[string]recordstore.FollowerConfig, len(entries))
	for name, rawEntry := range entries {
		fields, err := objectFields(rawEntry, true)
		if err != nil {
			return nil, ErrFollowerConfig
		}
		config := snapshotfollower.Config{StoreName: name}
		for field, rawValue := range fields {
			switch field {
			case "createIfMissing":
				if json.Unmarshal(rawValue, &config.CreateIfMissing) != nil {
					return nil, ErrFollowerConfig
				}
			default:
				var target *string
				switch field {
				case "sqlitePath":
					target = &config.SQLitePath
				case "clusterId":
					target = &config.Enrollment.ClusterID
				case "kind":
					target = &config.Enrollment.Kind
				case "rulesetId":
					target = &config.Enrollment.RulesetID
				case "lineageId":
					target = &config.Enrollment.LineageID
				case "authorityEpoch":
					target = &config.Enrollment.AuthorityEpoch
				case "nodeId":
					target = &config.NodeID
				case "authorityUrl":
					target = &config.AuthorityURL
				case "token":
					target = &config.Token
				default:
					return nil, ErrFollowerConfig
				}
				if string(rawValue) == "null" || json.Unmarshal(rawValue, target) != nil {
					return nil, ErrFollowerConfig
				}
			}
		}
		if len(fields) < 9 || len(fields) > 10 {
			return nil, ErrFollowerConfig
		}
		for _, required := range []string{"sqlitePath", "clusterId", "kind", "rulesetId", "lineageId", "authorityEpoch", "nodeId", "authorityUrl", "token"} {
			if _, present := fields[required]; !present {
				return nil, ErrFollowerConfig
			}
		}
		if err := snapshotfollower.ValidateConfig(config); err != nil {
			return nil, ErrFollowerConfig
		}
		out[name] = config
		bindings[name] = recordstore.FollowerConfig{SQLitePath: config.SQLitePath, Enrollment: config.Enrollment, CreateIfMissing: config.CreateIfMissing}
	}
	if err := recordstore.ValidateBindingsWithFollowers(legacy, versioned, bindings); err != nil {
		return nil, ErrFollowerConfig
	}
	return out, nil
}

func FollowerBindings(configs map[string]snapshotfollower.Config) map[string]recordstore.FollowerConfig {
	if len(configs) == 0 {
		return nil
	}
	out := make(map[string]recordstore.FollowerConfig, len(configs))
	for name, config := range configs {
		out[name] = recordstore.FollowerConfig{SQLitePath: config.SQLitePath, Enrollment: config.Enrollment, CreateIfMissing: config.CreateIfMissing}
	}
	return out
}

// ValidateStoreListenerTopology rejects mutation listeners on follower stores
// and constrains read-only snapshot credentials to writer-versioned stores.
func ValidateStoreListenerTopology(raw []byte, versioned map[string]recordstore.VersionedConfig, followers map[string]snapshotfollower.Config) error {
	root, err := objectFields(raw, false)
	if err != nil {
		return err
	}
	rawListeners, present := root["listeners"]
	if !present {
		return nil
	}
	var listeners []json.RawMessage
	if json.Unmarshal(rawListeners, &listeners) != nil {
		return ErrFollowerConfig
	}
	adminTokens := map[string]bool{}
	readerTokens := map[string]bool{}
	for _, rawListener := range listeners {
		var looseEntry map[string]json.RawMessage
		if json.Unmarshal(rawListener, &looseEntry) != nil {
			continue
		}
		var kind string
		if rawKind, ok := looseEntry["type"]; ok {
			_ = json.Unmarshal(rawKind, &kind)
		}
		if kind != "httpAdminServer" {
			continue
		}
		rawConfig, ok := looseEntry["config"]
		if !ok {
			continue
		}
		var looseConfig map[string]json.RawMessage
		if json.Unmarshal(rawConfig, &looseConfig) != nil {
			continue
		}
		if rawToken, ok := looseConfig["token"]; ok {
			var token string
			if json.Unmarshal(rawToken, &token) == nil {
				adminTokens[token] = true
			}
		}
		if rawReaders, ok := looseConfig["snapshotReaders"]; ok {
			var readers []json.RawMessage
			if json.Unmarshal(rawReaders, &readers) == nil {
				for _, rawReader := range readers {
					var fields map[string]json.RawMessage
					if json.Unmarshal(rawReader, &fields) != nil {
						continue
					}
					var token string
					if rawToken, present := fields["token"]; !present || json.Unmarshal(rawToken, &token) != nil {
						continue
					}
					if readerTokens[token] {
						return ErrFollowerConfig
					}
					readerTokens[token] = true
				}
			}
		}
		store := recordstore.DefaultName
		if rawStore, ok := looseConfig["store"]; ok {
			_ = json.Unmarshal(rawStore, &store)
			if store == "" {
				store = recordstore.DefaultName
			}
		}
		_, isFollower := followers[store]
		_, hasReaders := looseConfig["snapshotReaders"]
		if !isFollower && !hasReaders {
			continue
		}
		entry, err := objectFields(rawListener, true)
		if err != nil {
			return ErrFollowerConfig
		}
		rawConfig, ok = entry["config"]
		if !ok {
			return ErrFollowerConfig
		}
		fields, err := objectFields(rawConfig, true)
		if err != nil {
			return ErrFollowerConfig
		}
		store = recordstore.DefaultName
		if rawStore, ok := fields["store"]; ok {
			if json.Unmarshal(rawStore, &store) != nil {
				return ErrFollowerConfig
			}
			if store == "" {
				store = recordstore.DefaultName
			}
		}
		if _, isFollower = followers[store]; isFollower {
			return ErrFollowerConfig
		}
		if _, hasReaders = fields["snapshotReaders"]; hasReaders {
			if _, isVersioned := versioned[store]; !isVersioned {
				return ErrFollowerConfig
			}
		}
	}
	for token := range readerTokens {
		if adminTokens[token] {
			return ErrFollowerConfig
		}
	}
	return nil
}
