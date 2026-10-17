package config

import (
	"encoding/json"
	"github.com/zhouchenh/secDNS/internal/recordstore"
)

// ParseVersionedRecordStores performs syntax-only validation, including collisions.
func ParseVersionedRecordStores(raw []byte, legacy map[string]string) (map[string]recordstore.VersionedConfig, error) {
	root, e := objectFields(raw, false)
	if e != nil {
		return nil, e
	}
	value, ok := root["versionedRecordStores"]
	if !ok {
		return nil, nil
	}
	entries, e := objectFields(value, true)
	if e != nil {
		return nil, e
	}
	out := map[string]recordstore.VersionedConfig{}
	for n, v := range entries {
		fields, e := objectFields(v, true)
		if e != nil {
			return nil, recordstore.ErrVersionedInput
		}
		c := recordstore.VersionedConfig{}
		for k, r := range fields {
			var target *string
			switch k {
			case "backend":
				target = &c.Backend
			case "sqlitePath":
				target = &c.SQLitePath
			case "rulesetId":
				target = &c.RulesetID
			case "lineageId":
				target = &c.LineageID
			default:
				return nil, recordstore.ErrVersionedInput
			}
			if string(r) == "null" || json.Unmarshal(r, target) != nil {
				return nil, recordstore.ErrVersionedInput
			}
		}
		expected := 3
		if c.Backend == "sqlite" {
			expected = 4
		}
		if len(fields) != expected {
			return nil, recordstore.ErrVersionedInput
		}
		if c.Backend == "memory" {
			if _, ok := fields["sqlitePath"]; ok {
				return nil, recordstore.ErrVersionedInput
			}
		}
		out[n] = c
	}
	if e := recordstore.ValidateBindings(legacy, out); e != nil {
		return nil, e
	}
	return out, nil
}
