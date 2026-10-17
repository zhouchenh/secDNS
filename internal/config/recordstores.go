package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/zhouchenh/secDNS/internal/recordstore"
	"io"
	"sort"
)

// objectFields rejects duplicate keys rather than silently rebinding a database.
func objectFields(raw []byte, strict bool) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("record stores require JSON objects")
	}
	out := map[string]json.RawMessage{}
	for d.More() {
		token, err = d.Token()
		if err != nil {
			return nil, err
		}
		name := token.(string)
		if _, ok := out[name]; ok && (strict || name == "recordStores" || name == "versionedRecordStores") {
			return nil, errors.New("duplicate record store configuration field")
		}
		var value json.RawMessage
		if err = d.Decode(&value); err != nil {
			return nil, err
		}
		out[name] = value
	}
	if _, err = d.Token(); err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errors.New("trailing JSON data")
	}
	return out, nil
}

// ParseRecordStores validates the optional persistence configuration without I/O.
func ParseRecordStores(raw []byte) (map[string]string, error) {
	root, err := objectFields(raw, false)
	if err != nil {
		return nil, err
	}
	value, ok := root["recordStores"]
	if !ok {
		return nil, nil
	}
	entries, err := objectFields(value, true)
	if err != nil {
		return nil, err
	}
	paths := map[string]string{}
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		options, err := objectFields(entries[name], true)
		if err != nil {
			return nil, err
		}
		if len(options) != 1 {
			return nil, errors.New("record store requires only sqlitePath")
		}
		rawPath, ok := options["sqlitePath"]
		if !ok {
			return nil, errors.New("record store requires sqlitePath")
		}
		var path string
		if err = json.Unmarshal(rawPath, &path); err != nil {
			return nil, errors.New("sqlitePath must be a string")
		}
		paths[name] = path
	}
	if err := recordstore.ValidatePaths(paths); err != nil {
		return nil, err
	}
	return paths, nil
}
