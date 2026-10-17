package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
)

// Presence tracking distinguishes null permanence from an omitted field and
// prevents simultaneous expiry modes from being silently coerced.
func (r *setRequest) UnmarshalJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("record request must be an object")
	}
	seen := map[string]bool{}
	for d.More() {
		token, err = d.Token()
		if err != nil {
			return err
		}
		name := token.(string)
		// Match encoding/json's case-insensitive field lookup, including Unicode
		// simple folding, before checking duplicates or expiry-field presence.
		recognized := false
		for _, known := range []string{"name", "type", "values", "ttl_seconds", "expires_in_seconds", "expires_at"} {
			if strings.EqualFold(name, known) {
				name = known
				recognized = true
				break
			}
		}
		if recognized && seen[name] {
			return errors.New("duplicate record request field")
		}
		if recognized {
			seen[name] = true
		}
		var value json.RawMessage
		if err = d.Decode(&value); err != nil {
			return err
		}
		if name == "values" {
			var values []json.RawMessage
			if err = json.Unmarshal(value, &values); err != nil {
				return errors.New("values must be strings")
			}
			for _, v := range values {
				var text string
				if bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
					return errors.New("values must be strings")
				}
				if err = json.Unmarshal(v, &text); err != nil {
					return errors.New("values must be strings")
				}
			}
		}
	}
	if _, err = d.Token(); err != nil {
		return err
	}
	type plain setRequest
	var out plain
	if err = json.Unmarshal(raw, &out); err != nil {
		return err
	}
	*r = setRequest(out)
	r.absolutePresent = seen["expires_at"]
	r.relativePresent = seen["expires_in_seconds"]
	return nil
}
