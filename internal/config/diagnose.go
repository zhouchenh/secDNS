package config

import (
	"fmt"

	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/pkg/listeners/server"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
)

// configError is a locatable configuration error. Where the opaque ErrBadConfig
// reported only that *something* in the file was wrong, configError names the
// section, the offending entry (by index), and the reason — so an operator can find
// the entry to fix instead of bisecting the whole file.
type configError struct {
	section string // top-level key: "listeners", "defaultResolver", "rules", or "(root)"
	locator string // entry within the section, e.g. `index 2`; empty for the section itself
	reason  string
}

func (e *configError) Error() string {
	msg := "config: " + e.section
	if e.locator != "" {
		msg += " " + e.locator
	}
	return msg + ": " + e.reason
}

// typeLookup is the registry signature shared by listeners, rules, and resolvers.
type typeLookup func(string) (descriptor.Describable, bool)

// jsonKind names the JSON type of a decoded value, for diagnostics.
func jsonKind(v interface{}) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case float64:
		return "number"
	case string:
		return "string"
	case []interface{}:
		return "array"
	case map[string]interface{}:
		return "object"
	default:
		return fmt.Sprintf("%T", v)
	}
}

// diagnoseConfig inspects the raw decoded JSON and returns a locatable error for the
// first problem it can pin down, or nil if it cannot improve on the opaque verdict
// (the caller then falls back to ErrBadConfig). It mirrors the loader's own
// accept/reject decisions — it re-runs the same section descriptors — so it never
// reports a problem the loader would have tolerated.
func diagnoseConfig(data interface{}) error {
	root, ok := data.(map[string]interface{})
	if !ok {
		return &configError{section: "(root)", reason: "must be a JSON object, got " + jsonKind(data)}
	}
	if err := diagnoseTypedArray(root, "listeners", server.Descriptor(), server.GetServerDescriptorByTypeName); err != nil {
		return err
	}
	if err := diagnoseDefaultResolver(root); err != nil {
		return err
	}
	// "rules" and "resolvers" are deliberately not diagnosed: the loader treats a
	// malformed or unknown-type entry in either as non-fatal (it falls back to an
	// empty section rather than failing the load), so they never reach this opaque-
	// error path, and reporting one as fatal would contradict the loader. Only the
	// sections without a default fallback — listeners and defaultResolver — can fail
	// the describe and land here.
	return nil
}

// diagnoseTypedArray validates that a present section is a JSON array whose entries
// are each accepted by the section descriptor, reporting the first that is not.
func diagnoseTypedArray(root map[string]interface{}, key string, sectionDescriptor descriptor.Describable, lookup typeLookup) error {
	raw, present := root[key]
	if !present {
		return nil // absence is handled by the loader's required-section checks
	}
	arr, ok := raw.([]interface{})
	if !ok {
		return &configError{section: key, reason: "must be a JSON array, got " + jsonKind(raw)}
	}
	for idx, entry := range arr {
		if reason := diagnoseTypedEntry(entry, sectionDescriptor, lookup); reason != "" {
			return &configError{section: key, locator: fmt.Sprintf("index %d", idx), reason: reason}
		}
	}
	return nil
}

// diagnoseDefaultResolver validates the required defaultResolver. A string value is a
// reference to a named resolver: the descriptor accepts it here and the reference is
// resolved later (a dangling name yields the registered-resolvers hint, not this
// path), so only a malformed inline definition is reported.
func diagnoseDefaultResolver(root map[string]interface{}) error {
	raw, present := root["defaultResolver"]
	if !present {
		return &configError{section: "defaultResolver", reason: "required, but missing"}
	}
	if _, isString := raw.(string); isString {
		return nil
	}
	if reason := diagnoseTypedEntry(raw, resolver.Descriptor(), resolver.GetResolverDescriptorByTypeName); reason != "" {
		return &configError{section: "defaultResolver", reason: reason}
	}
	return nil
}

// diagnoseTypedEntry returns a reason a {type, config} entry is malformed, or "" if
// the section descriptor accepts it. lookup, when non-nil, distinguishes an unknown
// type from a present type with an invalid config block.
func diagnoseTypedEntry(entry interface{}, sectionDescriptor descriptor.Describable, lookup typeLookup) string {
	obj, ok := entry.(map[string]interface{})
	if !ok {
		return `entry must be a {"type", "config"} object, got ` + jsonKind(entry)
	}
	rawType, present := obj["type"]
	if !present {
		return `entry is missing the required "type" field`
	}
	typeName, ok := rawType.(string)
	if !ok {
		return `entry "type" must be a string, got ` + jsonKind(rawType)
	}
	if typeName == "" {
		return `entry "type" must not be empty`
	}
	if lookup != nil {
		if _, known := lookup(typeName); !known {
			return fmt.Sprintf("unknown type %q", typeName)
		}
	}
	if !describes(sectionDescriptor, entry) {
		return fmt.Sprintf("type %q has an invalid config block", typeName)
	}
	return ""
}

// describes reports whether the descriptor accepts a value, using the same
// success/failure accounting the loader applies (success > 0, failure < 1).
func describes(d descriptor.Describable, v interface{}) bool {
	obj, s, f := d.Describe(v)
	return s > 0 && f < 1 && obj != nil
}
