package config

import (
	"encoding/json"
	"fmt"
	"github.com/zhouchenh/secDNS/internal/common"
	named "github.com/zhouchenh/secDNS/internal/config/named/resolver"
	"github.com/zhouchenh/secDNS/internal/core"
	"github.com/zhouchenh/secDNS/internal/upstream/resolvers/authoritative"
	"github.com/zhouchenh/secDNS/internal/upstream/resolvers/policy"
	"github.com/zhouchenh/secDNS/pkg/listeners/server"
	"github.com/zhouchenh/secDNS/pkg/rules/provider"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
	"io"
	"sort"
	"sync"
)

// Descriptor construction uses a shared named-resolver assignment callback and
// pending list. Keep the entire build, including diagnostics and initialization,
// in one transaction so independent loads cannot bind each other's resolvers.
var loadMu sync.Mutex

// LoadConfig constructs an instance without starting listeners. Concurrent calls
// to LoadConfig and ValidateConfig are serialized during configuration building.
func LoadConfig(r io.Reader) (core.Instance, error) {
	return loadConfig(r, false)
}

// ValidateConfig runs startup configuration checks without starting listeners or
// making DNS queries, and additionally rejects errors reported by rule providers.
// Existing permissive descriptor parsing is unchanged; this is not strict schema
// validation of every configuration field or rule entry.
// It may run concurrently with LoadConfig or another ValidateConfig call.
func ValidateConfig(r io.Reader) error {
	_, err := loadConfig(r, true)
	return err
}

func loadConfig(r io.Reader, strict bool) (core.Instance, error) {
	rawData, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var data interface{}
	err = json.Unmarshal(rawData, &data)
	if err != nil {
		return nil, err
	}
	if root, ok := data.(map[string]interface{}); ok {
		if err := validateAdminAuthSyntax(rawData); err != nil {
			return nil, err
		}
		legacy, parseErr := ParseRecordStores(rawData)
		if parseErr != nil {
			return nil, parseErr
		}
		versioned, parseErr := ParseVersionedRecordStores(rawData, legacy)
		if parseErr != nil {
			return nil, parseErr
		}
		followers, parseErr := ParseFollowerRecordStores(rawData, legacy, versioned)
		if parseErr != nil {
			return nil, parseErr
		}
		if _, listenersAreArray := root["listeners"].([]interface{}); listenersAreArray {
			if parseErr = ValidateStoreListenerTopology(rawData, versioned, followers); parseErr != nil {
				return nil, parseErr
			}
		}
		if parseErr = ValidateExactStoreOverlayTopology(rawData, legacy, versioned, followers); parseErr != nil {
			return nil, parseErr
		}
	}
	if strict {
		if root, ok := data.(map[string]interface{}); ok {
			if rawRules, present := root["rules"]; present {
				rules, ok := rawRules.([]interface{})
				if !ok {
					return nil, fmt.Errorf("config: rules must be an array")
				}
				for index, raw := range rules {
					rule, ok := raw.(map[string]interface{})
					if !ok {
						return nil, fmt.Errorf("config: rules index %d: must be an object", index)
					}
					kind, ok := rule["type"].(string)
					if !ok || kind == "" {
						return nil, fmt.Errorf("config: rules index %d: type must be a non-empty string", index)
					}
					if _, known := provider.GetProviderDescriptorByTypeName(kind); !known {
						return nil, fmt.Errorf("config: rules index %d: unknown provider type %q", index, kind)
					}
				}
			}
		}
	}
	loadMu.Lock()
	defer func() {
		named.SetNameRegistryAssignmentFunction(nil)
		named.ResetKnownNamedResolvers()
		loadMu.Unlock()
	}()
	// Start from a clean slate: describing the config below appends every string-referenced
	// resolver to a process-global pending list, and a previous LoadConfig that failed
	// before resolving that list would otherwise leave stale names behind.
	named.ResetKnownNamedResolvers()
	rawConfig, s, f := Descriptor().Describe(data)
	ok := s > 0 && f < 1
	if !ok {
		if diag := diagnoseConfig(data); diag != nil {
			return nil, diag
		}
		return nil, ErrBadConfig
	}
	config, ok := rawConfig.(*Config)
	if !ok || config == nil || config.Resolvers == nil {
		if diag := diagnoseConfig(data); diag != nil {
			return nil, diag
		}
		return nil, ErrBadConfig
	}
	if len(config.Listeners) < 1 {
		return nil, ErrMissingListenersConfig
	}
	if config.DefaultResolver == nil {
		return nil, ErrMissingDefaultResolverConfig
	}
	authBindings, err := parseAdminBindings(data, config)
	if err != nil {
		return nil, err
	}
	statusBindings, err := parseFollowerStatusBindings(rawData, config)
	if err != nil {
		return nil, err
	}
	selected, err := bindListeners(data, config)
	if err != nil {
		return nil, err
	}
	instance := core.NewInstance()
	instance.AddListener(config.Listeners...)
	instance.AddListener()
	var providerError error
	for index, p := range config.Rules {
		instance.AcceptProvider(p, func(err error) {
			if !strict {
				common.ErrOutputErrorHandler(err)
			}
			if providerError == nil && err != nil {
				// Keep only the first error: a malformed large list must not create
				// an unbounded collection of validation diagnostics.
				providerError = fmt.Errorf("config: loaded rule provider index %d: %w", index, err)
			}
		})
	}
	instance.SetDefaultResolver(config.DefaultResolver)
	instance.SetResolutionDepth(config.ResolutionDepth)
	instanceResolver, ok := instance.GetResolver()
	if !ok {
		return nil, ErrUnexpectedBadConfig
	}
	err = config.Resolvers.NameResolver("", instanceResolver)
	if err != nil {
		return nil, err
	}
	err = named.InitKnownNamedResolvers()
	if err != nil {
		if _, ok := err.(named.NotFoundError); ok {
			names := config.Resolvers.Names()
			if len(names) > 0 {
				sort.Strings(names)
				return nil, fmt.Errorf("%w (registered resolvers: %v)", err, names)
			}
		}
		return nil, err
	}
	roots := []resolver.Resolver{instanceResolver}
	for _, name := range config.Resolvers.Names() {
		r, _ := config.Resolvers.Lookup(name)
		if _, ok := r.(*policy.Policy); ok {
			roots = append(roots, r)
		}
		if _, ok := r.(*authoritative.ExactStoreOverlay); ok {
			roots = append(roots, r)
		}
	}
	selected = selected || containsPolicyGraph(roots)
	if providerError != nil && (strict || selected) {
		return nil, providerError
	}
	if selected {
		for _, listener := range config.Listeners {
			if binding, ok := listener.(*server.Binding); ok {
				if binding.Resolver != nil {
					roots = append(roots, binding.Resolver)
				}
				if binding.PeerResolver != nil {
					roots = append(roots, binding.PeerResolver.ResolverDependencies()...)
				}
			}
		}
		if config.sourcePolicy != nil {
			for _, id := range config.sourcePolicy.resolverIDs {
				roots = append(roots, config.sourcePolicy.resolvers[id])
			}
		}
		if err := validateResolverGraph(roots); err != nil {
			return nil, err
		}
		if err := validateExactStoreOverlayCachePlacement(roots); err != nil {
			return nil, err
		}
		if err := validateSourcePolicyCacheIsolation(config.sourcePolicy); err != nil {
			return nil, err
		}
	}
	if len(authBindings) > 0 || len(statusBindings) > 0 {
		return &authInstance{Instance: instance, bindings: authBindings, followerStatus: statusBindings}, nil
	}
	return instance, nil
}
