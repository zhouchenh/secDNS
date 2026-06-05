package config

import (
	"encoding/json"
	"fmt"
	"github.com/zhouchenh/secDNS/internal/common"
	named "github.com/zhouchenh/secDNS/internal/config/named/resolver"
	"github.com/zhouchenh/secDNS/internal/core"
	"io"
	"sort"
)

func LoadConfig(r io.Reader) (core.Instance, error) {
	rawData, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var data interface{}
	err = json.Unmarshal(rawData, &data)
	if err != nil {
		return nil, err
	}
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
	instance := core.NewInstance()
	instance.AddListener(config.Listeners...)
	instance.AddListener()
	for _, p := range config.Rules {
		instance.AcceptProvider(p, common.ErrOutputErrorHandler)
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
	return instance, nil
}
