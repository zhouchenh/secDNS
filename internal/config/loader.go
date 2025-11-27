package config

import (
	"encoding/json"
	common2 "github.com/zhouchenh/secDNS/internal/common"
	named "github.com/zhouchenh/secDNS/internal/config/named/resolver"
	"github.com/zhouchenh/secDNS/internal/core"
	"io"
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
	rawConfig, s, f := Descriptor().Describe(data)
	ok := s > 0 && f < 1
	if !ok {
		return nil, ErrBadConfig
	}
	config, ok := rawConfig.(*Config)
	if !ok || config == nil || config.Resolvers == nil {
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
		instance.AcceptProvider(p, common2.ErrOutputErrorHandler)
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
		return nil, err
	}
	return instance, nil
}
