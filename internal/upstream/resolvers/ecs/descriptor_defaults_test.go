package ecs

import (
	"testing"

	ednsecs "github.com/zhouchenh/secDNS/internal/edns/ecs"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"

	_ "github.com/zhouchenh/secDNS/internal/config/resolver"
	_ "github.com/zhouchenh/secDNS/internal/config/typed/resolver"
	_ "github.com/zhouchenh/secDNS/internal/upstream/resolvers/no/answer/resolver"
)

func TestECSDescriptorUsesStringEcsDefault(t *testing.T) {
	describable, ok := resolver.GetResolverDescriptorByTypeName("ecs")
	if !ok {
		t.Fatalf("descriptor for ecs not registered")
	}
	cfg := map[string]interface{}{
		"resolver": map[string]interface{}{
			"type":   "noAnswer",
			"config": map[string]interface{}{},
		},
	}
	obj, s, f := describable.Describe(cfg)
	if s < 1 || f > 0 {
		t.Fatalf("describe failed: success=%d failure=%d", s, f)
	}
	r := obj.(*Resolver)
	if r.EcsMode != string(ednsecs.ModePassthrough) {
		t.Fatalf("expected ecsMode default %q, got %q", ednsecs.ModePassthrough, r.EcsMode)
	}
}
