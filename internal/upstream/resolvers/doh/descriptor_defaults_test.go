package doh

import (
	"testing"

	"github.com/zhouchenh/secDNS/internal/edns/ecs"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"

	_ "github.com/zhouchenh/secDNS/internal/config/resolver"
	_ "github.com/zhouchenh/secDNS/internal/config/typed/resolver"
	_ "github.com/zhouchenh/secDNS/internal/upstream/resolvers/no/answer/resolver"
)

func TestDoHDescriptorUsesStringEcsDefault(t *testing.T) {
	describable, ok := resolver.GetResolverDescriptorByTypeName("doh")
	if !ok {
		t.Fatalf("descriptor for doh not registered")
	}
	cfg := map[string]interface{}{
		"url": "https://dns.google/dns-query",
		"urlResolver": map[string]interface{}{
			"type":   "noAnswer",
			"config": map[string]interface{}{},
		},
	}
	obj, s, f := describable.Describe(cfg)
	if s < 1 || f > 0 {
		t.Fatalf("describe failed: success=%d failure=%d", s, f)
	}
	d := obj.(*DoH)
	if d.EcsMode != string(ecs.ModePassthrough) {
		t.Fatalf("expected ecsMode default %q, got %q", ecs.ModePassthrough, d.EcsMode)
	}
}
