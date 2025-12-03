package nameserver

import (
	"testing"

	"github.com/zhouchenh/secDNS/internal/edns/ecs"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
)

func TestNameServerDescriptorUsesStringEcsDefault(t *testing.T) {
	describable, ok := resolver.GetResolverDescriptorByTypeName("nameServer")
	if !ok {
		t.Fatalf("descriptor for nameServer not registered")
	}
	cfg := map[string]interface{}{
		"address": "1.1.1.1",
	}
	obj, s, f := describable.Describe(cfg)
	if s < 1 || f > 0 {
		t.Fatalf("describe failed: success=%d failure=%d", s, f)
	}
	ns := obj.(*NameServer)
	if ns.EcsMode != string(ecs.ModePassthrough) {
		t.Fatalf("expected ecsMode default %q, got %q", ecs.ModePassthrough, ns.EcsMode)
	}
}
