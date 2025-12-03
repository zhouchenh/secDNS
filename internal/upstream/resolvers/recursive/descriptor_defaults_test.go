package recursive

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/internal/edns/ecs"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
)

func TestRecursiveDescriptorUsesStringEcsDefault(t *testing.T) {
	describable, ok := resolver.GetResolverDescriptorByTypeName("recursive")
	if !ok {
		t.Fatalf("descriptor for recursive not registered")
	}
	cfg := map[string]interface{}{
		"validateDNSSEC": "permissive",
		"qnameMinimize":  true,
		"ednsSize":       float64(1232),
	}
	obj, s, f := describable.Describe(cfg)
	if s < 1 || f > 0 {
		if dd, ok := describable.(*descriptor.Descriptor); ok {
			val := reflect.New(reflect.Type(dd.Type)).Elem()
			var details []string
			for idx, filler := range dd.Filler.(descriptor.Fillers) {
				sPart, fPart := filler.Fill(val, cfg)
				if fPart > 0 {
					details = append(details, fmt.Sprintf("filler[%d] type=%T s=%d f=%d", idx, filler, sPart, fPart))
				}
			}
			t.Fatalf("describe failed: success=%d failure=%d details=%v", s, f, details)
		}
		t.Fatalf("describe failed: success=%d failure=%d", s, f)
	}
	r := obj.(*Recursive)
	if r.EcsMode != string(ecs.ModePassthrough) {
		t.Fatalf("expected ecsMode default %q, got %q", ecs.ModePassthrough, r.EcsMode)
	}
}
