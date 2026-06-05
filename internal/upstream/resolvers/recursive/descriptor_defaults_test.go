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
	if r.MaxQueries != defaultMaxQueries {
		t.Fatalf("expected maxQueries default %d, got %d", defaultMaxQueries, r.MaxQueries)
	}
	if r.MaxResolutionTime != defaultMaxResolutionTime {
		t.Fatalf("expected maxResolutionTime default %v, got %v", defaultMaxResolutionTime, r.MaxResolutionTime)
	}
}

func TestRecursiveDescriptorBudgetConfig(t *testing.T) {
	describable, ok := resolver.GetResolverDescriptorByTypeName("recursive")
	if !ok {
		t.Fatalf("descriptor for recursive not registered")
	}
	// Explicit values, including maxResolutionTime 0 to disable the time budget.
	cfg := map[string]interface{}{
		"maxQueries":        float64(64),
		"maxResolutionTime": float64(0),
	}
	obj, s, f := describable.Describe(cfg)
	if s < 1 || f > 0 {
		t.Fatalf("describe failed: success=%d failure=%d", s, f)
	}
	r := obj.(*Recursive)
	if r.MaxQueries != 64 {
		t.Fatalf("maxQueries = %d, want 64", r.MaxQueries)
	}
	if r.MaxResolutionTime != 0 {
		t.Fatalf("maxResolutionTime = %v, want 0 (disabled)", r.MaxResolutionTime)
	}
	// A below-range maxQueries is rejected, leaving the default.
	obj2, s2, f2 := describable.Describe(map[string]interface{}{"maxQueries": float64(1)})
	if s2 < 1 || f2 > 0 {
		t.Fatalf("describe failed: success=%d failure=%d", s2, f2)
	}
	if got := obj2.(*Recursive).MaxQueries; got != defaultMaxQueries {
		t.Fatalf("an out-of-range maxQueries should fall back to the default %d, got %d", defaultMaxQueries, got)
	}
}
