package conf

import (
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
	"testing"
)

func TestProvideNilResolver(t *testing.T) {
	conf := &DnsmasqConf{
		FilePath:    "test.conf",
		fileContent: []string{"server=/example.com/"},
		Resolver:    nil,
	}

	var receivedErr error
	more := conf.Provide(func(name string, r resolver.Resolver) {
		t.Fatalf("receive should not be called when resolver is nil")
	}, func(err error) {
		receivedErr = err
	})

	if more {
		t.Fatalf("Provide() should stop when resolver is nil")
	}
	if _, ok := receivedErr.(NilResolverError); !ok {
		t.Fatalf("Provide() error = %v, want NilResolverError", receivedErr)
	}
}
