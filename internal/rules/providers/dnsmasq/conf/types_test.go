package conf

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"github.com/zhouchenh/secDNS/pkg/upstream/resolver"
)

type noopResolver struct{}

func (noopResolver) Type() descriptor.Type { return nil }
func (noopResolver) TypeName() string      { return "noop" }
func (noopResolver) Resolve(_ *dns.Msg, _ int) (*dns.Msg, error) {
	return nil, nil
}

func TestProvideNilResolver(t *testing.T) {
	conf := &DnsmasqConf{
		FilePath: "test.conf",
		Resolver: nil,
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
	var nilErr NilResolverError
	if !errors.As(receivedErr, &nilErr) {
		t.Fatalf("Provide() error = %v, want NilResolverError", receivedErr)
	}
}

func TestProvideParsesEntries(t *testing.T) {
	path := writeTempConf(t, strings.Join([]string{
		"server=/example.com/8.8.8.8",
		"# comment line",
		"server=/example.org/",
	}, "\n"))
	conf := &DnsmasqConf{
		FilePath: path,
		Resolver: noopResolver{},
	}

	var domains []string
	for conf.Provide(func(name string, r resolver.Resolver) {
		domains = append(domains, name)
	}, func(err error) {
		t.Fatalf("unexpected error: %v", err)
	}) {
	}

	want := []string{"example.com.", "example.org."}
	if len(domains) != len(want) {
		t.Fatalf("got %v domains, want %v", domains, want)
	}
	for i, d := range want {
		if domains[i] != d {
			t.Fatalf("domain[%d]=%s want %s", i, domains[i], d)
		}
	}
}

func TestProvideInvalidDomainReported(t *testing.T) {
	path := writeTempConf(t, "server=/invalid domain/1.1.1.1\n")
	conf := &DnsmasqConf{
		FilePath: path,
		Resolver: noopResolver{},
	}
	var invalidErr error
	conf.Provide(func(name string, r resolver.Resolver) {
		t.Fatalf("expected no valid domains, got %s", name)
	}, func(err error) {
		invalidErr = err
	})

	var domainErr InvalidDomainNameError
	if !errors.As(invalidErr, &domainErr) {
		t.Fatalf("want InvalidDomainNameError, got %v", invalidErr)
	}
}

func TestDnsmasqConfReset(t *testing.T) {
	path := writeTempConf(t, "server=/example.com/")
	conf := &DnsmasqConf{
		FilePath: path,
		Resolver: noopResolver{},
	}
	var count int
	for conf.Provide(func(name string, r resolver.Resolver) {
		count++
	}, func(err error) {
		t.Fatalf("unexpected error: %v", err)
	}) {
	}
	if count != 1 {
		t.Fatalf("expected 1 entry, got %d", count)
	}
	conf.Reset()
	count = 0
	for conf.Provide(func(name string, r resolver.Resolver) {
		count++
	}, func(err error) {
		t.Fatalf("unexpected error: %v", err)
	}) {
	}
	if count != 1 {
		t.Fatalf("expected reset to allow reread, got %d entries", count)
	}
}

func writeTempConf(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsmasq.conf")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write temp conf: %v", err)
	}
	return path
}
