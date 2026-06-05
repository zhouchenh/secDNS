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

func TestProvideToleratesLongLine(t *testing.T) {
	// A >64 KiB line (here a long comment) exceeds the default bufio.Scanner token
	// limit. With the default buffer the scan aborts at this line and drops the valid
	// entry after it; with the raised buffer parsing continues.
	longComment := "#" + strings.Repeat("x", 100<<10)
	path := writeTempConf(t, longComment+"\nserver=/example.com/8.8.8.8\n")
	conf := &DnsmasqConf{FilePath: path, Resolver: noopResolver{}}

	var domains []string
	for conf.Provide(func(name string, r resolver.Resolver) {
		domains = append(domains, name)
	}, func(err error) {
		t.Fatalf("unexpected error: %v", err)
	}) {
	}

	if len(domains) != 1 || domains[0] != "example.com." {
		t.Fatalf("a long line aborted the scan; got %v", domains)
	}
}

func TestProvideTruncatesAtEntryCap(t *testing.T) {
	defer func(prev int) { maxEntries = prev }(maxEntries)
	maxEntries = 3

	var lines []string
	for _, d := range []string{"a", "b", "c", "d", "e"} {
		lines = append(lines, "server=/"+d+".example.com/8.8.8.8")
	}
	path := writeTempConf(t, strings.Join(lines, "\n")+"\n")
	conf := &DnsmasqConf{FilePath: path, Resolver: noopResolver{}}

	var domains []string
	var truncErr error
	for conf.Provide(func(name string, r resolver.Resolver) {
		domains = append(domains, name)
	}, func(err error) {
		truncErr = err
	}) {
	}

	if len(domains) != 3 {
		t.Fatalf("entry cap not enforced: got %d entries, want 3", len(domains))
	}
	var te TruncatedError
	if !errors.As(truncErr, &te) {
		t.Fatalf("want TruncatedError when the cap is hit, got %v", truncErr)
	}
	if !strings.Contains(te.Error(), "3-entry limit") {
		t.Fatalf("TruncatedError should name the limit, got %q", te.Error())
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
