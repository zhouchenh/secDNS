package doh

import (
	"errors"
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type traceBootstrap struct {
	calls  atomic.Int32
	active atomic.Int32
	peak   atomic.Int32
	delay  time.Duration
}

func (s *traceBootstrap) Type() descriptor.Type { return descriptor.TypeOfNew(new(*traceBootstrap)) }
func (s *traceBootstrap) TypeName() string      { return "trace-bootstrap" }
func (s *traceBootstrap) Resolve(q *dns.Msg, _ int) (*dns.Msg, error) {
	s.calls.Add(1)
	n := s.active.Add(1)
	defer s.active.Add(-1)
	for p := s.peak.Load(); n > p && !s.peak.CompareAndSwap(p, n); p = s.peak.Load() {
	}
	time.Sleep(s.delay)
	return nil, errors.New("synthetic bootstrap unavailable")
}

type traceTransport func(*http.Request) (*http.Response, error)

func (f traceTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestDiagnosticFailedRefresh(t *testing.T) {
	bootstrap := &traceBootstrap{delay: 150 * time.Millisecond}
	u, _ := url.Parse("https://resolver.example/dns-query")
	d := &DoH{URL: u, QueryTimeout: 50 * time.Millisecond, Resolver: bootstrap, MaxConcurrentRequests: 256, requestLimiter: make(chan struct{}, 256)}
	d.initOnce.Do(func() {})
	d.queryClient = &client{serverName: "resolver.example", resolvedURLs: []string{"https://192.0.2.1/dns-query"}, httpClient: &http.Client{Timeout: d.QueryTimeout, Transport: traceTransport(func(r *http.Request) (*http.Response, error) { return nil, errors.New("synthetic HTTP failure") })}}
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			q := new(dns.Msg)
			q.SetQuestion("fresh.example.", dns.TypeAAAA)
			_, _ = d.Resolve(q, 8)
		}()
	}
	wg.Wait()
	t.Logf("failed_calls=8 configured_timeout_ms=50 elapsed_ms=%d bootstrap_calls=%d peak_bootstrap=%d", time.Since(start).Milliseconds(), bootstrap.calls.Load(), bootstrap.peak.Load())
	if bootstrap.calls.Load() != 16 {
		t.Fatalf("expected current A/AAAA refresh amplification, got%d", bootstrap.calls.Load())
	}
}
