package doh

import (
	"bytes"
	"context"
	"errors"
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"io"
	"net"
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
func TestFailedRefreshCoalescedNonblocking(t *testing.T) {
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
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("error blocked on bootstrap: %v", elapsed)
	}
	deadline := time.Now().Add(time.Second)
	for bootstrap.calls.Load() < 2 || bootstrap.active.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("bootstrap did not finish")
		}
		time.Sleep(time.Millisecond)
	}
	if bootstrap.calls.Load() != 2 || bootstrap.peak.Load() != 1 {
		t.Fatalf("uncoalesced refresh calls=%d peak=%d", bootstrap.calls.Load(), bootstrap.peak.Load())
	}
	d.queryClient.urlMutex.RLock()
	defer d.queryClient.urlMutex.RUnlock()
	if len(d.queryClient.resolvedURLs) != 1 || d.queryClient.resolvedURLs[0] != "https://192.0.2.1/dns-query" {
		t.Fatal("failed refresh replaced working endpoints")
	}
}
func TestSuccessfulResponseCancelsLosers(t *testing.T) {
	for _, rcode := range []int{dns.RcodeSuccess, dns.RcodeServerFailure, dns.RcodeNameError} {
		t.Run(dns.RcodeToString[rcode], func(t *testing.T) { testResponseCancelsLoser(t, rcode) })
	}
}
func testResponseCancelsLoser(t *testing.T, rcode int) {
	entered := make(chan struct{})
	finished := make(chan struct{})
	u, _ := url.Parse("https://resolver.example/dns-query")
	d := &DoH{URL: u, QueryTimeout: time.Second, MaxConcurrentRequests: 2, requestLimiter: make(chan struct{}, 2)}
	d.initOnce.Do(func() {})
	d.queryClient = &client{serverName: "resolver.example", resolvedURLs: []string{"https://192.0.2.1/query", "https://192.0.2.2/query"}, httpClient: &http.Client{Transport: traceTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "192.0.2.2" {
			close(entered)
			<-r.Context().Done()
			close(finished)
			return nil, errors.New("released loser")
		}
		<-entered
		raw, _ := io.ReadAll(r.Body)
		q := new(dns.Msg)
		_ = q.Unpack(raw)
		reply := new(dns.Msg)
		reply.SetReply(q)
		reply.Rcode = rcode
		wire, _ := reply.Pack()
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(wire)), Header: make(http.Header)}, nil
	})}}
	q := new(dns.Msg)
	q.SetQuestion("fresh.example.", dns.TypeAAAA)
	reply, err := d.Resolve(q, 8)
	if err != nil || reply.Rcode != rcode {
		t.Fatalf("native response changed: %v %v", reply, err)
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("loser not canceled after success")
	}
}
func TestQueueWaitCountsAgainstBudget(t *testing.T) {
	u, _ := url.Parse("https://192.0.2.1/query")
	d := &DoH{URL: u, QueryTimeout: 40 * time.Millisecond, MaxConcurrentRequests: 1, requestLimiter: make(chan struct{}, 1)}
	d.initOnce.Do(func() {})
	d.queryClient = &client{serverName: "192.0.2.1", resolvedURLs: []string{u.String()}, httpClient: &http.Client{Timeout: d.QueryTimeout, Transport: traceTransport(func(r *http.Request) (*http.Response, error) { return nil, errors.New("synthetic failure") })}}
	d.requestLimiter <- struct{}{}
	go func() { time.Sleep(160 * time.Millisecond); <-d.requestLimiter }()
	q := new(dns.Msg)
	q.SetQuestion("fresh.example.", dns.TypeAAAA)
	start := time.Now()
	_, err := d.Resolve(q, 8)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline, got%v", err)
	}
	t.Logf("configured_ms=40 occupied_slot_ms=160 observed_ms=%d", time.Since(start).Milliseconds())
	if time.Since(start) > 120*time.Millisecond {
		t.Fatal("slot wait escaped budget")
	}
}
func TestRefreshUpdatesEndpointsWithoutBlockingSuccessfulQueries(t *testing.T) {
	u, _ := url.Parse("https://resolver.example/query")
	answer := new(dns.Msg)
	answer.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "resolver.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.IPv4(192, 0, 2, 2)}}
	d := &DoH{URL: u, Resolver: &stubResolver{response: answer}, QueryTimeout: time.Second, MaxConcurrentRequests: 2, requestLimiter: make(chan struct{}, 2)}
	d.initOnce.Do(func() {})
	d.queryClient = &client{serverName: "resolver.example", resolvedURLs: []string{"https://192.0.2.1/query"}, httpClient: &http.Client{Transport: traceTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "192.0.2.1" {
			return nil, errors.New("old endpoint down")
		}
		raw, _ := io.ReadAll(r.Body)
		q := new(dns.Msg)
		_ = q.Unpack(raw)
		reply := new(dns.Msg)
		reply.SetReply(q)
		reply.Rcode = dns.RcodeServerFailure
		wire, _ := reply.Pack()
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(wire)), Header: make(http.Header)}, nil
	})}}
	q := new(dns.Msg)
	q.SetQuestion("fresh.example.", dns.TypeAAAA)
	if _, err := d.Resolve(q, 8); err == nil {
		t.Fatal("old endpoint unexpectedly worked")
	}
	end := time.Now().Add(time.Second)
	for {
		d.queryClient.urlMutex.RLock()
		ready := len(d.queryClient.resolvedURLs) == 1 && d.queryClient.resolvedURLs[0] == "https://192.0.2.2/query"
		d.queryClient.urlMutex.RUnlock()
		if ready {
			break
		}
		if time.Now().After(end) {
			t.Fatal("refresh did not install endpoint")
		}
		time.Sleep(time.Millisecond)
	}
	// A refresh in flight must not block traffic using the usable snapshot.
	d.refreshMutex.Lock()
	d.refreshing = true
	d.refreshMutex.Unlock()
	reply, err := d.Resolve(q, 8)
	if err != nil || reply.Rcode != dns.RcodeServerFailure {
		t.Fatalf("native RCODE changed: reply=%v error=%v", reply, err)
	}
}

type deadlineBody struct{ ctx context.Context }

func (b deadlineBody) Read([]byte) (int, error) { <-b.ctx.Done(); return 0, b.ctx.Err() }
func (b deadlineBody) Close() error             { return nil }
func TestBodyDeadlineReleasesSlot(t *testing.T) {
	u, _ := url.Parse("https://192.0.2.1/query")
	d := &DoH{URL: u, QueryTimeout: 40 * time.Millisecond, MaxConcurrentRequests: 1, requestLimiter: make(chan struct{}, 1)}
	d.initOnce.Do(func() {})
	d.queryClient = &client{serverName: "192.0.2.1", resolvedURLs: []string{u.String()}, httpClient: &http.Client{Transport: traceTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: deadlineBody{r.Context()}}, nil
	})}}
	q := new(dns.Msg)
	q.SetQuestion("fresh.example.", dns.TypeA)
	start := time.Now()
	_, err := d.Resolve(q, 8)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 150*time.Millisecond {
		t.Fatalf("body deadline escaped: %v", err)
	}
	end := time.Now().Add(time.Second)
	for len(d.requestLimiter) != 0 {
		if time.Now().After(end) {
			t.Fatal("slot not released")
		}
		time.Sleep(time.Millisecond)
	}
}
func TestEmptySnapshotRecoversSameQuery(t *testing.T) {
	u, _ := url.Parse("https://resolver.example/query")
	answer := new(dns.Msg)
	answer.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "resolver.example.", Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.IPv4(192, 0, 2, 2)}}
	d := &DoH{URL: u, Resolver: &stubResolver{response: answer}, QueryTimeout: time.Second}
	d.initOnce.Do(func() {})
	d.queryClient = &client{serverName: "resolver.example", httpClient: &http.Client{Transport: traceTransport(func(r *http.Request) (*http.Response, error) {
		raw, _ := io.ReadAll(r.Body)
		q := new(dns.Msg)
		_ = q.Unpack(raw)
		reply := new(dns.Msg)
		reply.SetReply(q)
		wire, _ := reply.Pack()
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(wire))}, nil
	})}}
	q := new(dns.Msg)
	q.SetQuestion("fresh.example.", dns.TypeA)
	if reply, err := d.Resolve(q, 8); err != nil || reply == nil {
		t.Fatalf("cold endpoint recovery failed: %v", err)
	}
}
