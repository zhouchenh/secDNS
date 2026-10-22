package doh

import (
	"crypto/x509"
	"github.com/miekg/dns"
	"github.com/zhouchenh/go-descriptor"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type loopbackBootstrap struct{}

func (*loopbackBootstrap) Type() descriptor.Type {
	return descriptor.TypeOfNew(new(*loopbackBootstrap))
}
func (*loopbackBootstrap) TypeName() string { return "loopback-bootstrap" }
func (*loopbackBootstrap) Resolve(q *dns.Msg, _ int) (*dns.Msg, error) {
	r := new(dns.Msg)
	r.SetReply(q)
	if q.Question[0].Qtype == dns.TypeA {
		r.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("127.0.0.1")}}
	}
	return r, nil
}

// Real TLS sockets, named SNI/Host and IP bootstrap exercise the production transport.
func TestHTTP2CancellationConnectionReuse(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "HTTP1", true: "HTTP2"}[h2], func(t *testing.T) {
			var connections, canceled, protocol atomic.Int32
			var blocked atomic.Bool
			entered := make(chan struct{}, 16)
			s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				protocol.Store(int32(r.ProtoMajor))
				if r.TLS.ServerName != "example.com" || r.Host != "example.com" {
					t.Errorf("identity changed: SNI=%q Host=%q", r.TLS.ServerName, r.Host)
				}
				raw, e := io.ReadAll(r.Body)
				if e != nil {
					return
				}
				q := new(dns.Msg)
				if q.Unpack(raw) != nil {
					return
				}
				if blocked.Load() {
					entered <- struct{}{}
					<-r.Context().Done()
					canceled.Add(1)
					return
				}
				reply := new(dns.Msg)
				reply.SetReply(q)
				wire, _ := reply.Pack()
				w.Header().Set("Content-Type", "application/dns-message")
				_, _ = w.Write(wire)
			}))
			s.EnableHTTP2 = true
			s.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					connections.Add(1)
				}
			}
			s.StartTLS()
			defer s.Close()
			u, _ := url.Parse(s.URL)
			u.Host = net.JoinHostPort("example.com", u.Port())
			d := &DoH{URL: u, Resolver: &loopbackBootstrap{}, QueryTimeout: time.Second}
			d.initOnce.Do(d.initClient)
			tr := d.queryClient.httpClient.Transport.(*http.Transport)
			tr.ForceAttemptHTTP2 = h2
			roots := x509.NewCertPool()
			roots.AddCert(s.Certificate())
			tr.TLSClientConfig.RootCAs = roots
			defer tr.CloseIdleConnections()
			query := func() error {
				q := new(dns.Msg)
				q.SetQuestion("synthetic.example.", dns.TypeA)
				_, e := d.Resolve(q, 8)
				return e
			}
			if e := query(); e != nil {
				t.Fatal(e)
			}
			if protocol.Load() != map[bool]int32{false: 1, true: 2}[h2] {
				t.Fatalf("protocol=%d", protocol.Load())
			}
			blocked.Store(true)
			var wg sync.WaitGroup
			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if query() == nil {
						t.Error("blocked query succeeded")
					}
				}()
			}
			for i := 0; i < 8; i++ {
				select {
				case <-entered:
				case <-time.After(3 * time.Second):
					t.Fatal("burst did not enter")
				}
			}
			wg.Wait()
			deadline := time.Now().Add(time.Second)
			for canceled.Load() != 8 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if canceled.Load() != 8 {
				t.Fatalf("canceled handlers=%d", canceled.Load())
			}
			before := connections.Load()
			blocked.Store(false)
			for i := 0; i < 8; i++ {
				if e := query(); e != nil {
					t.Fatal(e)
				}
			}
			t.Logf("canceled=8 protocol=%d connections_before_recovery=%d after=%d", protocol.Load(), before, connections.Load())
			if h2 && connections.Load() != 1 {
				t.Fatalf("warmed HTTP2 connection not retained: %d", connections.Load())
			}
			if !h2 && connections.Load() <= before {
				t.Fatal("HTTP1 comparison did not reconnect")
			}
		})
	}
}

func TestHTTP2NegotiationAndCertificateValidation(t *testing.T) {
	for _, tc := range []struct {
		name                string
		serverH2, wrongName bool
		want                int32
	}{
		{"H2", true, false, 2}, {"H1Fallback", false, false, 1}, {"WrongCertificate", true, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var protocol atomic.Int32
			s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				protocol.Store(int32(r.ProtoMajor))
				raw, _ := io.ReadAll(r.Body)
				q := new(dns.Msg)
				_ = q.Unpack(raw)
				reply := new(dns.Msg)
				reply.SetReply(q)
				wire, _ := reply.Pack()
				_, _ = w.Write(wire)
			}))
			s.EnableHTTP2 = tc.serverH2
			s.StartTLS()
			defer s.Close()
			u, _ := url.Parse(s.URL)
			name := "example.com"
			if tc.wrongName {
				name = "wrong.example"
			}
			u.Host = net.JoinHostPort(name, u.Port())
			d := &DoH{URL: u, Resolver: &loopbackBootstrap{}, QueryTimeout: time.Second}
			d.initOnce.Do(d.initClient)
			tr := d.queryClient.httpClient.Transport.(*http.Transport)
			defer tr.CloseIdleConnections()
			roots := x509.NewCertPool()
			roots.AddCert(s.Certificate())
			tr.TLSClientConfig.RootCAs = roots
			q := new(dns.Msg)
			q.SetQuestion("synthetic.example.", dns.TypeAAAA)
			_, e := d.Resolve(q, 8)
			if tc.wrongName {
				if e == nil {
					t.Fatal("invalid certificate accepted")
				}
			} else if e != nil {
				t.Fatal(e)
			}
			if protocol.Load() != tc.want {
				t.Fatalf("protocol=%d want=%d", protocol.Load(), tc.want)
			}
		})
	}
}
