package nameserver

import (
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// fakeConn is a no-op net.Conn that records how many times it was closed.
type fakeConn struct{ closed int32 }

func (f *fakeConn) Read([]byte) (int, error)         { return 0, nil }
func (f *fakeConn) Write(b []byte) (int, error)      { return len(b), nil }
func (f *fakeConn) Close() error                     { atomic.AddInt32(&f.closed, 1); return nil }
func (f *fakeConn) LocalAddr() net.Addr              { return nil }
func (f *fakeConn) RemoteAddr() net.Addr             { return nil }
func (f *fakeConn) SetDeadline(time.Time) error      { return nil }
func (f *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(time.Time) error { return nil }

func TestConnPoolBoundsIdle(t *testing.T) {
	p := newConnPool()
	p.maxIdle = 2
	conns := []*fakeConn{{}, {}, {}}
	for _, fc := range conns {
		p.put(&dns.Conn{Conn: fc})
	}
	if atomic.LoadInt32(&conns[2].closed) != 1 {
		t.Fatalf("surplus connection beyond maxIdle should be closed on put, closed=%d", conns[2].closed)
	}
	if len(p.idle) != 2 {
		t.Fatalf("pool should hold exactly maxIdle=2 idle conns, got %d", len(p.idle))
	}
	if p.get() == nil || p.get() == nil {
		t.Fatal("get should return the two pooled connections")
	}
	if p.get() != nil {
		t.Fatal("get on an empty pool should return nil")
	}
}

func TestConnPoolIdleTimeout(t *testing.T) {
	p := newConnPool()
	p.idleTimeout = 10 * time.Millisecond
	fc := &fakeConn{}
	p.put(&dns.Conn{Conn: fc})
	time.Sleep(25 * time.Millisecond)
	if p.get() != nil {
		t.Fatal("an idle connection older than idleTimeout must not be reused")
	}
	if atomic.LoadInt32(&fc.closed) != 1 {
		t.Fatalf("an expired idle connection must be closed, closed=%d", fc.closed)
	}
}

type countingListener struct {
	net.Listener
	accepts int32
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		atomic.AddInt32(&l.accepts, 1)
	}
	return c, err
}

// TestNameServerTCPConnectionReuse verifies that sequential queries over TCP reuse a
// single pooled connection instead of dialing (and handshaking) per query.
func TestNameServerTCPConnectionReuse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	cl := &countingListener{Listener: ln}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.IP{1, 2, 3, 4},
		})
		_ = w.WriteMsg(m)
	})
	srv := &dns.Server{Listener: cl, Handler: handler}
	go func() { _ = srv.ActivateAndServe() }()
	defer srv.Shutdown()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	ns := &NameServer{
		Address:      net.ParseIP(host),
		Port:         uint16(port),
		Protocol:     "tcp",
		QueryTimeout: 2 * time.Second,
	}

	const N = 12
	for i := 0; i < N; i++ {
		q := new(dns.Msg)
		q.SetQuestion("example.com.", dns.TypeA)
		resp, err := ns.Resolve(q, 5)
		if err != nil {
			t.Fatalf("query %d failed: %v", i, err)
		}
		if len(resp.Answer) != 1 {
			t.Fatalf("query %d: expected 1 answer, got %d", i, len(resp.Answer))
		}
	}
	if got := atomic.LoadInt32(&cl.accepts); got > 2 {
		t.Fatalf("expected connection reuse (<=2 accepts) for %d sequential TCP queries, got %d", N, got)
	}
}
