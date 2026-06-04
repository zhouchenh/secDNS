package nameserver

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	// defaultMaxIdleConns bounds the idle connections (and file descriptors) a single
	// pool may hold. Each nameServer client dials exactly one destination, so this is a
	// per-destination cap.
	defaultMaxIdleConns = 8
	// defaultConnIdleTimeout is how long an idle pooled connection may be reused before
	// it is assumed the peer has likely closed it; older idle connections are closed
	// rather than reused. A reuse that nonetheless hits a peer-closed connection falls
	// back to a fresh dial, so this only trades off re-dial frequency.
	defaultConnIdleTimeout = 10 * time.Second
)

type pooledConn struct {
	conn      *dns.Conn
	idleSince time.Time
}

// connPool is a small bounded pool of idle stream (TCP / DoT) connections to a single
// destination, reused one outstanding query at a time. It is safe for concurrent use.
type connPool struct {
	mu          sync.Mutex
	idle        []*pooledConn
	maxIdle     int
	idleTimeout time.Duration
}

func newConnPool() *connPool {
	return &connPool{maxIdle: defaultMaxIdleConns, idleTimeout: defaultConnIdleTimeout}
}

// get returns a reusable idle connection, or nil if none is available. Idle
// connections older than idleTimeout are closed and skipped so a likely-dead peer
// connection is not handed out.
func (p *connPool) get() *dns.Conn {
	p.mu.Lock()
	defer p.mu.Unlock()
	for len(p.idle) > 0 {
		n := len(p.idle) - 1
		pc := p.idle[n]
		p.idle[n] = nil
		p.idle = p.idle[:n]
		if time.Since(pc.idleSince) > p.idleTimeout {
			pc.conn.Close()
			continue
		}
		return pc.conn
	}
	return nil
}

// put returns a connection to the pool for reuse. If the pool is already at maxIdle the
// connection is closed instead, so the idle-connection (and file-descriptor) count
// stays bounded.
func (p *connPool) put(conn *dns.Conn) {
	p.mu.Lock()
	if len(p.idle) >= p.maxIdle {
		p.mu.Unlock()
		conn.Close()
		return
	}
	p.idle = append(p.idle, &pooledConn{conn: conn, idleSince: time.Now()})
	p.mu.Unlock()
}
