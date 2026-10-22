package server

import (
	"github.com/miekg/dns"
	"github.com/zhouchenh/secDNS/internal/upstream/diagnostics"
	"net"
	"time"
)

type diagnosticReader struct{ dns.Reader }

func recordRead(b []byte, err error, at time.Time) {
	if err != nil || !diagnostics.CorrelationActive() {
		return
	}
	q := new(dns.Msg)
	if q.Unpack(b) != nil {
		return
	}
	diagnostics.RecordBoundary(q, "listener.read", at, "read")
}
func (r diagnosticReader) ReadTCP(c net.Conn, t time.Duration) ([]byte, error) {
	b, e := r.Reader.ReadTCP(c, t)
	at := time.Now()
	recordRead(b, e, at)
	return b, e
}
func (r diagnosticReader) ReadUDP(c *net.UDPConn, t time.Duration) ([]byte, *dns.SessionUDP, error) {
	b, s, e := r.Reader.ReadUDP(c, t)
	at := time.Now()
	recordRead(b, e, at)
	return b, s, e
}

type diagnosticPacketReader struct {
	diagnosticReader
	packet dns.PacketConnReader
}

func (r diagnosticPacketReader) ReadPacketConn(c net.PacketConn, t time.Duration) ([]byte, net.Addr, error) {
	b, a, e := r.packet.ReadPacketConn(c, t)
	at := time.Now()
	recordRead(b, e, at)
	return b, a, e
}
func decorateDiagnosticReader(r dns.Reader) dns.Reader {
	if !diagnostics.CorrelationActive() {
		return r
	}
	d := diagnosticReader{r}
	if p, ok := r.(dns.PacketConnReader); ok {
		return diagnosticPacketReader{d, p}
	}
	return d
}
