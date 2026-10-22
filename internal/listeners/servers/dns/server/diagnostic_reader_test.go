package server

import (
	"errors"
	"github.com/miekg/dns"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

type fakeDiagnosticReader struct {
	data    []byte
	session *dns.SessionUDP
	address net.Addr
	err     error
}

func (r *fakeDiagnosticReader) ReadTCP(net.Conn, time.Duration) ([]byte, error) { return r.data, r.err }
func (r *fakeDiagnosticReader) ReadUDP(*net.UDPConn, time.Duration) ([]byte, *dns.SessionUDP, error) {
	return r.data, r.session, r.err
}
func (r *fakeDiagnosticReader) ReadPacketConn(net.PacketConn, time.Duration) ([]byte, net.Addr, error) {
	return r.data, r.address, r.err
}
func TestDiagnosticReaderPreservesTransport(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("secdnshealth0123456789abcdef01234567.1-1-1-1.sslip.io.", dns.TypeAAAA)
	data, _ := q.Pack()
	r := &fakeDiagnosticReader{data: data, session: &dns.SessionUDP{}, address: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}}
	t.Setenv("SECDNS_QUERY_TRACE_SALT", "")
	if decorateDiagnosticReader(r) != r {
		t.Fatal("disabled wrapper installed")
	}
	t.Setenv("SECDNS_QUERY_TRACE_SALT", strings.Repeat("ab", 32))
	t.Setenv("SECDNS_QUERY_TRACE_UNTIL", strconv.FormatInt(time.Now().Add(time.Minute).Unix(), 10))
	d := decorateDiagnosticReader(r)
	for _, want := range []error{nil, errors.New("read failed")} {
		r.err = want
		b, e := d.ReadTCP(nil, time.Second)
		if &b[0] != &data[0] || e != want {
			t.Fatal("TCP changed")
		}
		b, s, e := d.ReadUDP(nil, time.Second)
		if &b[0] != &data[0] || s != r.session || e != want {
			t.Fatal("UDP changed")
		}
		b, a, e := d.(dns.PacketConnReader).ReadPacketConn(nil, time.Second)
		if &b[0] != &data[0] || a != r.address || e != want {
			t.Fatal("packet conn changed")
		}
	}
	r.err = nil
	r.data = []byte{1, 2}
	if b, _, e := d.ReadUDP(nil, time.Second); len(b) != 2 || e != nil {
		t.Fatal("malformed bytes changed")
	}
}
