package server

import (
	"net"
	"net/netip"
	"testing"

	listener "github.com/zhouchenh/secDNS/pkg/listeners/server"
)

type unknownAddr string

func (a unknownAddr) Network() string { return "unknown" }
func (a unknownAddr) String() string  { return string(a) }

func TestDNSServerImplementsPeerServer(t *testing.T) {
	var _ listener.PeerServer = (*DNSServer)(nil)
}

func TestPeerAddressAcceptsOnlySocketAddressTypes(t *testing.T) {
	for _, test := range []struct {
		name string
		addr net.Addr
		want netip.Addr
	}{
		{name: "udp4", addr: &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 53000}, want: netip.MustParseAddr("127.0.0.2")},
		{name: "tcp4-mapped", addr: &net.TCPAddr{IP: net.ParseIP("::ffff:127.0.0.3"), Port: 53000}, want: netip.MustParseAddr("127.0.0.3")},
		{name: "udp6", addr: &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 53000}, want: netip.MustParseAddr("2001:db8::2")},
		{name: "udp-zone", addr: &net.UDPAddr{IP: net.ParseIP("fe80::1"), Zone: "7", Port: 53000}},
		{name: "tcp-zone", addr: &net.TCPAddr{IP: net.ParseIP("fe80::1"), Zone: "7", Port: 53000}},
		{name: "unknown", addr: unknownAddr("127.0.0.2:53000")},
		{name: "nil"},
		{name: "typed-nil-udp", addr: (*net.UDPAddr)(nil)},
		{name: "typed-nil-tcp", addr: (*net.TCPAddr)(nil)},
		{name: "invalid-ip", addr: &net.UDPAddr{IP: net.IP{1, 2, 3}, Port: 53000}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := peerAddress(test.addr); got != test.want {
				t.Fatalf("got %v, want %v", got, test.want)
			}
		})
	}
}
