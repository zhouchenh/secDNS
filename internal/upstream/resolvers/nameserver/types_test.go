package nameserver

import (
	"errors"
	"github.com/miekg/dns"
	resolverpkg "github.com/zhouchenh/secDNS/pkg/upstream/resolver"
	"net"
	"sync"
	"testing"
	"time"
)

func TestNameServerDepthLimit(t *testing.T) {
	ns := &NameServer{}
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)
	if _, err := ns.Resolve(query, -1); !errors.Is(err, resolverpkg.ErrLoopDetected) {
		t.Fatalf("expected ErrLoopDetected, got %v", err)
	}
}

func TestNameServerUDPTruncatedFallbacksToTCP(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)

	udpResp := new(dns.Msg)
	udpResp.SetReply(query)
	udpResp.Truncated = true

	tcpResp := new(dns.Msg)
	tcpResp.SetReply(query)

	var udpDials, tcpDials int
	ns := &NameServer{
		Protocol:     "udp",
		Address:      net.IPv4(127, 0, 0, 1),
		Port:         53,
		QueryTimeout: time.Second,
	}
	ns.queryClient = mockDNSClient("udp", udpResp, &udpDials)
	ns.tcpFallbackClient = mockDNSClient("tcp", tcpResp, &tcpDials)

	ns.initOnce.Do(func() {})
	ns.tcpFallbackOnce.Do(func() {})

	resp, err := ns.Resolve(query, 5)
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if resp == nil {
		t.Fatalf("expected response, got nil")
	}
	if resp.Truncated {
		t.Fatalf("expected fallback response without truncation")
	}
	if udpDials != 1 || tcpDials != 1 {
		t.Fatalf("expected one UDP and one TCP dial, got udp=%d tcp=%d", udpDials, tcpDials)
	}
}

func mockDNSClient(protocol string, resp *dns.Msg, dialCounter *int) *client {
	c := &client{
		Client: &dns.Client{
			Net:     protocol,
			UDPSize: 4096,
			Dialer:  &net.Dialer{Timeout: time.Second},
		},
	}
	var mu sync.Mutex
	dial := func(network, address string) (net.Conn, error) {
		if dialCounter != nil {
			mu.Lock()
			*dialCounter++
			mu.Unlock()
		}
		clientConn, serverConn := net.Pipe()
		go func() {
			defer serverConn.Close()
			serverDNS := &dns.Conn{Conn: serverConn}
			if _, err := serverDNS.ReadMsg(); err != nil {
				return
			}
			if resp != nil {
				_ = serverDNS.WriteMsg(resp.Copy())
			}
		}()
		return clientConn, nil
	}
	c.dialFunc = dial
	c.dialTLSFunc = dial
	return c
}
