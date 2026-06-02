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
			req, err := serverDNS.ReadMsg()
			if err != nil {
				return
			}
			if resp != nil {
				// Echo the request's transaction ID, as a real DNS server does, so
				// the response passes the resolver's ID/question validation.
				out := resp.Copy()
				out.Id = req.Id
				_ = serverDNS.WriteMsg(out)
			}
		}()
		return clientConn, nil
	}
	c.dialFunc = dial
	c.dialTLSFunc = dial
	return c
}

func TestResponseMatchesQuery(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	q.Id = 0x1234

	good := new(dns.Msg)
	good.SetReply(q)
	if !responseMatchesQuery(good, q) {
		t.Fatalf("matching response was rejected")
	}

	badID := good.Copy()
	badID.Id = q.Id ^ 0xFFFF
	if responseMatchesQuery(badID, q) {
		t.Fatalf("response with mismatched transaction ID was accepted")
	}

	badName := new(dns.Msg)
	badName.SetQuestion("evil.example.com.", dns.TypeA)
	badName.Id = q.Id
	if responseMatchesQuery(badName, q) {
		t.Fatalf("response with mismatched question name was accepted")
	}

	badType := new(dns.Msg)
	badType.SetQuestion("example.com.", dns.TypeAAAA)
	badType.Id = q.Id
	if responseMatchesQuery(badType, q) {
		t.Fatalf("response with mismatched qtype was accepted")
	}

	mixedCase := new(dns.Msg)
	mixedCase.SetQuestion("ExAmPlE.CoM.", dns.TypeA)
	mixedCase.Id = q.Id
	if !responseMatchesQuery(mixedCase, q) {
		t.Fatalf("case-insensitive question name match was rejected")
	}
}

// TestNameServerSkipsSpoofedThenAcceptsValid verifies that a datagram whose
// transaction ID does not match the (randomized) query is discarded and the
// resolver keeps reading until the genuine answer arrives.
func TestNameServerSkipsSpoofedThenAcceptsValid(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)

	valid := new(dns.Msg)
	valid.SetReply(query)
	validA, err := dns.NewRR("example.com. 60 IN A 93.184.216.34")
	if err != nil {
		t.Fatalf("NewRR: %v", err)
	}
	valid.Answer = []dns.RR{validA}

	ns := &NameServer{
		Protocol:     "udp",
		Address:      net.IPv4(127, 0, 0, 1),
		Port:         53,
		QueryTimeout: time.Second,
	}
	ns.queryClient = mockSpoofThenValidClient(valid)
	ns.initOnce.Do(func() {})

	resp, err := ns.Resolve(query, 5)
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(resp.Answer))
	}
	if a, ok := resp.Answer[0].(*dns.A); !ok || a.A.String() != "93.184.216.34" {
		t.Fatalf("expected the genuine answer 93.184.216.34, got %v", resp.Answer[0])
	}
}

func mockSpoofThenValidClient(valid *dns.Msg) *client {
	c := &client{
		Client: &dns.Client{
			Net:     "udp",
			UDPSize: 4096,
			Dialer:  &net.Dialer{Timeout: time.Second},
		},
	}
	dial := func(network, address string) (net.Conn, error) {
		clientConn, serverConn := net.Pipe()
		go func() {
			defer serverConn.Close()
			s := &dns.Conn{Conn: serverConn}
			req, err := s.ReadMsg()
			if err != nil {
				return
			}
			// A spoofed datagram with the right question but a wrong transaction ID.
			spoof := valid.Copy()
			spoof.Id = req.Id ^ 0xFFFF
			if spoofA, err := dns.NewRR("example.com. 60 IN A 6.6.6.6"); err == nil {
				spoof.Answer = []dns.RR{spoofA}
			}
			_ = s.WriteMsg(spoof)
			// The genuine answer, echoing the request's transaction ID.
			out := valid.Copy()
			out.Id = req.Id
			_ = s.WriteMsg(out)
		}()
		return clientConn, nil
	}
	c.dialFunc = dial
	c.dialTLSFunc = dial
	return c
}
