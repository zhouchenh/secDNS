package server

import (
	"net"
	"testing"
)

func TestDNSServerServeNilHandler(t *testing.T) {
	var called bool
	d := &DNSServer{
		Listen:   net.IPv4(127, 0, 0, 1),
		Port:     0,
		Protocol: "udp",
	}
	d.Serve(nil, func(err error) {
		called = true
		if err != ErrNilHandler {
			t.Fatalf("expected ErrNilHandler, got %v", err)
		}
	})
	if !called {
		t.Fatalf("expected error handler to be called")
	}
}
