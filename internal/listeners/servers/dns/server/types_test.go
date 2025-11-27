package server

import (
	"errors"
	"net"
	"testing"
	"time"
)

func TestDNSServerServeNilHandler(t *testing.T) {
	var called bool
	d := &DNSServer{
		Listen:   net.IPv4(127, 0, 0, 1),
		Port:     0,
		Protocol: "udp",
	}
	done := make(chan struct{})
	go func() {
		d.Serve(nil, func(err error) {
			called = true
			if err != nil && !errors.Is(err, ErrNilHandler) {
				t.Errorf("expected ErrNilHandler, got %v", err)
			}
			close(done)
		})
	}()
	select {
	case <-done:
		if !called {
			t.Fatalf("expected error handler to be called")
		}
	case <-time.After(time.Second):
		t.Fatalf("Serve should return immediately when handler is nil")
	}
}
