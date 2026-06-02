package server

import (
	"testing"

	"github.com/miekg/dns"
)

func TestSafeHandleRecoversPanic(t *testing.T) {
	var captured error
	reply := safeHandle(func(*dns.Msg) *dns.Msg { panic("boom") }, new(dns.Msg), func(err error) { captured = err })
	if reply != nil {
		t.Fatalf("expected a nil reply after a handler panic, got %v", reply)
	}
	if captured == nil {
		t.Fatalf("expected the error handler to receive the recovered panic")
	}
}

func TestSafeHandlePassesThrough(t *testing.T) {
	want := new(dns.Msg)
	got := safeHandle(func(*dns.Msg) *dns.Msg { return want }, new(dns.Msg), nil)
	if got != want {
		t.Fatalf("safeHandle altered a normal reply")
	}
}
